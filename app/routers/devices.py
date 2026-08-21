import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import (
    APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response,
)
from sqlalchemy import text
from sqlalchemy.orm import Session
from zk.exception import ZKErrorConnection, ZKErrorResponse, ZKNetworkError
from zk.finger import Finger

from app import audit, config
from app.database import get_db
from app.models import (
    Device, DeviceCommandLog, DeviceCommandOutbox, DeviceEmployee, Employee,
    FingerprintTemplate, User,
)
from app.deps import require_admin, require_auth
from app.net import client_ip, valid_cidrs
from app.schemas import (
    BulkPushRequest, CommandCreate, CommandLogOut, CommandOut, DeviceCreate,
    DeviceInfoOut, DeviceOut,
    DeviceProtocolUpdate, DeviceTimezoneUpdate, DeviceUpdate, EnrollRequest,
    FingerprintTemplateOut, LcdRequest, PairingOpenRequest, PairingWindowOut,
    SetTimeRequest, UnlockRequest,
)
from app.services import commands, employee_sync, pairing, provisioning
from app.services.poller import pull_attendance, pull_device, pull_employees
from app.services.sdk import device_connection, enroll_user_task

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(require_auth)])

log = logging.getLogger(__name__)


def _get_device_or_404(sn: str, db: Session) -> Device:
    device = db.query(Device).filter_by(serial_number=sn).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


def _safe(fn, default=None):
    """Call an optional device getter, returning ``default`` if the device
    reports it cannot read that field (some models lack MAC, face/fp version,
    etc. and raise ZKErrorResponse instead of returning a value)."""
    try:
        return fn()
    except ZKErrorResponse:
        return default


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=List[DeviceOut])
def list_devices(
    status: Optional[str] = Query(default=None, pattern="^(pending|approved|rejected)$"),
    db: Session = Depends(get_db),
):
    """All devices, or one trust state — ``?status=pending`` is the approval queue."""
    query = db.query(Device)
    if status:
        query = query.filter(Device.status == status)
    return query.all()


@router.post("", response_model=DeviceOut, status_code=201)
def create_device(
    payload: DeviceCreate,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if db.query(Device).filter_by(serial_number=payload.serial_number).first():
        raise HTTPException(status_code=409, detail="Device already registered")
    # An admin typing a serial in by hand *is* the approval — only serials the
    # server discovers on its own have to wait in the queue.
    device = Device(
        **payload.model_dump(),
        status="approved",
        approved_at=datetime.now(timezone.utc),
        approved_by=admin.username,
        # Seeded from the configured default, exactly as an auto-registered
        # serial is. It is not a field on this form: correcting it later is a
        # deliberate act with its own endpoint, because it relabels history.
        timezone=config.DEFAULT_DEVICE_TIMEZONE,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    # Manual creation grants trust immediately, same as /approve — worth the
    # same accountability even though it isn't on the roster's call-site list.
    audit.record(db, admin.username, "device_create", target=device.serial_number, ip=client_ip(request))
    return device


# ---------------------------------------------------------------------------
# Pairing window — declared before /{sn} so "pairing" is not read as a serial
# ---------------------------------------------------------------------------

def _window_out(row) -> dict:
    remaining = pairing.seconds_remaining(row)
    return {
        "is_open": remaining > 0,
        "open_until": row.open_until if remaining > 0 else None,
        "seconds_remaining": remaining,
        "opened_at": row.opened_at,
        "opened_by": row.opened_by,
    }


@router.get("/pairing", response_model=PairingWindowOut)
def get_pairing_window(db: Session = Depends(get_db)):
    return _window_out(pairing.get_window(db))


@router.post("/pairing", response_model=PairingWindowOut)
def open_pairing_window(
    payload: PairingOpenRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Accept unrecognised serials into the approval queue, briefly."""
    row = pairing.open_window(db, payload.minutes, admin.username)
    audit.record(db, admin.username, "pairing_open", ip=client_ip(request),
                 detail=f"open_until={row.open_until.isoformat()}")
    return _window_out(row)


@router.delete("/pairing", response_model=PairingWindowOut)
def close_pairing_window(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = pairing.close_window(db, admin.username)
    audit.record(db, admin.username, "pairing_close", ip=client_ip(request))
    return _window_out(row)


@router.get("/{sn}", response_model=DeviceOut)
def get_device(sn: str, db: Session = Depends(get_db)):
    return _get_device_or_404(sn, db)


@router.patch("/{sn}", response_model=DeviceOut)
def update_device(
    sn: str,
    payload: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    device = _get_device_or_404(sn, db)
    fields = payload.model_dump(exclude_unset=True)

    if "allowed_cidrs" in fields:
        good, bad = valid_cidrs(fields["allowed_cidrs"])
        if bad:
            raise HTTPException(
                status_code=400,
                detail=f"Not a valid CIDR or IP address: {', '.join(bad)}",
            )
        # Store normalised, or NULL when cleared, so "is a list set?" is one test.
        fields["allowed_cidrs"] = ", ".join(good) or None

    # An IP check with nothing to match against would refuse every push from
    # this device, which is never what the operator meant.
    enabled = fields.get("ip_check_enabled", device.ip_check_enabled)
    allowed = fields.get("allowed_cidrs", device.allowed_cidrs)
    if enabled and not valid_cidrs(allowed)[0]:
        raise HTTPException(
            status_code=400,
            detail="Add at least one allowed CIDR before enabling the IP check",
        )

    for key, value in fields.items():
        setattr(device, key, value)
    db.commit()
    db.refresh(device)

    # "allowlist change" is the roster's call site: ip_address/port/name/
    # comm_key edits on this same endpoint are not audited here. comm_key is
    # a secret (D7) — its new value never enters detail, only the fact that
    # it changed, and only piggy-backed on an allowlist audit row.
    if "ip_check_enabled" in fields or "allowed_cidrs" in fields:
        parts = []
        if "ip_check_enabled" in fields:
            parts.append(f"ip_check_enabled={device.ip_check_enabled}")
        if "allowed_cidrs" in fields:
            parts.append(f"allowed_cidrs={device.allowed_cidrs or '(cleared)'}")
        if "comm_key" in fields:
            parts.append("comm_key also changed (value not logged)")
        audit.record(db, admin.username, "device_allowlist_change", target=sn,
                     ip=client_ip(request), detail="; ".join(parts))
    return device


# ---------------------------------------------------------------------------
# Device timezone — its own endpoint, because it rewrites history's labels
# ---------------------------------------------------------------------------

@router.patch("/{sn}/timezone", response_model=DeviceOut)
def update_device_timezone(
    sn: str,
    payload: DeviceTimezoneUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Change what this device's clock digits mean, and relabel its history.

    Separate from PATCH /{sn} on purpose. Every other field on a device
    affects the device; this one affects every attendance record the device
    has ever pushed, because those rows carry a snapshot of it. Nobody should
    be able to trigger that while renaming a door.

    What this is for: a device whose zone was recorded wrongly. It corrects a
    *label*. It is NOT a relocation tool — the stored wall-clock digits are
    never touched, so relabelling a device that has physically moved would
    claim its old punches happened in the new zone, which is false.
    """
    device = _get_device_or_404(sn, db)

    new_tz = (payload.timezone or "").strip()
    if not config.valid_timezone(new_tz):
        raise HTTPException(
            status_code=400,
            detail=f"'{new_tz}' is not a known IANA timezone name. "
                   "Use a name from the tz database, e.g. Asia/Dubai.",
        )

    old_tz = device.timezone
    if new_tz == old_tz:
        return device   # nothing to relabel, nothing to audit

    device.timezone = new_tz
    db.commit()

    # One statement, never a loop: a device that has been running for a year
    # can easily own six figures of rows. Only the label column is written —
    # `timestamp` does not appear in this UPDATE at all, which is the whole
    # guarantee: the digits a device reported stay exactly as reported.
    relabelled = db.execute(
        text("UPDATE attendance_logs SET timezone = :tz WHERE device_sn = :sn"),
        {"tz": new_tz, "sn": sn},
    ).rowcount
    db.commit()
    db.refresh(device)

    log.info("device %s timezone %s -> %s, relabelled %s attendance row(s)",
             sn, old_tz, new_tz, relabelled)
    audit.record(
        db, admin.username, "device_timezone_change", target=sn,
        ip=client_ip(request),
        detail=f"timezone {old_tz or '(unset)'} -> {new_tz}; "
               f"{relabelled} attendance record(s) relabelled; punch times unchanged",
    )
    return device


# ---------------------------------------------------------------------------
# Device protocol — its own endpoint, because it is a correction, not a field
# ---------------------------------------------------------------------------

@router.patch("/{sn}/protocol", response_model=DeviceOut)
def update_device_protocol(
    sn: str,
    payload: DeviceProtocolUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Correct which PUSH protocol family a device is treated as speaking.

    Separate from PATCH /{sn} on purpose, matching the timezone endpoint's
    precedent: `app/routers/adms.py` sets `Device.protocol` automatically from
    what the device itself announces (`DeviceType=acc` on a handshake, an
    ATTLOG push, or a call to /iclock/registry or /iclock/push), and that must
    stay the normal path. This endpoint exists for the moment automatic
    classification is stale — a terminal that has just been switched between
    cloud and local server modes, before it has said so on the wire again.

    Interaction with the automatic rules (E6's design question): the value set
    here is authoritative — and used immediately by outbound transport
    routing — until the device itself produces evidence that contradicts it.
    That is `_set_protocol`'s job, not this one: it flips the value AND clears
    `protocol_pinned` AND audits the moment distinctly, so a later
    "correction" a device makes on its own is never a silent revert. See
    `Device.protocol_pinned` and `app.routers.adms._set_protocol`.
    """
    device = _get_device_or_404(sn, db)

    new_protocol = payload.protocol
    old_protocol = device.protocol
    if new_protocol == old_protocol and device.protocol_pinned:
        return device   # already this value, already pinned — nothing to do

    device.protocol = new_protocol
    device.protocol_pinned = True
    db.commit()
    db.refresh(device)

    log.warning("device %s protocol %s -> %s (manual, pinned by %s)",
                sn, old_protocol, new_protocol, admin.username)
    audit.record(
        db, admin.username, "device_protocol_change", target=sn,
        ip=client_ip(request),
        detail=f"{old_protocol} -> {new_protocol} (manual override, pinned)",
    )
    return device


# ---------------------------------------------------------------------------
# Device approval
# ---------------------------------------------------------------------------

@router.post("/{sn}/approve", response_model=DeviceOut)
def approve_device(
    sn: str,
    background_tasks: BackgroundTasks,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Let this serial push. Until this happens it is refused at /iclock/*."""
    device = _get_device_or_404(sn, db)
    was_approved = device.status == "approved"
    device.status = "approved"
    device.approved_at = datetime.now(timezone.utc)
    device.approved_by = admin.username
    db.commit()
    db.refresh(device)
    log.warning("device %s approved by %s", sn, admin.username)
    audit.record(db, admin.username, "device_approve", target=sn, ip=client_ip(request))
    if not was_approved:
        # Same first-contact sync auto-registration used to do, moved to the
        # moment a human actually vouches for the device.
        background_tasks.add_task(pull_device, sn)
    return device


@router.post("/{sn}/reject", response_model=DeviceOut)
def reject_device(sn: str, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Refuse this serial without forgetting it — it stays visible and refused."""
    device = _get_device_or_404(sn, db)
    device.status = "rejected"
    device.approved_at = None
    device.approved_by = None
    db.commit()
    db.refresh(device)
    log.warning("device %s rejected by %s", sn, admin.username)
    audit.record(db, admin.username, "device_reject", target=sn, ip=client_ip(request))
    return device


@router.delete("/{sn}", status_code=204)
def delete_device(sn: str, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    device = _get_device_or_404(sn, db)
    db.delete(device)
    db.commit()
    audit.record(db, admin.username, "device_delete", target=sn, ip=client_ip(request))


# ---------------------------------------------------------------------------
# SDK pull (background)
# ---------------------------------------------------------------------------

@router.post("/{sn}/pull", dependencies=[Depends(require_admin)])
def trigger_pull(sn: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    _get_device_or_404(sn, db)
    background_tasks.add_task(pull_device, sn)
    return {"message": "Pull started", "device": sn}


@router.post("/{sn}/pull/employees", dependencies=[Depends(require_admin)])
def trigger_pull_employees(sn: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    _get_device_or_404(sn, db)
    background_tasks.add_task(pull_employees, sn)
    return {"message": "Employee sync started", "device": sn}


@router.post("/{sn}/pull/attendance", dependencies=[Depends(require_admin)])
def trigger_pull_attendance(sn: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    _get_device_or_404(sn, db)
    background_tasks.add_task(pull_attendance, sn)
    return {"message": "Attendance sync started", "device": sn}


# ---------------------------------------------------------------------------
# ADMS command queue
# ---------------------------------------------------------------------------

@router.post("/{sn}/commands", status_code=201, dependencies=[Depends(require_admin)])
def queue_command(sn: str, payload: CommandCreate, db: Session = Depends(get_db)):
    """Queue one command for delivery on the device's next poll.

    201 means queued, not delivered — there is no synchronous path to an ADMS
    device, so this cannot report whether the device accepted it. Read the
    outcome from the two GETs below.
    """
    _get_device_or_404(sn, db)
    row = commands.queue(db, sn, payload.command)
    return CommandOut.model_validate(row)


@router.get("/{sn}/commands", response_model=list[CommandOut],
            dependencies=[Depends(require_admin)])
def list_outstanding_commands(sn: str, db: Session = Depends(get_db)):
    """What this device still owes us — the whole outbox, oldest first.

    A row here with attempts=0 has not failed at anything; it is waiting for
    the device to poll. That is the ordinary state of a queue for a terminal
    that is switched off, and is exactly what makes the queue useful.
    """
    _get_device_or_404(sn, db)
    return (
        db.query(DeviceCommandOutbox)
        .filter_by(device_sn=sn)
        .order_by(DeviceCommandOutbox.created_at, DeviceCommandOutbox.id)
        .all()
    )


@router.get("/{sn}/commands/history", response_model=list[CommandLogOut],
            dependencies=[Depends(require_admin)])
def list_concluded_commands(sn: str, limit: int = 100, db: Session = Depends(get_db)):
    """Commands that are over, most recent first — how each one ended.

    ``outcome='failed'`` with a ``return_code`` is the device having refused
    the command; ``failed`` with a null code and a ``last_error`` is us having
    given up on it.
    """
    _get_device_or_404(sn, db)
    return (
        db.query(DeviceCommandLog)
        .filter_by(device_sn=sn)
        .order_by(DeviceCommandLog.concluded_at.desc(), DeviceCommandLog.id.desc())
        .limit(max(1, min(limit, 1000)))
        .all()
    )


# ---------------------------------------------------------------------------
# Device info
# ---------------------------------------------------------------------------

@router.get("/{sn}/info", response_model=DeviceInfoOut)
def get_device_info(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.read_sizes()
            return {
                "serial_number": conn.get_serialnumber(),
                "firmware_version": conn.get_firmware_version(),
                "platform": conn.get_platform(),
                "device_name": conn.get_device_name(),
                "mac": _safe(conn.get_mac),
                "face_version": _safe(conn.get_face_version),
                "fp_version": _safe(conn.get_fp_version),
                "pin_width": _safe(conn.get_pin_width),
                "network": conn.get_network_params(),
                "sizes": {
                    "users": getattr(conn, "users", 0),
                    "fingers": getattr(conn, "fingers", 0),
                    "records": getattr(conn, "records", 0),
                    "cards": getattr(conn, "cards", 0),
                    "faces": getattr(conn, "faces", 0),
                    "users_cap": getattr(conn, "users_cap", 0),
                    "fingers_cap": getattr(conn, "fingers_cap", 0),
                    "rec_cap": getattr(conn, "rec_cap", 0),
                    "faces_cap": getattr(conn, "faces_cap", 0),
                },
            }
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Device clock
# ---------------------------------------------------------------------------

@router.get("/{sn}/time")
def get_device_time(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            t = conn.get_time()
            return {"device_sn": sn, "time": t.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/time", dependencies=[Depends(require_admin)])
def set_device_time(sn: str, payload: SetTimeRequest, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    if payload.sync:
        target = datetime.now(timezone.utc)
    elif payload.dt:
        try:
            target = datetime.fromisoformat(payload.dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid datetime format — use ISO 8601")
    else:
        raise HTTPException(status_code=400, detail="Provide sync=true or a dt value")
    try:
        with device_connection(device) as conn:
            conn.set_time(target)
            return {"device_sn": sn, "time_set": target.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Door control
# ---------------------------------------------------------------------------

@router.post("/{sn}/unlock")
def unlock_door(
    sn: str,
    payload: UnlockRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.unlock(time=payload.seconds)
            audit.record(db, admin.username, "door_unlock", target=sn,
                         ip=client_ip(request), detail=f"seconds={payload.seconds}")
            return {"device_sn": sn, "unlocked_for_seconds": payload.seconds}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.get("/{sn}/lock")
def get_lock_state(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            locked = conn.get_lock_state()
            return {"device_sn": sn, "locked": locked}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Device control
# ---------------------------------------------------------------------------

@router.post("/{sn}/restart")
def restart_device(sn: str, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.restart()
            audit.record(db, admin.username, "device_restart", target=sn, ip=client_ip(request))
            return {"device_sn": sn, "message": "Device restarting"}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/lcd", dependencies=[Depends(require_admin)])
def write_lcd(sn: str, payload: LcdRequest, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.write_lcd(payload.line, payload.text)
            return {"device_sn": sn, "line": payload.line, "text": payload.text}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/lcd", status_code=204, dependencies=[Depends(require_admin)])
def clear_lcd(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.clear_lcd()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# User sync: list enrolled, push/remove individual users on a device
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Provisioning a person onto a device: which wire, and who records the link
# ---------------------------------------------------------------------------
#
# There are two ways to put a user on a terminal and they must never both be
# used for the same one, because both would write `device_employees` and each
# has a different idea of what a uid is. The choice is made from
# Device.protocol — a stored fact an operator can correct (E6) — and never
# guessed from whether a TCP connection happens to succeed:
#
#   att -> the SDK, TCP 4370, synchronous. Returns having actually written the
#          device, so it records the link itself, with the real device-side
#          uid it just learned.
#   acc -> the ADMS command queue, asynchronous. Queues two commands and
#          returns; the device collects them on its next poll (~10s) and
#          acknowledges later. The link is written when that acknowledgement
#          arrives (app/services/provisioning.note_acknowledged), not here,
#          because until then "this person is on this device" is not true yet.
#
# A device has exactly one protocol at a time, so exactly one of these runs
# for a given (device, user). Neither writes DeviceEmployee inline any more:
# both go through employee_sync.link_device_employee, which is the single
# writer E1 established.

def _uses_command_queue(device: Device) -> bool:
    """True if this device is provisioned over the ADMS queue rather than SDK.

    Anything that is not explicitly `acc` — including a row whose protocol is
    somehow unset — takes the SDK path. That is the safe default in the exact
    sense that matters here: an SDK push to a device that cannot answer fails
    loudly with a 503 in front of the operator, whereas queueing acc-shaped
    commands to an attendance terminal would sit in the outbox looking
    healthy, get collected, and be rejected or ignored by a device that has no
    such tables. Failure should be visible, not silent.
    """
    return (device.protocol or "att") == "acc"


@router.get("/{sn}/users")
def list_device_users(sn: str, db: Session = Depends(get_db)):
    """Return user_ids enrolled on this device."""
    _get_device_or_404(sn, db)
    rows = db.query(DeviceEmployee).filter_by(device_sn=sn).all()
    return [{"user_id": r.user_id, "uid": r.uid, "synced_at": r.synced_at} for r in rows]


@router.post("/{sn}/users/push_bulk", dependencies=[Depends(require_admin)])
def push_users_bulk(sn: str, payload: BulkPushRequest, response: Response,
                    db: Session = Depends(get_db)):
    """Push several employees to one device. Same two transports, same rules.

    On an `acc` device this is queueing, and the queue is deliberately slow:
    COMMAND_BATCH_SIZE is 1 and a terminal polls about every 10 seconds, so
    each person costs two commands and roughly 20 seconds. Ten people is
    several minutes and it is not stuck. That number is not raised here on
    spec — no real terminal has ever been observed acknowledging a
    multi-command reply, and mis-acknowledging is the exact bug E7 fixed.
    """
    device = _get_device_or_404(sn, db)
    pushed = []
    errors = []

    if _uses_command_queue(device):
        queued = []
        for user_id in payload.user_ids:
            emp = db.query(Employee).filter_by(user_id=user_id).first()
            if not emp:
                errors.append(f"{user_id}: employee not found in DB")
                continue
            queued.extend(r.id for r in provisioning.provision(db, sn, emp))
            pushed.append(user_id)

        response.status_code = 202
        seconds = len(queued) * 10
        return {
            "device_sn": sn,
            "transport": "adms_queue",
            "status": "queued",
            "pushed": pushed,
            "errors": errors,
            "command_ids": queued,
            "message": (
                f"Queued {len(queued)} commands for {len(pushed)} people. "
                f"At one command per poll this takes roughly {seconds} seconds "
                "to drain, and nothing is delivered until the device collects it."
            ),
        }

    try:
        with device_connection(device) as conn:
            users_on_device = conn.get_users()
            uid_by_user = {u.user_id: u for u in users_on_device}

            for user_id in payload.user_ids:
                emp = db.query(Employee).filter_by(user_id=user_id).first()
                if not emp:
                    errors.append(f"{user_id}: employee not found in DB")
                    continue
                try:
                    existing = uid_by_user.get(str(user_id))
                    uid = existing.uid if existing else None
                    pre_uid = conn.next_uid
                    conn.set_user(
                        uid=uid,
                        name=emp.name,
                        privilege=emp.privilege,
                        user_id=emp.user_id,
                        card=int(emp.card) if emp.card and emp.card != "0" else 0,
                    )
                    actual_uid = uid if uid is not None else pre_uid
                    employee_sync.link_device_employee(db, sn, user_id, uid=actual_uid)
                    pushed.append(user_id)
                except Exception as e:
                    errors.append(f"{user_id}: {e}")

            db.commit()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")

    return {"device_sn": sn, "pushed": pushed, "errors": errors}


@router.post("/{sn}/users/{user_id}/push", dependencies=[Depends(require_admin)])
def push_user_to_device(sn: str, user_id: str, response: Response, db: Session = Depends(get_db)):
    """Put one employee onto one device. Explicit, per device, never fanned out.

    Two transports, chosen by Device.protocol (see _uses_command_queue above),
    and the response says which one ran and what actually happened:

    * `att` — the SDK writes the device now. 200, `status: "written"`.
    * `acc` — two commands are queued (the user record and the door
      permission). **202, `status: "queued"`** — the device has not seen them
      yet, will collect them on its next poll, and may still refuse them.
      Calling that a success would be a lie the operator can only discover by
      walking to the terminal.

    In neither case does this enrol a biometric. The person walks up to the
    terminal and registers their face or finger there; the device uploads the
    template back by itself.
    """
    device = _get_device_or_404(sn, db)
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    if _uses_command_queue(device):
        rows = provisioning.provision(db, sn, emp)
        response.status_code = 202
        return {
            "device_sn": sn,
            "user_id": user_id,
            "transport": "adms_queue",
            "status": "queued",
            "command_ids": [r.id for r in rows],
            "commands": [r.command for r in rows],
            # Said in the response rather than only in a docstring, because
            # this string is what the UI shows and what stops "pushed" from
            # being read as "done".
            "message": (
                f"Queued {len(rows)} commands for {sn}. The device collects "
                "them on its next poll (about 10 seconds) and acknowledges "
                "afterwards — this is not delivered yet."
            ),
        }

    try:
        with device_connection(device) as conn:
            users_on_device = conn.get_users()  # also initialises conn.next_uid
            existing = next((u for u in users_on_device if u.user_id == str(user_id)), None)

            uid = existing.uid if existing else None
            pre_uid = conn.next_uid  # pyzk will assign this if uid is None

            conn.set_user(
                uid=uid,
                name=emp.name,
                privilege=emp.privilege,
                user_id=emp.user_id,
                card=int(emp.card) if emp.card and emp.card != "0" else 0,
            )

            actual_uid = uid if uid is not None else pre_uid

            # One writer for this table, shared with the SDK pull, the ADMS
            # upload ingest and the ADMS acknowledgement path (E1's rule).
            employee_sync.link_device_employee(db, sn, user_id, uid=actual_uid)
            db.commit()

        return {
            "device_sn": sn,
            "user_id": user_id,
            "uid": actual_uid,
            "transport": "sdk",
            "status": "written",
            "message": "User written to device",
        }
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/users/{user_id}", status_code=204, dependencies=[Depends(require_admin)])
def remove_user_from_device(sn: str, user_id: str, db: Session = Depends(get_db)):
    """Remove a user from the device. Does not delete the employee from DB."""
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device")
    try:
        with device_connection(device) as conn:
            conn.delete_user(uid=de.uid, user_id=user_id)
        db.delete(de)
        db.commit()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Attendance: clear device memory
# ---------------------------------------------------------------------------

@router.delete("/{sn}/attendance", status_code=204)
def clear_device_attendance(
    sn: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Wipe attendance logs from device memory. Does not touch our DB."""
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.clear_attendance()
            audit.record(db, admin.username, "clear_attendance", target=sn, ip=client_ip(request))
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Fingerprint templates
# ---------------------------------------------------------------------------

@router.post("/{sn}/templates/pull", response_model=List[FingerprintTemplateOut], dependencies=[Depends(require_admin)])
def pull_templates(sn: str, db: Session = Depends(get_db)):
    """
    Pull all fingerprint templates from device and save to DB.
    Overwrites existing DB record for the same (user_id, finger_id) pair.
    """
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            users = conn.get_users()
            uid_map = {u.uid: u.user_id for u in users}
            fingers = conn.get_templates()

            result = []
            for finger in fingers:
                user_id = uid_map.get(finger.uid)
                if not user_id:
                    continue
                packed = finger.json_pack()
                ft = db.query(FingerprintTemplate).filter_by(
                    user_id=user_id, finger_id=finger.fid
                ).first()
                if ft:
                    ft.valid = finger.valid
                    ft.template = packed["template"]
                    ft.source_device_sn = sn
                else:
                    ft = FingerprintTemplate(
                        user_id=user_id,
                        finger_id=finger.fid,
                        valid=finger.valid,
                        template=packed["template"],
                        source_device_sn=sn,
                    )
                    db.add(ft)
                result.append(ft)

            db.commit()
            for r in result:
                db.refresh(r)
            return result
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/users/{user_id}/templates/push")
def push_templates_to_device(
    sn: str,
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Copy fingerprint templates stored in DB onto the device.
    Typical workflow: pull from Device A, then push to Devices B, C, D.
    The user must already exist on the target device (call /push first).
    """
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device — call /push first")

    templates = db.query(FingerprintTemplate).filter_by(user_id=user_id).all()
    if not templates:
        raise HTTPException(status_code=404, detail="No fingerprint templates in DB for this employee")

    try:
        with device_connection(device) as conn:
            users = conn.get_users()
            device_user = next((u for u in users if u.user_id == str(user_id)), None)
            if not device_user:
                raise HTTPException(status_code=422, detail="User not found on device — call /push first")

            fingers = [
                Finger.json_unpack({
                    "uid": device_user.uid,  # uid on THIS device, not the source device
                    "fid": ft.finger_id,
                    "valid": ft.valid,
                    "template": ft.template,
                })
                for ft in templates
            ]
            conn.save_user_template(device_user, fingers)

        audit.record(db, admin.username, "template_push", target=f"{sn}/{user_id}",
                     ip=client_ip(request), detail=f"fingers={len(fingers)}")
        return {
            "device_sn": sn,
            "user_id": user_id,
            "templates_pushed": len(fingers),
        }
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/users/{user_id}/templates/{finger_id}", status_code=204)
def delete_user_template(
    sn: str,
    user_id: str,
    finger_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a specific finger template from device and from DB."""
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device")
    try:
        with device_connection(device) as conn:
            conn.delete_user_template(uid=de.uid, temp_id=finger_id, user_id=user_id)
        ft = db.query(FingerprintTemplate).filter_by(user_id=user_id, finger_id=finger_id).first()
        if ft:
            db.delete(ft)
            db.commit()
        audit.record(db, admin.username, "template_delete", target=f"{sn}/{user_id}/{finger_id}",
                     ip=client_ip(request))
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Live enrollment
# ---------------------------------------------------------------------------

@router.post("/{sn}/users/{user_id}/enroll", status_code=202, dependencies=[Depends(require_admin)])
def enroll_user(
    sn: str,
    user_id: str,
    payload: EnrollRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Trigger a live fingerprint enrollment on the device.
    Returns immediately (202). The device will prompt the person to scan their
    finger 3 times. Check DB templates after ~30s to confirm success.
    The user must already exist on the device (call /push first).
    """
    _get_device_or_404(sn, db)
    if not db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first():
        raise HTTPException(status_code=404, detail="User not enrolled on this device — call /push first")
    background_tasks.add_task(enroll_user_task, sn, user_id, payload.finger_id)
    return {
        "message": "Enrollment started — person must scan their finger on the device",
        "device_sn": sn,
        "user_id": user_id,
        "finger_id": payload.finger_id,
    }
