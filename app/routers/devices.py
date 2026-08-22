import logging
from datetime import datetime, timezone
from typing import List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
    RevocationGroupOut, SetTimeRequest, UnlockRequest,
)
from app.services import (
    commands, devicecontrol, employee_sync, pairing, provisioning,
)
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


def _as_device_local(dt: datetime, zone: str) -> datetime:
    """The wall-clock time this instant shows in ``zone``, as a naive datetime.

    Used only for the `acc` clock command (E15), which carries a bare
    wall-clock value with no offset in it. A naive input is taken to already
    BE device-local and is returned untouched — that is what an operator
    typing a time into the Set Clock box means, and converting it would move a
    time they had just chosen.

    An unknown zone label falls back to the instant as given rather than
    raising: a device row with a typo'd timezone should still be settable, and
    the response says which zone was used either way.
    """
    if dt.tzinfo is None:
        return dt
    try:
        return dt.astimezone(ZoneInfo(zone)).replace(tzinfo=None)
    except (ZoneInfoNotFoundError, ValueError):
        log.warning("device timezone %r not recognised — sending the time "
                    "as supplied", zone)
        return dt.replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------

def _with_pending_revocations(db: Session, rows) -> list:
    """Stamp DeviceOut.pending_revocations on each device (E8).

    One extra query for the whole listing, not one per device: the outbox is
    the hot table on every device poll and this is an operator page.

    Counted over the whole outbox rather than only `acc` rows because the
    outbox is the only place a revocation can be outstanding at all — the SDK
    transport has either done it or failed loudly by the time the request
    returns, and never leaves anything behind to count.
    """
    serials = [r.serial_number for r in rows]
    counts = {}
    if serials:
        for row in (
            db.query(DeviceCommandOutbox)
            .filter(DeviceCommandOutbox.device_sn.in_(serials))
            .all()
        ):
            if provisioning.pin_from_revocation_command(row.command):
                counts[row.device_sn] = counts.get(row.device_sn, 0) + 1

    out = []
    for row in rows:
        shape = DeviceOut.model_validate(row)
        shape.pending_revocations = counts.get(row.serial_number, 0)
        out.append(shape)
    return out


@router.get("", response_model=List[DeviceOut])
def list_devices(
    status: Optional[str] = Query(default=None, pattern="^(pending|approved|rejected)$"),
    db: Session = Depends(get_db),
):
    """All devices, or one trust state — ``?status=pending`` is the approval queue."""
    query = db.query(Device)
    if status:
        query = query.filter(Device.status == status)
    return _with_pending_revocations(db, query.all())


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
    return _with_pending_revocations(db, [_get_device_or_404(sn, db)])[0]


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
        # moment a human actually vouches for the device — and routed on
        # protocol for the same reason the Sync menu is (E12). This is the
        # fifth caller of the SDK pull and it had the same defect: on an `acc`
        # terminal it dialled TCP 4370 and timed out, silently, in a
        # background task nobody was watching.
        if _uses_command_queue(device):
            provisioning.query_everything(db, sn)
        else:
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
# Pulling what a device holds — two transports (E12)
# ---------------------------------------------------------------------------
#
# Same rule as every write to a terminal (see `_uses_command_queue` further
# down): the transport is a total function of Device.protocol, never of what
# happens to answer a socket. Until E12 these four endpoints had no protocol
# check at all — every one of them dialled TCP 4370 through
# app/services/poller.py. On an `acc` terminal behind NAT that is a timeout,
# which is exactly what the operator saw when they clicked Sync Employees.
#
#   att -> the SDK poller, unchanged, in a background task. It really does
#          read the device, so it reports what it read.
#   acc -> a `DATA QUERY` on the E7 outbox. **202 and the word "queued"**: the
#          device collects it on its next poll (~10s) and answers by POSTing
#          the table to /iclock/querydata, where E9 ingests it. Nothing has
#          been read at the moment this returns, so nothing here says it has.
#
# Attendance has no `acc` branch on purpose — see provisioning.NO_ATTENDANCE_QUERY.

def _queued_query_response(sn: str, rows, created: int, response: Response,
                           what: str, extra: str = "") -> dict:
    """The one shape every queued-pull answer takes. Says queued, not done."""
    response.status_code = 202
    seconds = max(len(rows), 1) * 10
    reused = len(rows) - created
    return {
        "device_sn": sn,
        "transport": "adms_queue",
        "status": "queued",
        "command_ids": [r.id for r in rows],
        "commands": [r.command for r in rows],
        "queued": created,
        "already_outstanding": reused,
        "message": (
            f"Asked {sn} for {what}: {len(rows)} command"
            f"{'' if len(rows) == 1 else 's'} on the queue"
            + (f" ({reused} of which {'was' if reused == 1 else 'were'} already "
               "waiting from an earlier click)" if reused else "")
            + f". The device collects one per poll, so this takes roughly "
              f"{seconds} seconds, and nothing has been read yet — watch "
              "Commands for the outcome." + extra
        ),
    }


@router.post("/{sn}/pull", dependencies=[Depends(require_admin)])
def trigger_pull(sn: str, background_tasks: BackgroundTasks, response: Response,
                 db: Session = Depends(get_db)):
    """Sync everything this device can be asked for.

    On `acc` that is three confirmed queries — users, photos, templates — and
    NOT attendance, which is not pulled from these terminals at all because it
    arrives on its own over the push channel. Three commands at one per poll
    is roughly thirty seconds and shows as three rows in Commands.
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        rows, created = provisioning.query_everything(db, sn)
        body = _queued_query_response(
            sn, rows, created, response, "its people, photos and templates",
            extra=" Attendance is not included — these terminals push punches "
                  "up by themselves.",
        )
        # The full reasoning, for a caller that wants it. Not in `message`,
        # which is what the UI shows in a toast.
        body["attendance"] = provisioning.NO_ATTENDANCE_QUERY
        return body
    background_tasks.add_task(pull_device, sn)
    return {"message": "Pull started", "device": sn}


@router.post("/{sn}/pull/employees", dependencies=[Depends(require_admin)])
def trigger_pull_employees(sn: str, background_tasks: BackgroundTasks, response: Response,
                           db: Session = Depends(get_db)):
    """Read the device's user table into `employees`."""
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        row, created = provisioning.query_users(db, sn)
        return _queued_query_response(sn, [row], int(created), response, "its user table")
    background_tasks.add_task(pull_employees, sn)
    return {"message": "Employee sync started", "device": sn}


@router.post("/{sn}/pull/attendance", dependencies=[Depends(require_admin)])
def trigger_pull_attendance(sn: str, background_tasks: BackgroundTasks,
                            db: Session = Depends(get_db)):
    """Read buffered punches off the device (`att` only).

    On an `acc` terminal this is REFUSED — 501 — and, as with the per-template
    delete E8 refused for the same kind of reason, the refusal is a finding
    rather than a gap somebody forgot to fill.

    No server-issued query for an access-control terminal's transaction table
    has ever been observed answering, and it is unknown whether the firmware
    supports one. What is known is that these devices do not need to be asked:
    they push every punch up as an `rtlog` record as it happens, and the
    operator has already watched punches buffered through an outage arrive by
    themselves once the server came back. So the honest answer is that this
    action does not apply here — not a fabricated `DATA QUERY
    tablename=transaction` that would look like it worked while doing nothing,
    or wedge the outbox retrying a command the device never answers.
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=(
                f"{sn} is an access-control terminal. "
                + provisioning.NO_ATTENDANCE_QUERY
                + " Nothing was queued and nothing was guessed at. Punches "
                "from this device appear in Attendance without any action here."
            ),
        )
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

    Each row carries a ``verdict`` — ``acknowledged``, ``refused``,
    ``unconfirmed``, ``cancelled`` or ``abandoned``. Prefer it to reading
    ``outcome`` and ``return_code``: a non-zero ``return_code`` is NOT the
    same thing as a refusal (E11), and ``unconfirmed`` is the case that
    distinction exists for.
    """
    _get_device_or_404(sn, db)
    return (
        db.query(DeviceCommandLog)
        .filter_by(device_sn=sn)
        .order_by(DeviceCommandLog.concluded_at.desc(), DeviceCommandLog.id.desc())
        .limit(max(1, min(limit, 1000)))
        .all()
    )


@router.delete("/{sn}/commands/{command_id}", dependencies=[Depends(require_admin)])
def cancel_command(
    sn: str,
    command_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Withdraw one outstanding command from the outbox.

    What this can honestly promise depends on whether the device has already
    been offered this command (``status``), which is why it is read and
    reported here rather than left for the caller to infer:

    * ``pending`` — never sent. Cancelling genuinely prevents delivery.
    * ``sent`` — delivered at least once already. Cancelling only removes our
      record of owing it; the device may already have collected and acted on
      it. This is loudest for a revocation (`DATA DELETE`), where it is the
      difference between access still being revoked at the door and access
      quietly being restored — the response says so plainly rather than
      implying anything was recalled.
    """
    _get_device_or_404(sn, db)
    row = (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.id == command_id, DeviceCommandOutbox.device_sn == sn)
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="No outstanding command with that id on this device",
        )

    # Snapshot before conclude() deletes the row — its attributes are gone
    # once that commit lands.
    was_sent = row.status == "sent"
    revocation = commands.is_revocation(row.command)
    command_text = row.command

    cancelled = commands.cancel(db, row, by=admin.username)
    if not cancelled:
        raise HTTPException(
            status_code=409,
            detail="Already concluded by the device — nothing left to cancel",
        )

    audit.record(db, admin.username, "device_command_cancel",
                 target=f"{sn}/{command_id}", ip=client_ip(request),
                 detail=f"status={'sent' if was_sent else 'pending'} "
                        f"revocation={revocation} command={command_text[:120]}")

    return {
        "id": command_id,
        "device_sn": sn,
        "was_sent": was_sent,
        "is_revocation": revocation,
        "message": (
            "This command was already delivered to the device at least once "
            "— cancelling only removes our record of owing it. The device "
            "may already have collected and acted on it; nothing was "
            "recalled." + (
                " That person's access may already be gone — check the "
                "terminal directly if this needs to be certain."
                if revocation else ""
            )
            if was_sent else
            "Cancelled before delivery. This command was never sent to the "
            "device."
        ),
    }


@router.post("/{sn}/commands/history/{log_id}/retry", status_code=201,
             dependencies=[Depends(require_admin)])
def retry_command(
    sn: str,
    log_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Requeue a failed command as a brand-new outbox row.

    Decision (documented in ``commands.retry``): this **copies** the command
    into a fresh outbox row rather than resurrecting the concluded one, so
    the original history row is untouched — what happened the first time
    stays on the record no matter what the retry does.

    Only a ``failed`` history row can be retried — an ``acknowledged`` one
    already succeeded, and requeueing it would just repeat a command the
    device already carried out (harmless per E7's idempotency note, but not
    what "retry" should mean here).

    Does not block a retry of a device refusal (``return_code`` set), but
    warns loudly: a refusal is the device having understood the command and
    declined it, and nothing about the device changed in between, so the
    same bytes will very likely earn the same refusal again.
    """
    _get_device_or_404(sn, db)
    log_row = (
        db.query(DeviceCommandLog)
        .filter(DeviceCommandLog.id == log_id, DeviceCommandLog.device_sn == sn)
        .first()
    )
    if log_row is None:
        raise HTTPException(
            status_code=404, detail="No history row with that id on this device",
        )
    if log_row.outcome != "failed":
        raise HTTPException(
            status_code=400,
            detail="Only a failed command can be retried; this one was acknowledged",
        )

    return_code = log_row.return_code
    # A refusal, specifically — not merely "a code came back". A code this
    # system cannot read is not a refusal, and warning the operator that the
    # device "will very likely refuse again" would be asserting something we
    # do not know, about a command that may well have worked. (E11)
    verdict = commands.history_verdict(
        log_row.outcome, return_code, log_row.last_error, log_row.command,
    )
    was_refusal = verdict == "refused"

    new_row = commands.retry(db, log_row)

    audit.record(db, admin.username, "device_command_retry",
                 target=f"{sn}/{log_id}", ip=client_ip(request),
                 detail=f"new_command_id={new_row.id} verdict={verdict} "
                        f"return_code={return_code if return_code is not None else 'none'}")

    if was_refusal:
        message = (
            f"Requeued. The device refused this with Return={return_code} "
            "last time — unless something changed at the device, it will "
            "very likely refuse again the same way."
        )
    elif verdict == "unconfirmed":
        message = (
            f"Requeued. The device answered Return={return_code} last time, "
            "which this system cannot read as either success or refusal — so "
            "it may already have worked. Sending it again is safe; it is not "
            "a retry of a known failure."
        )
    else:
        message = (
            "Requeued as a new command. The previous attempt was never "
            "acknowledged; this one starts its own delivery attempts from "
            "zero."
        )

    return {
        "id": new_row.id,
        "device_sn": sn,
        "command": new_row.command,
        "retried_from_log_id": log_id,
        "was_device_refusal": was_refusal,
        "verdict": verdict,
        "message": message,
    }


# ---------------------------------------------------------------------------
# Device control — two transports (E15)
# ---------------------------------------------------------------------------
#
# The same total-function-of-Device.protocol rule as everywhere else. What is
# different here is that for the first time the `acc` commands come from the
# vendor's own specification rather than from an SDK constant table or a
# capture: the complete Security PUSH 3.1.2 document, whose command chapters
# live on pages 100-150 and were missing from every truncated copy available
# when push-protocol.md §3.8 was written. app/services/devicecontrol.py holds
# the shapes and the evidence for each one.
#
# Five of these actions have a documented `acc` command and are implemented.
# Four do not exist in the protocol at all and REFUSE with 501 rather than
# guessing: reading the clock, reading the lock state, and the two LCD
# actions. The refusals name the reason, because "not supported here" and
# "broken" look identical from a menu.

def _queued_control_response(sn: str, row, response: Response, what: str,
                             extra: str = "") -> dict:
    """The one shape every queued device-control answer takes.

    Says *queued*, never *done*. Nothing on this transport is synchronous, and
    an operator who is told "restarting" for a command that is still sitting
    in an outbox has been told something false.
    """
    response.status_code = 202
    return {
        "device_sn": sn,
        "transport": "adms_queue",
        "status": "queued",
        "command_id": row.id,
        "command": row.command,
        "message": (
            f"Queued: {what}. This terminal is not dialled — it collects "
            "commands when it next polls, about every 10 seconds, and nothing "
            "has happened yet. Watch Commands for the outcome." + extra
        ),
    }


# ---------------------------------------------------------------------------
# Device info
# ---------------------------------------------------------------------------

@router.get("/{sn}/info", response_model=None)
def get_device_info(sn: str, db: Session = Depends(get_db)):
    """What this device is.

    * `att` — read live over TCP 4370, unchanged.
    * `acc` — the **last known** parameter line the device sent us, parsed.
      Not a live read and labelled as such, with the time it arrived.

    Why last-known rather than a refusal: this is the one read where the value
    can be sourced from something the device volunteers. Every `acc` terminal
    pushes a complete comma-separated parameter inventory at registration, and
    again whenever it re-sends its options (`PushOptionsFlag=1`, which this
    hardware sets). That line is already stored verbatim in `capabilities`.
    Rendering it is reporting what the device said; the only dishonesty
    available would be presenting it as current, which is why the response
    carries `source: "last_known"` and `as_of`, and why the drawer says so.

    There is also a live path — `GET OPTIONS`, §12.5.2 — but it is a *queued*
    command answered a poll later, so it cannot serve a synchronous GET. It is
    offered separately as Refresh, below.
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        options = devicecontrol.parse_options(device.capabilities or "")
        info = devicecontrol.options_as_info(options)
        info.update({
            "device_sn": sn,
            "transport": "adms_last_known",
            "source": "last_known",
            "as_of": device.capabilities_at,
            "parameter_count": len(options),
            "message": (
                "Last known values, reported by the terminal itself — not a "
                "live reading. An access-control terminal cannot be dialled "
                "for this; it sends its parameters when it registers and "
                "whenever they change. Use Refresh to ask it again, which is "
                "queued and answers on its next poll."
                if options else
                "This terminal has not sent its parameters yet, so there is "
                "nothing to show. They arrive when it registers; Refresh asks "
                "for them now, which is queued and answers on its next poll."
            ),
        })
        # The serial is the one field we always know for certain, whatever the
        # device has or has not told us about itself.
        info["serial_number"] = info.get("serial_number") or sn
        return info

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


@router.post("/{sn}/info/refresh", dependencies=[Depends(require_admin)])
def refresh_device_info(sn: str, response: Response, db: Session = Depends(get_db)):
    """Ask an `acc` terminal to re-send its parameters (`GET OPTIONS`).

    §12.5.2. The device does not answer inline: it POSTs the parameters to
    /iclock/querydata with `tablename=options` and acknowledges separately, so
    this returns 202 and the values appear in Device Info a poll later.

    `att` has no equivalent and does not need one — its Device Info is read
    live over the SDK every time the drawer opens, so there is nothing to
    refresh.
    """
    device = _get_device_or_404(sn, db)
    if not _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=(
                f"{sn} is read live over the SDK every time Device Info is "
                "opened, so there is nothing to refresh — close and reopen it. "
                "Refresh exists for access-control terminals, which cannot be "
                "dialled and answer on their next poll instead."
            ),
        )
    row, created = provisioning.queue_query(
        db, sn, devicecontrol.QUERY_OPTIONS)
    return _queued_control_response(
        sn, row, response, "asked the terminal to re-send its parameters",
        extra="" if created else
        " (an identical request was already waiting, so this reuses it "
        "rather than costing another poll cycle.)",
    )


# ---------------------------------------------------------------------------
# Device clock
# ---------------------------------------------------------------------------

@router.get("/{sn}/time")
def get_device_time(sn: str, db: Session = Depends(get_db)):
    """Read the device's clock (`att` only).

    REFUSED on `acc` — 501 — and the refusal is a finding, not a gap.

    The vendor protocol has no command for asking an access-control terminal
    what time it holds. The traffic runs the other way: §12.5.1 documents the
    DEVICE fetching the time from the SERVER (`GET /iclock/rtdata?type=time`),
    which is the opposite direction to this endpoint. Setting the clock is
    supported and implemented below; reading it is not, and does not need to
    be, since setting it does not depend on knowing what it was.
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=(
                f"{sn} is an access-control terminal. "
                + devicecontrol.NO_DEVICE_TIME_READ
                + " Nothing was queued and nothing was guessed at. Setting "
                "the clock does work — use Set Clock."
            ),
        )
    try:
        with device_connection(device) as conn:
            t = conn.get_time()
            return {"device_sn": sn, "time": t.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/time", response_model=None, dependencies=[Depends(require_admin)])
def set_device_time(sn: str, payload: SetTimeRequest, response: Response,
                    db: Session = Depends(get_db)):
    """Set the device's clock.

    * `att` — set live over the SDK, unchanged.
    * `acc` — `SET OPTIONS DateTime=<encoded>` on the outbox (§12.5.1). 202.

    **The two branches send different instants on purpose.** The SDK path has
    always sent UTC and is left exactly as it was. The `acc` path sends the
    device's own local wall-clock time, taken from `Device.timezone`, because
    that is what makes the terminal's display and its `rtlog` timestamps
    correct — these devices push local time with no offset (which is the whole
    reason `Device.timezone` exists), so handing one UTC would silently shift
    every punch it reports. Changing the `att` branch to match is a separate
    decision about live hardware and is not made here.
    """
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

    if _uses_command_queue(device):
        zone = device.timezone or config.DEFAULT_DEVICE_TIMEZONE
        local = _as_device_local(target, zone)
        row = commands.queue(db, sn, devicecontrol.set_time_command(local))
        body = _queued_control_response(
            sn, row, response,
            f"set the clock to {local.strftime('%Y-%m-%d %H:%M:%S')} ({zone})",
        )
        body["time_set"] = local.isoformat()
        body["timezone"] = zone
        return body

    try:
        with device_connection(device) as conn:
            conn.set_time(target)
            return {"device_sn": sn, "time_set": target.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Door control
# ---------------------------------------------------------------------------

@router.post("/{sn}/unlock", response_model=None)
def unlock_door(
    sn: str,
    payload: UnlockRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Open the door.

    * `att` — the SDK opens it synchronously. Unchanged: the call returns when
      the door has opened, and the response says so.
    * `acc` — `CONTROL DEVICE 01<door>01<secs>` on the outbox (§12.4). **202,
      and the response says queued, not unlocked**, because on this transport
      it genuinely is not open yet.

    THE TWO TRANSPORTS ARE NOT EQUIVALENT AND THIS ENDPOINT DOES NOT PRETEND
    THEY ARE. An SDK unlock is a round trip to the door. An ADMS unlock is a
    row in a queue that the terminal collects when it next polls — normally
    within about ten seconds, but behind anything else already queued for that
    device, because delivery is FIFO at one command per poll. Somebody is
    standing at the door while that happens.

    Which is why an `acc` unlock is given a short deadline
    (`DOOR_COMMAND_TTL_SECONDS`, 60s) instead of the queue's usual patience.
    Past it the command is never delivered and is concluded as "the door was
    not opened". Two failure modes go away with it: a door that opens minutes
    later at nobody, and — because the deadline is no longer than the shortest
    retry backoff — a lost acknowledgement re-opening the door repeatedly over
    the following hour. A door command from here is one-shot by construction.
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        try:
            command = devicecontrol.unlock_command(
                door=payload.door, seconds=payload.seconds)
        except devicecontrol.UnsafeDoorCommand as e:
            # 400, not 500: the caller asked for something specific and this
            # says exactly which part of it will not be sent to a door.
            raise HTTPException(status_code=400, detail=str(e))

        row = commands.queue(
            db, sn, command,
            ttl_seconds=config.DOOR_COMMAND_TTL_SECONDS,
        )
        audit.record(db, admin.username, "door_unlock_queued", target=sn,
                     ip=client_ip(request),
                     detail=f"door={payload.door} seconds={payload.seconds} "
                            f"command_id={row.id}")
        body = _queued_control_response(
            sn, row, response,
            f"open door {payload.door} for {payload.seconds} seconds",
            extra=(
                f" THIS IS NOT AN IMMEDIATE UNLOCK: the door opens when the "
                f"terminal next polls, usually within about 10 seconds. If it "
                f"has not collected the command within "
                f"{config.DOOR_COMMAND_TTL_SECONDS} seconds the command is "
                "cancelled and the door will NOT open later."
            ),
        )
        body.update({
            "door": payload.door,
            "unlocked_for_seconds": None,
            "requested_seconds": payload.seconds,
            "expires_at": row.expires_at,
            "synchronous": False,
        })
        return body

    try:
        with device_connection(device) as conn:
            conn.unlock(time=payload.seconds)
            audit.record(db, admin.username, "door_unlock", target=sn,
                         ip=client_ip(request), detail=f"seconds={payload.seconds}")
            return {"device_sn": sn, "unlocked_for_seconds": payload.seconds,
                    "synchronous": True}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.get("/{sn}/lock")
def get_lock_state(sn: str, db: Session = Depends(get_db)):
    """Is the door locked? (`att` only.)

    REFUSED on `acc` — 501. Two independent reasons, either of which alone
    would be enough:

    1. The protocol defines no command for asking. Door, relay and alarm state
       arrive only when the device chooses to push an `rtstate` record; there
       is no server-initiated read of it anywhere in the specification.
    2. Even the pushed record could not honestly answer this. Its `sensor`,
       `relay` and `alarm` fields are raw hex bytes whose meaning the
       specification never defines. Decoding them would be guessing about
       whether a door is open, which is the last thing to guess about.
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=f"{sn} is an access-control terminal. "
                   + devicecontrol.NO_LOCK_STATE_READ,
        )
    try:
        with device_connection(device) as conn:
            locked = conn.get_lock_state()
            return {"device_sn": sn, "locked": locked}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Device control
# ---------------------------------------------------------------------------

@router.post("/{sn}/restart", response_model=None)
def restart_device(sn: str, request: Request, response: Response,
                   db: Session = Depends(get_db),
                   admin: User = Depends(require_admin)):
    """Reboot the device.

    * `att` — SDK, synchronous, unchanged.
    * `acc` — `CONTROL DEVICE 03000000` on the outbox (§12.4 example (3),
      "restarting the current device"). 202: queued, not restarting.

    No deadline on this one, unlike the door. A reboot collected late is still
    a reboot, and there is no equivalent of "the person has walked away".
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        row = commands.queue(db, sn, devicecontrol.restart_command())
        audit.record(db, admin.username, "device_restart_queued", target=sn,
                     ip=client_ip(request), detail=f"command_id={row.id}")
        return _queued_control_response(
            sn, row, response, "restart the terminal",
            extra=" It will go offline briefly once it collects this, and "
                  "reconnect by itself.",
        )

    try:
        with device_connection(device) as conn:
            conn.restart()
            audit.record(db, admin.username, "device_restart", target=sn, ip=client_ip(request))
            return {"device_sn": sn, "message": "Device restarting"}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/lcd", dependencies=[Depends(require_admin)])
def write_lcd(sn: str, payload: LcdRequest, db: Session = Depends(get_db)):
    """Write a line of text to the device screen (`att` only).

    REFUSED on `acc` — 501. The vendor protocol defines eight server-to-device
    commands and not one of them addresses the display. See
    `devicecontrol.NO_LCD_COMMAND` for what was searched and what was found
    instead (a capability bit for resource files whose delivery command the
    specification never defines).
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=f"{sn} is an access-control terminal. "
                   + devicecontrol.NO_LCD_COMMAND,
        )
    try:
        with device_connection(device) as conn:
            conn.write_lcd(payload.line, payload.text)
            return {"device_sn": sn, "line": payload.line, "text": payload.text}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/lcd", status_code=204, dependencies=[Depends(require_admin)])
def clear_lcd(sn: str, db: Session = Depends(get_db)):
    """Clear the device screen (`att` only). REFUSED on `acc` — see write_lcd."""
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=f"{sn} is an access-control terminal. "
                   + devicecontrol.NO_LCD_COMMAND,
        )
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
            # One person's uncollected revocation must not be undone by a bulk
            # push aimed at everybody else. Named in `errors` so it is visible
            # rather than being a silently missing row in the result.
            if provisioning.outstanding_revocations(db, sn, user_id):
                errors.append(
                    f"{user_id}: a revocation for this person on {sn} is still "
                    "queued and unconfirmed — not pushed, because that would "
                    "contradict it. Cancel the revocation to re-grant access."
                )
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
        blocked = _revocation_block(db, sn, user_id)
        if blocked:
            raise blocked
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


# ---------------------------------------------------------------------------
# Revoking a person from a device (E8)
# ---------------------------------------------------------------------------
#
# The mirror of the push above, on the same two transports and by the same
# rule — but with one difference that is not cosmetic.
#
# A push that has not been delivered yet means somebody cannot get in yet. A
# revocation that has not been delivered yet means somebody who should have
# lost access still has it, at a physical door, with nothing at the door
# saying so. So on the `acc` path this endpoint answers **202 and the word
# "queued"**, never 204 and silence, and every layer above it — the response
# message, the outbox listing, the person's page, the device list — is
# required to keep saying "not yet confirmed at the door" until the terminal
# acknowledges. The single worst outcome available to this unit is a screen
# that says access was revoked when it was not.


def _revocation_block(db: Session, sn: str, user_id: str):
    """A 409 if a revocation for this pair is outstanding, else None.

    Called by every path that would put this person back onto this door. The
    two orders of business are settled explicitly rather than left to the
    FIFO: queueing a delete *withdraws* outstanding pushes (provisioning.
    revoke), and queueing a push while a delete is outstanding is *refused*.

    Not symmetrical on purpose. Withdrawing a push to make room for a delete
    fails safe — the worst case is somebody has to be pushed again. Silently
    letting a push through behind an uncollected delete fails the other way:
    the terminal would perform the delete and then immediately restore the
    person, and the operator's screen would show a completed revocation for
    somebody who can still open the door.

    Refusing needs an escape hatch or it just strands the operator behind an
    offline terminal, so there is one: DELETE .../revocation cancels it, as a
    named and audited act.
    """
    outstanding = provisioning.outstanding_revocations(db, sn, user_id)
    if not outstanding:
        return None
    return HTTPException(
        status_code=409,
        detail=(
            f"A revocation for {user_id} on {sn} has not been confirmed by the "
            f"device yet ({len(outstanding)} command(s) still queued: "
            f"{', '.join(str(r.id) for r in outstanding)}). Pushing now would "
            "queue an instruction that contradicts it. Wait for the terminal "
            "to collect the revocation, or cancel the revocation first — "
            "nothing was queued."
        ),
    )


@router.delete("/{sn}/users/{user_id}", dependencies=[Depends(require_admin)])
def remove_user_from_device(
    sn: str,
    user_id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Take one person off one device. Does not delete the employee from the DB.

    Routed on Device.protocol exactly as the push is, and for the same reason:

    * `att` — the SDK deletes the user over TCP 4370 now. **200,
      `status: "removed"`.** By the time this returns it has happened, so the
      local enrolment record is dropped in the same breath.
    * `acc` — `DATA DELETE user` and `DATA DELETE userauthorize` go on the
      outbox. **202, `status: "queued"`.** The terminal has not been told yet.
      The local enrolment record deliberately **stays** until it acknowledges,
      so the UI keeps showing this person as present-but-being-revoked rather
      than quietly claiming a removal nobody has performed.

    Before this unit both paths dialled TCP 4370 unconditionally, so an `acc`
    terminal behind NAT — which is every one of them — answered 503 and there
    was no way at all to take back access this application could grant.
    """
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()

    if _uses_command_queue(device):
        # A person can be owed to a device without being on it: the push was
        # queued and the terminal has not collected it. "Remove" then means
        # "call it off", which is a real and useful thing to be able to do —
        # and 404ing here would leave the push in the outbox to be delivered
        # later, which is the opposite of what was asked for.
        if not de:
            withdrawn = provisioning.withdraw_pushes_for(
                db, sn, user_id,
                reason=f"withdrawn: {user_id} was removed from {sn} before delivery",
            )
            if not withdrawn:
                raise HTTPException(
                    status_code=404, detail="User not enrolled on this device"
                )
            audit.record(db, admin.username, "device_user_remove",
                         target=f"{sn}/{user_id}", ip=client_ip(request),
                         detail=f"withdrew {len(withdrawn)} undelivered push(es)")
            return {
                "device_sn": sn,
                "user_id": user_id,
                "transport": "adms_queue",
                "status": "withdrawn",
                "withdrawn_command_ids": withdrawn,
                "message": (
                    f"This person was never confirmed on {sn}; the "
                    f"{len(withdrawn)} command(s) still waiting to put them "
                    "there have been withdrawn. Nothing was sent to the device."
                ),
            }

        rows, withdrawn = provisioning.revoke(db, sn, user_id)
        audit.record(db, admin.username, "device_user_remove",
                     target=f"{sn}/{user_id}", ip=client_ip(request),
                     detail=f"queued={len(rows)} withdrew={len(withdrawn)}")
        response.status_code = 202
        return {
            "device_sn": sn,
            "user_id": user_id,
            "transport": "adms_queue",
            "status": "queued",
            "command_ids": [r.id for r in rows],
            "commands": [r.command for r in rows],
            "withdrawn_command_ids": withdrawn,
            # This string is what the operator reads. It is the difference
            # between an accurate belief and a dangerous one, so it says the
            # unwelcome thing first and does not soften it.
            "message": (
                f"Access revoked in the system — NOT yet confirmed at the door. "
                f"{sn} collects one command per poll (about 10 seconds) and "
                "confirms afterwards; until it does, this person can still "
                "open that door. If the terminal is offline the revocation "
                "waits, and stays visible as outstanding."
            ),
        }

    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device")

    try:
        with device_connection(device) as conn:
            conn.delete_user(uid=de.uid, user_id=user_id)
        # Only now, and through the single deleter — the device has actually
        # done it, which is what the SDK transport's synchronicity buys.
        employee_sync.unlink_device_employee(db, sn, user_id)
        db.commit()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")

    audit.record(db, admin.username, "device_user_remove", target=f"{sn}/{user_id}",
                 ip=client_ip(request), detail="transport=sdk")
    return {
        "device_sn": sn,
        "user_id": user_id,
        "transport": "sdk",
        "status": "removed",
        "message": f"Removed from {sn}. The device confirmed it.",
    }


@router.get("/{sn}/revocations", response_model=list[RevocationGroupOut],
            dependencies=[Depends(require_admin)])
def list_revocations(sn: str, user_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Revocations this device still owes somebody, one entry per person —
    not one per underlying `DATA DELETE` command (E13).

    A single source of truth for what used to be two client-side panels
    (Employees.jsx, CommandsDrawer.jsx) independently re-deriving the same
    grouping from the wire text. Optionally narrowed to one person, so a
    detail page does not have to fetch every revocation on the device and
    filter client-side.
    """
    _get_device_or_404(sn, db)
    return provisioning.revocation_groups(db, sn, user_id)


@router.delete("/{sn}/users/{user_id}/revocation", dependencies=[Depends(require_admin)])
def cancel_user_revocation(
    sn: str,
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Call off a revocation the device has not collected yet.

    The escape hatch for the 409 in :func:`_revocation_block`. Only touches
    commands still in the outbox — once a terminal has acknowledged a delete
    there is nothing here to cancel, and the way to put the person back is to
    push them again.

    Deliberately its own endpoint rather than a flag on the push: re-granting
    access somebody deliberately revoked should be a thing an operator has to
    ask for by name, and a thing the audit trail records under that name.
    """
    _get_device_or_404(sn, db)
    cancelled = provisioning.cancel_revocation(db, sn, user_id, by=admin.username)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail=f"No outstanding revocation for {user_id} on {sn}",
        )
    audit.record(db, admin.username, "device_user_revocation_cancel",
                 target=f"{sn}/{user_id}", ip=client_ip(request),
                 detail=f"cancelled={len(cancelled)}")
    return {
        "device_sn": sn,
        "user_id": user_id,
        "status": "cancelled",
        "cancelled_command_ids": cancelled,
        "message": (
            f"Revocation cancelled. {user_id} keeps their access to {sn} — "
            "if they were already confirmed on it, nothing about the device "
            "changed at any point."
        ),
    }


# ---------------------------------------------------------------------------
# Attendance: clear device memory
# ---------------------------------------------------------------------------

@router.delete("/{sn}/attendance", status_code=204, response_model=None)
def clear_device_attendance(
    sn: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Wipe attendance logs from device memory. Does not touch our DB.

    * `att` — SDK, synchronous, unchanged. Still 204.
    * `acc` — `DATA DELETE transaction *` on the outbox (§12.1.2.5, "Delete
      all the access control records", `*` meaning clear the table). **202
      with a body**, not 204, because there is something to say: which command
      is queued and that nothing has been deleted yet.

    Note what this is not. E12 refused to invent a `DATA QUERY
    tablename=transaction` and that refusal stands — no server-issued *query*
    of the transaction table has ever been seen answered, and these terminals
    push their punches up unasked, so nothing needs to ask. This is the
    documented *delete*, printed in the specification with a worked example.
    Reading E12's refusal as "the transaction table is off limits" would be
    over-reading it, and the AST test that enforces E12's rule is deliberately
    scoped to the query form for exactly this reason.
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        row = commands.queue(db, sn, devicecontrol.CLEAR_RECORDS)
        audit.record(db, admin.username, "clear_attendance_queued", target=sn,
                     ip=client_ip(request), detail=f"command_id={row.id}")
        return _queued_control_response(
            sn, row, response,
            "clear the access-control records held on the terminal",
            extra=" Nothing has been deleted yet, and nothing already synced "
                  "to this database is affected either way.",
        )

    try:
        with device_connection(device) as conn:
            conn.clear_attendance()
            audit.record(db, admin.username, "clear_attendance", target=sn, ip=client_ip(request))
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Fingerprint templates
# ---------------------------------------------------------------------------

@router.post("/{sn}/templates/pull", response_model=None, dependencies=[Depends(require_admin)])
def pull_templates(sn: str, response: Response, db: Session = Depends(get_db)):
    """Read the biometrics a device holds. Two transports, as everywhere else.

    * `att` — the SDK reads templates over TCP 4370 now and saves them to
      `fingerprint_templates`. 200, and the list it read, exactly as before.
    * `acc` — ONE `DATA QUERY tablename=biodata` on the outbox. **202,
      `status: "queued"`** — the device answers on /iclock/querydata a poll
      later and E9 writes `biometric_templates`.

    One query, not one per modality. The terminal ignores the type filter:
    `filter=type=9` and `filter=type=1` came back byte-identical, six records
    and 7002 bytes both times, covering face and fingerprint together. Asking
    twice would occupy the queue for a second poll to be told the same thing.
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        row, created = provisioning.query_templates(db, sn)
        return _queued_query_response(sn, [row], int(created), response,
                                      "its biometric templates")

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
            # Serialised here rather than by `response_model`, which this
            # endpoint gave up when it grew a second transport that answers
            # with a queue receipt. The `att` body is unchanged.
            return [FingerprintTemplateOut.model_validate(r) for r in result]
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


def _queue_templates_to_device(sn, user_id, request, response, db, admin):
    """The `acc` half of the template push: `DATA UPDATE BIODATA` on the outbox.

    Everything here is queued, never delivered. The terminal collects one
    command on each poll (about every ten seconds) and reports on it
    afterwards, so a person with two templates and no user record on that door
    yet is four commands and roughly forty seconds. COMMAND_BATCH_SIZE stays
    at 1: no real terminal has ever been observed acknowledging even a single
    command, let alone several in one reply, and this is the wrong payload to
    find that out with.

    Nothing that fails here fails silently:

    * templates captured on *this* device are never sent back to it, and the
      response names them,
    * a template that cannot be expressed on the wire is refused rather than
      trimmed to fit, and the response names it,
    * a person with nothing captured is an error, not an empty success.
    """
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        # The user record has to be buildable before a template can be queued
        # behind it — a template belongs to a Pin the terminal knows.
        raise HTTPException(status_code=404, detail="Employee not found")

    # Same rule as the user push: a biometric queued behind an uncollected
    # delete would put the credential back on the door the delete is meant to
    # take it off.
    blocked = _revocation_block(db, sn, user_id)
    if blocked:
        raise blocked

    sendable, from_this_device = provisioning.templates_for_device(db, sn, user_id)

    if not sendable and not from_this_device:
        raise HTTPException(
            status_code=404,
            detail=(
                "No biometric templates captured for this person. They must "
                "enrol a face or finger at a terminal first — nothing was queued."
            ),
        )
    if not sendable:
        raise HTTPException(
            status_code=409,
            detail=(
                f"All {len(from_this_device)} stored template(s) for this person "
                f"were captured on {sn} itself. A template is never pushed back "
                "to its own device — nothing was queued."
            ),
        )

    bodies, unsendable = provisioning.template_commands(sendable)
    if not bodies:
        raise HTTPException(
            status_code=422,
            detail=(
                "Stored template data cannot be put on the wire: "
                + "; ".join(reason for _, reason in unsendable)
                + " — nothing was queued."
            ),
        )

    # The person first, unless this terminal has already confirmed it holds
    # them. `device_employees` is written only on a real acknowledgement (E3),
    # so its presence is evidence rather than optimism.
    already_there = provisioning.is_on_device(db, sn, user_id)
    rows = provisioning.push_templates(
        db, sn, emp, bodies, with_user_record=not already_there,
    )

    audit.record(db, admin.username, "template_queue", target=f"{sn}/{user_id}",
                 ip=client_ip(request),
                 detail=f"templates={len(bodies)} user_record={not already_there}")

    response.status_code = 202
    seconds = len(rows) * 10
    return {
        "device_sn": sn,
        "user_id": user_id,
        "transport": "adms_queue",
        "status": "queued",
        "templates_queued": len(bodies),
        "user_record_queued": not already_there,
        "command_ids": [r.id for r in rows],
        # The command *names* only. The bytes of a template are a biometric
        # credential and there is no reason to hand them back out of the
        # database to a browser to be logged, cached or screenshotted.
        "commands": [r.command.split("\t")[0] for r in rows],
        "skipped_from_this_device": [
            {"type": t.type, "no": t.no} for t in from_this_device
        ],
        "skipped_unsendable": [
            {"type": t.type, "no": t.no, "reason": reason}
            for t, reason in unsendable
        ],
        "message": (
            f"Queued {len(rows)} commands for {sn}: {len(bodies)} template(s)"
            + (" behind the person's user record and door permission, which "
               "this terminal has not confirmed yet" if not already_there else "")
            + f". At one command per poll this takes roughly {seconds} seconds, "
            "and nothing is delivered until the device collects it — this is "
            "not delivered yet."
        ),
    }


@router.post("/{sn}/users/{user_id}/templates/push")
def push_templates_to_device(
    sn: str,
    user_id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Copy stored biometrics onto a device, so one enrolment works everywhere.

    Same routing rule as every other write to a terminal, and for the same
    reason (see `_uses_command_queue`): the transport is a function of
    Device.protocol, never of what happens to be reachable.

    * `acc` — `DATA UPDATE BIODATA` commands on the E7 outbox, built verbatim
      from the templates E2 captured. **202, `status: "queued"`.**
    * `att` — the SDK writes the device now over TCP 4370, from
      `fingerprint_templates`. 200, and the count it wrote.

    The two draw on different tables and that is not an oversight. A
    `biometric_templates` row is base64 the ADMS upload handed us; a
    `fingerprint_templates` row is a pyzk-packed blob from a TCP pull. Neither
    is the other's format, so neither is offered on the other's wire.
    """
    device = _get_device_or_404(sn, db)

    if _uses_command_queue(device):
        return _queue_templates_to_device(sn, user_id, request, response, db, admin)

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
    """Delete a specific finger template from device and from DB (`att` only).

    On an `acc` terminal this is REFUSED — 501 — and the refusal is a finding,
    not a gap somebody forgot to fill.

    §3.8 reproduces ZKTeco's own access-control SDK command constants, which
    the protocol reference rates as its highest-weight source. That
    enumeration carries `DATA UPDATE` for every biometric table
    (`BIODATA`, `biophoto`, `templatev10`, `facev7`), `DATA QUERY` and
    `DATA COUNT` for `biodata` — and exactly one `DATA DELETE`, for `user`.
    There is no per-template delete in the vendor's own command set, and the
    reading that makes that coherent is that a person's biometrics live with
    their user record and go when it goes.

    So the supported way to remove somebody's biometrics from an
    access-control terminal is to remove the person: DELETE
    /devices/{sn}/users/{user_id}, which queues `DATA DELETE user Pin=<n>`.
    That is said in the response, because an operator who clicked this needs
    to be told what to do instead, not merely told no.

    What this deliberately does NOT do is guess. Fabricating a delete for one
    of the biometric tables and shipping it as though it were known would put
    an unverified command on physical door hardware; if the shape were wrong
    the terminal would refuse it and the operator would be looking at a
    failure for a credential that was, in fact, still on the door — or at a
    success for one that was not removed. Both readings are worse than an
    honest refusal. UNVERIFIED either way until somebody watches a real
    BioFace A1 answer a user delete and then reports whether its face count
    dropped.
    """
    device = _get_device_or_404(sn, db)
    if _uses_command_queue(device):
        raise HTTPException(
            status_code=501,
            detail=(
                f"{sn} is an access-control terminal, and the PUSH protocol "
                "has no confirmed command for deleting one biometric on its "
                "own — the vendor's own SDK command set contains no biometric "
                "delete at all. Nothing was queued and nothing was guessed at. "
                "To take this person's biometrics off this door, remove the "
                "person from it (Remove, on their Enrolled Devices list): "
                "deleting the user record is what removes their templates. "
                "UNVERIFIED against real hardware."
            ),
        )
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
