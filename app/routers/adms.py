"""The device-facing half of the server: ZKTeco's PUSH ("ADMS") protocols.

There is no single ADMS protocol. ZKTeco publishes **two** PUSH documents that
share the ``/iclock/*`` URL space and disagree about almost everything inside
it:

* **Attendance PUSH** (``DeviceType=att``) — the handshake answers with a
  ``GET OPTION FROM:`` block, there is no registration step, and punches
  arrive as positional TSV under ``table=ATTLOG``.
* **Security PUSH** (``DeviceType=acc``) — the handshake answers ``registry=ok``
  plus a ``RegistryCode``, registration and configuration live at
  ``/iclock/registry`` and ``/iclock/push``, and access events arrive as
  keyed TSV under ``table=rtlog``.

Both are spoken here. The rule that keeps the two production attendance
devices safe is that ``att`` is the default in every ambiguous case: a serial
speaks Security PUSH only once it has announced ``DeviceType=acc`` or called
an endpoint that exists nowhere else. See ``_protocol_for``.

The failure mode this module is written against is not a crash. It is a
device that registers, reports healthy and silently discards every punch —
which is what the previous ``if table != "ATTLOG": return "OK"`` did to
``rtlog``. Hence: dispatch on ``table`` explicitly, log anything unrecognised
instead of dropping it, and never filter records on a code we have not
actually confirmed.
"""

import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app import audit, config
from app.database import get_db
from app.models import AttendanceLog, Device, DeviceCommand
from app.net import client_ip, ip_in_cidrs
from app.services import employee_sync, pairing

router = APIRouter(tags=["adms"])

log = logging.getLogger(__name__)

# These endpoints are the only ones reachable without credentials, so a
# refusal says nothing a prober could learn from: not whether the serial is
# known, not whether it is merely awaiting approval, not whether an IP rule
# exists. The reason goes to the log, where the operator can see it.
_REFUSAL_BODY = "Unauthorized"
_REFUSAL_STATUS = 401

# /iclock/registry is documented to signal a failed registration with 406, and
# that is the status this firmware is written to understand. A 401 would very
# likely also make it back off, but there is no reason to hand a device a code
# its own protocol does not define.
_REGISTRY_REFUSAL_STATUS = 406

# How much of an unrecognised request body reaches the log. Bodies are already
# capped at MAX_REQUEST_BYTES by middleware; this is about keeping one strange
# upload from flooding the operator's log file.
_LOG_BODY_LIMIT = 2000

# `tabledata` gets its own, much larger limit. 2000 characters is the right
# size for a log *line*; it is the wrong size for the only record we will ever
# have of what a bulk upload contained. The BioFace A1's first `user` push
# declared count=3 and the log kept one record — the two that were cut are
# exactly the two that would have told us whether real names ever arrive.
# 20 KB holds roughly 160 `user` records at the ~125 bytes each one measures on
# the wire, which covers any terminal this server is pointed at, and a 20 KB
# log line is large but bounded.
_TABLEDATA_LOG_LIMIT = 20000

# ...except for the tables whose payload is base64 blob. One `biophoto` record
# is ~100 KB and a push may carry dozens; a journal is not a blob store. These
# are summarised by size and record count instead, which is what an operator
# and the units that will parse them (E2, E5) actually need from the log.
# Lowercased for comparison — `ATTPHOTO` is the one table the vendor spells in
# capitals.
_BLOB_TABLES = frozenset({
    "biodata", "biophoto", "userpic", "identitycard", "templatev10", "attphoto",
})

# How much of a device's raw capability line is kept on its row. The real ones
# run to about 2 KB; the cap exists so a malformed push cannot fill the column.
_CAPABILITIES_LIMIT = 8000


def _refuse(
    db: Session,
    sn: str,
    ip: str,
    reason: str,
    status: int = _REFUSAL_STATUS,
    body: str = _REFUSAL_BODY,
) -> PlainTextResponse:
    log.warning("ADMS refused: serial=%s ip=%s reason=%s status=%s", sn, ip, reason, status)
    # Actor is "device" — the caller has no operator session, only a serial
    # number that may or may not be one the server has ever approved.
    audit.record(db, "device", "adms_refused", target=sn, ip=ip, detail=reason)
    return PlainTextResponse(content=body, status_code=status)


def _clip(text: str, limit: int = _LOG_BODY_LIMIT) -> str:
    """A body trimmed to a length that is safe to put in a log line."""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [{len(text) - limit} more chars]"


def _query(request: Request, name: str, default: str = "") -> str:
    """Case-insensitive query-string lookup.

    The protocol documents spell parameters ``DeviceType``, ``PushOptionsFlag``
    and ``pushver`` — mixed case, and there is no guarantee every firmware
    revision agrees on it. Matching case-insensitively costs nothing and
    removes a whole class of "worked in the lab" bug.
    """
    target = name.lower()
    for key, value in request.query_params.items():
        if key.lower() == target:
            return value
    return default


def _touch(db: Session, device: Device, request: Request) -> None:
    """Mark a device as heard from, recording where it was heard from.

    The address stored is the resolved client address, never
    ``request.client.host`` — behind Apache that is only ever the proxy."""
    device.last_seen = datetime.now(timezone.utc)
    device.is_online = True
    device.last_ip = client_ip(request)
    db.commit()


def _authorise(
    sn: str,
    request: Request,
    db: Session,
    refusal_status: int = _REFUSAL_STATUS,
    refusal_body: str = _REFUSAL_BODY,
):
    """Decide whether this serial may act, in the order the threat model needs.

    known serial → approved → source address inside the device's own allowlist.

    Returns ``(device, None)`` when the request may proceed and
    ``(None, response)`` when it must be refused. An unknown serial is filed as
    ``pending`` while a pairing window is open and dropped otherwise; either
    way it is refused this time, because nothing pushes before an admin has
    approved it.
    """
    ip = client_ip(request)
    device = db.query(Device).filter_by(serial_number=sn).first()

    def refuse(reason):
        return None, _refuse(db, sn, ip, reason, refusal_status, refusal_body)

    if not device:
        if not pairing.is_open(db):
            return refuse("unknown serial, pairing window closed")
        db.add(Device(
            serial_number=sn,
            ip_address=ip,
            port=4370,
            name="Unknown Device",
            status="pending",
            last_ip=ip,
            # Seeded, not guessed: a device sends bare wall-clock times, so
            # something has to say what they mean from the first punch. The
            # operator corrects it per device if this serial sits elsewhere.
            timezone=config.DEFAULT_DEVICE_TIMEZONE,
        ))
        db.commit()
        log.warning(
            "ADMS: new serial %s from %s filed for approval (pairing window open)", sn, ip
        )
        return refuse("awaiting approval")

    if device.status != "approved":
        # Still worth recording where it is calling from — that is what the
        # operator needs in order to recognise it in the approval queue.
        if device.last_ip != ip:
            device.last_ip = ip
            db.commit()
        return refuse(f"device status is {device.status}")

    if device.ip_check_enabled and not ip_in_cidrs(ip, device.allowed_cidrs):
        if device.last_ip != ip:
            device.last_ip = ip
            db.commit()
        return refuse("source address outside the device allowlist")

    return device, None


def _device_timezone(device: Device) -> str:
    """The zone label to stamp on rows arriving from this device.

    Falls back to the configured default rather than storing nothing: an
    unlabelled punch time is exactly the ambiguity D10 exists to remove, so a
    device row that somehow has no zone still yields a definite answer.
    """
    return (device.timezone if device is not None and device.timezone
            else config.DEFAULT_DEVICE_TIMEZONE)


# ---------------------------------------------------------------------------
# Which protocol is this device speaking?
# ---------------------------------------------------------------------------

def _protocol_for(device: Device, request: Request) -> str:
    """``"acc"`` (Security PUSH) or ``"att"`` (Attendance PUSH), in that order
    of evidence:

    1. **``DeviceType`` in the query string.** The device's own live
       self-declaration, and the parameter that selects the protocol document.
       It is emitted only when it has been configured on the device, which is
       exactly the population that speaks Security PUSH.
    2. **The persisted ``protocol`` column.** Sticky: a serial that has ever
       registered as ``acc`` stays ``acc`` even if it omits ``DeviceType`` on
       some later request.
    3. **Default ``att``.**

    ``pushver`` is deliberately *not* a discriminator. Attendance devices send
    it too — the Attendance document's own example is ``pushver=2.2.14`` — so
    it is neither exclusive to Security PUSH nor always present, and a 3.x
    value from a device that has never announced ``DeviceType=acc`` and never
    registered is not evidence of anything. Using it alone would be a coin
    flip on exactly the two serials that must not regress. It is logged on the
    handshake so an operator can see what each device actually sends.
    """
    declared = _query(request, "DeviceType").strip().lower()
    if declared == "acc":
        return "acc"
    if declared:
        # An explicit non-acc DeviceType is the device telling us it has been
        # switched to T&A mode. It outranks the sticky column, which is what
        # makes the "convert the terminal to T&A PUSH" path recoverable
        # without an operator editing the database by hand.
        return "att"
    if device is not None and device.protocol == "acc":
        return "acc"
    return "att"


def _set_protocol(db: Session, device: Device, protocol: str, reason: str, ip: str) -> None:
    """Persist a change of protocol family, once, loudly.

    This fires at most a handful of times in a device's life, so it is worth
    an audit row: it records the moment the server changed how it talks to a
    physical door controller, and why.
    """
    if device is None or device.protocol == protocol:
        return
    previous = device.protocol
    device.protocol = protocol
    db.commit()
    log.warning(
        "ADMS: device %s protocol %s -> %s (%s)",
        device.serial_number, previous, protocol, reason,
    )
    audit.record(
        db, "device", "adms_protocol_change",
        target=device.serial_number, ip=ip,
        detail=f"{previous} -> {protocol} ({reason})",
    )


def _acc_identity(db: Session, device: Device) -> tuple:
    """The device's ``(RegistryCode, SessionID)``, minted on first use.

    Both are documented as opaque values the server invents — the protocol
    describes RegistryCode only as "a random number generated by the server,
    up to 32 bytes", and every implementation surveyed returns something
    different without any device objecting. They are persisted so that a
    server restart does not hand the device a different pair than the one its
    session token was derived from.
    """
    changed = False
    if not device.registry_code:
        device.registry_code = secrets.token_hex(8)          # 16 chars, well under 32
        changed = True
    if not device.session_id:
        device.session_id = secrets.token_hex(16).upper()    # 32 hex chars, as in the spec's example
        changed = True
    if changed:
        db.commit()
    return device.registry_code, device.session_id


# ---------------------------------------------------------------------------
# Handshake bodies
# ---------------------------------------------------------------------------

def _legacy_option_block(sn: str) -> str:
    """The Attendance PUSH handshake reply — **byte-for-byte as it has always
    been**. Two production devices depend on this exact string; the fixture
    test pins its SHA-256. Do not "tidy" it."""
    return "\n".join([
        f"GET OPTION FROM: {sn}",
        "ATTLOGStamp=9999",
        "OPERLOGStamp=9999",
        "ATTPHOTOStamp=None",
        "ErrorDelay=30",
        "Delay=10",
        "TransTimes=00:00;14:05",
        "TransInterval=1",
        "TransFlag=1111000000",
        "TimeZone=0",
        "Realtime=1",
        "Encrypt=None",
    ])


def _acc_registry_block(registry_code: str, session_id: str) -> str:
    """The Security PUSH handshake reply, "already registered" form.

    Answering the handshake as *already registered* is what ZKTeco's own
    access-control server does — it returns this block unconditionally and
    implements neither /iclock/registry nor /iclock/push, because a device
    that receives a RegistryCode here never asks for them. The protocol
    document's literal wording ("the client needs to be registered for each
    connection") points the other way, so both routes exist anyway; whichever
    path the firmware takes, it reaches steady state.

    ``PushProtVer`` and ``PushVersion`` are both emitted on purpose. They are
    the same field under two names, and ZKTeco's own server picks between them
    by the device's ``MachineType`` — a value we do not learn until the device
    registers, which is after it has already had to read this block. Emitting
    both removes the guess; unknown keys are ignored by the firmware.
    """
    return "\n".join([
        "registry=ok",
        f"RegistryCode={registry_code}",
        "ServerVersion=3.1.2",
        "ServerName=ADMS",
        "PushProtVer=3.1.2",
        "PushVersion=3.1.2",
        "ErrorDelay=30",
        "RequestDelay=10",
        "TransTimes=00:00;14:05",
        "TransInterval=1",
        "TransTables=User Transaction",
        "Realtime=1",
        f"SessionID={session_id}",
        "TimeoutSec=10",
    ])


def _acc_push_block(session_id: str) -> str:
    """The Security PUSH configuration-download reply (/iclock/push).

    Field set and ordering follow the protocol document's own list. Delays
    match ``_acc_registry_block`` rather than the document's example, which
    uses different numbers in the two places — a device must not behave
    differently depending on which of the two paths it happened to take.

    ``TransTables=User Transaction`` is the conservative choice: it asks the
    device for users and transactions only. Implementations that also want
    biometric templates add ``Facev7 templatev10`` here and advertise the
    ``BioDataFun`` / ``MultiBioDataSupport`` negotiation keys. We want
    attendance, so we ask for less — omitting those keys leaves the
    hybrid-identification intersection empty and template sync simply does not
    happen, which is the intended outcome until someone asks for it.
    """
    return "\n".join([
        "ServerVersion=3.1.2",
        "ServerName=ADMS",
        "PushVersion=3.1.2",
        "PushProtVer=3.1.2",
        "ErrorDelay=30",
        "RequestDelay=10",
        "TransTimes=00:00;14:05",
        "TransInterval=1",
        "TransTables=User Transaction",
        "Realtime=1",
        f"SessionID={session_id}",
        "TimeoutSec=10",
    ])


@router.get("/iclock/cdata", response_class=PlainTextResponse)
def adms_handshake(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    protocol = _protocol_for(device, request)

    # The one log line that answers "what is each device actually sending?".
    # It is what tells an operator whether a legacy device announces a
    # DeviceType at all, and it is the first thing to read when a handshake
    # goes to the wrong branch.
    log.info(
        "ADMS handshake: serial=%s protocol=%s DeviceType=%r pushver=%r query=%r",
        SN, protocol, _query(request, "DeviceType"), _query(request, "pushver"),
        str(request.query_params),
    )

    if protocol == "acc":
        _set_protocol(db, device, "acc", "DeviceType=acc on handshake", client_ip(request))
        registry_code, session_id = _acc_identity(db, device)
        _touch(db, device, request)
        return PlainTextResponse(content=_acc_registry_block(registry_code, session_id))

    _touch(db, device, request)
    return PlainTextResponse(content=_legacy_option_block(SN))


@router.post("/iclock/cdata", response_class=PlainTextResponse)
async def adms_receive(
    request: Request,
    SN: str = Query(...),
    table: str = Query(default=""),
    db: Session = Depends(get_db),
):
    # Authorise before reading a byte of the body: an unapproved serial must
    # not be able to write attendance rows.
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    name = (table or "").strip()

    # --- Attendance PUSH tables (uppercase). Unchanged behaviour. ---------
    if name == "ATTLOG":
        raw = await request.body()
        body = raw.decode("utf-8", errors="ignore")
        _store_attlog(db, SN, body, _device_timezone(device))
        _touch(db, device, request)
        # An ATTLOG push is proof this serial speaks Attendance PUSH, whatever
        # a stale `protocol` column says. It is the mirror of DeviceType=acc,
        # and it makes the sticky column self-correcting if a terminal is ever
        # converted from A&C mode back to T&A mode.
        _set_protocol(db, device, "att", "ATTLOG push", client_ip(request))
        return PlainTextResponse(content="OK")

    if name == "OPERLOG":
        # Operation logs have never been parsed here and still are not; the
        # reply is the same "OK" the legacy devices have always received.
        return PlainTextResponse(content="OK")

    # --- Security PUSH tables (lowercase) ---------------------------------
    # The two protocols use disjoint, case-distinct table names, so
    # dispatching on `table` needs no device classification at all — an
    # attendance device never sends `rtlog` and an access device never sends
    # `ATTLOG`.
    if name == "rtlog":
        raw = await request.body()
        body = raw.decode("utf-8", errors="ignore")
        _store_rtlog(db, SN, body, client_ip(request), _device_timezone(device))
        _touch(db, device, request)
        return PlainTextResponse(content="OK")

    if name == "rtstate":
        # Door sensor / relay / alarm state. Not attendance; recorded in the
        # log so an operator can see the door is alive, then dropped.
        raw = await request.body()
        log.debug("ADMS rtstate from %s: %s", SN, _clip(raw.decode("utf-8", errors="ignore")))
        _touch(db, device, request)
        return PlainTextResponse(content="OK")

    if name == "options":
        # The device pushing its own parameters, triggered by
        # PushOptionsFlag=1. Same one-line comma-separated shape as the
        # registration body, and just as useful to keep: it is a complete
        # capability inventory.
        raw = await request.body()
        _store_capabilities(db, device, raw.decode("utf-8", errors="ignore"))
        _touch(db, device, request)
        return PlainTextResponse(content="OK")

    if name == "tabledata":
        # Bulk upload of users, templates, photos or error logs. The reply is
        # NOT "OK" — the protocol wants "<tablename>=<count>" echoed back, and
        # a device that does not see its own table name acknowledged is
        # documented to retry the upload indefinitely.
        raw = await request.body()
        body = raw.decode("utf-8", errors="ignore")
        tablename = _query(request, "tablename").strip()
        count = _query(request, "count").strip()
        if not tablename:
            log.warning("ADMS tabledata from %s with no tablename: %s", SN, _clip(body))
            return PlainTextResponse(content="OK")

        records = len([ln for ln in body.splitlines() if ln.strip()])
        if not count:
            # Fall back to counting records so the acknowledgement is still
            # well-formed if the device omits the parameter.
            count = str(records)

        low = tablename.lower()
        if low in _BLOB_TABLES:
            log.info(
                "ADMS tabledata from %s: tablename=%s count=%s (not stored) "
                "body=%d bytes in %d record(s) [base64, not logged]",
                SN, tablename, count, len(raw), records,
            )
        else:
            log.info(
                "ADMS tabledata from %s: tablename=%s count=%s body=%s",
                SN, tablename, count, _clip(body, _TABLEDATA_LOG_LIMIT),
            )

        if low == "user":
            try:
                _store_user_table(db, SN, body)
            except Exception:
                # The acknowledgement below matters more than the ingest. A
                # device that does not see `<tablename>=<count>` is documented
                # to retry the upload forever, so a parse or database fault
                # here has to be loud in the log and invisible on the wire.
                log.exception(
                    "ADMS tabledata from %s: user upload could not be stored; "
                    "acknowledging anyway so the device does not retry forever", SN,
                )
                db.rollback()

        _touch(db, device, request)
        return PlainTextResponse(content=f"{tablename}={count}")

    # --- Anything else ----------------------------------------------------
    # Acknowledged so the device does not loop, but never discarded silently:
    # the whole point of this branch is that an unrecognised table shows up in
    # the log as data an operator can read and act on, rather than as an
    # absence of attendance nobody notices.
    raw = await request.body()
    log.warning(
        "ADMS cdata: unhandled table=%r from serial=%s query=%r body=%s",
        name, SN, str(request.query_params),
        _clip(raw.decode("utf-8", errors="ignore")),
    )
    return PlainTextResponse(content="OK")


# ---------------------------------------------------------------------------
# Table parsers
# ---------------------------------------------------------------------------

def _store_attlog(db: Session, sn: str, body: str, tz: str) -> None:
    """Attendance PUSH punches: positional TSV.

    The parse is unchanged from the original — ``parts[1]`` is stored exactly
    as the device typed it, never converted. ``tz`` is the label for those
    digits, snapshotted onto each row (D10)."""
    for line in body.strip().splitlines():
        line = line.strip()
        if not line or "\t" not in line or line.startswith("TableName"):
            continue

        parts = line.split("\t")
        if len(parts) < 3:
            continue

        try:
            user_id = parts[0].strip()
            timestamp = datetime.strptime(parts[1].strip(), "%Y-%m-%d %H:%M:%S")
            status = int(parts[2].strip()) if parts[2].strip() else 0
            punch = int(parts[3].strip()) if len(parts) > 3 and parts[3].strip() else 0
        except (ValueError, IndexError):
            continue

        exists = db.query(AttendanceLog).filter_by(
            device_sn=sn, user_id=user_id, timestamp=timestamp
        ).first()
        if not exists:
            db.add(AttendanceLog(
                device_sn=sn,
                user_id=user_id,
                timestamp=timestamp,
                status=status,
                punch=punch,
                source="adms_push",
                # The device's own wall-clock digits, kept verbatim, plus what
                # they mean at the moment of the punch.
                timezone=tz,
            ))

    db.commit()


def _rtlog_fields(line: str) -> dict:
    """One ``rtlog`` record → a dict. Keyed ``key=value`` pairs, TAB-separated.

    Parsed by key and never by position: the field list has grown three times
    across firmware revisions (``sitecode``/``linkid`` in 2020,
    ``maskflag``/``temperature``/``convtemperature`` in 2021), so field count
    and order vary by device.
    """
    fields = {}
    for pair in line.split("\t"):
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        fields[key.strip().lower()] = value.strip()
    return fields


def _verify_mode_int(value: str) -> int:
    """``verifytype`` as an int for the legacy ``punch`` column, or 0.

    3.1.2 reports verification mode two different ways depending on what both
    sides support: a small decimal (the legacy scheme) or a 16-character
    bitmask, where face is ``0000000000000010``. Handing that bitmask to
    ``int()`` yields 10 — a *different*, real legacy verify mode — so anything
    that is not a canonical small decimal is left at 0 here. The raw string is
    always kept in ``AttendanceLog.verify_type``, so nothing is lost either way.
    """
    if not value or not value.isdigit():
        return 0
    if len(value) > 1 and value.startswith("0"):
        return 0          # zero-padded: the bitmask form, not a verify mode
    try:
        return int(value)
    except ValueError:
        return 0


def _is_person(pin: str) -> bool:
    """Does this record describe a person, rather than the device itself?

    ``pin`` is the user ID, and device-state events — start-up, door sensor,
    auxiliary input, remote open/close — carry ``pin=0`` because nobody is
    involved. This is the whole punch filter, and it is deliberate: which
    ``event`` codes mean "successful verification" on this firmware is not
    established, so filtering on a guessed allow-list of event codes would
    drop real punches silently and permanently. Keying on ``pin`` instead
    means an abnormal event may briefly be counted as a punch — visible in the
    data, and correctable once real codes have been observed.
    """
    if not pin:
        return False
    try:
        return int(pin) != 0
    except ValueError:
        return True       # a non-numeric PIN is still a person


def _store_rtlog(db: Session, sn: str, body: str, ip: str, tz: str) -> None:
    """Security PUSH access events: keyed TSV, deduped on ``(device_sn, index)``."""
    # Logged verbatim, at INFO, one line per push. This log is the evidence
    # that closes the open question about event codes: correlate it against
    # known punches and the mapping falls out. Do not turn it down until that
    # has been done.
    log.info("ADMS rtlog from %s: %s", sn, _clip(body))

    stored = 0
    ignored = 0
    seen_index = set()
    seen_punch = set()

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _rtlog_fields(line)
        if not fields:
            log.warning("ADMS rtlog from %s: unparseable record %r", sn, _clip(line, 300))
            continue

        record_index = fields.get("index", "")[:32]
        pin = fields.get("pin", "")

        if not _is_person(pin):
            # A device event, not a punch. Kept in the log rather than in the
            # attendance table.
            log.info(
                "ADMS rtlog from %s: device event (pin=%r event=%r index=%r)",
                sn, pin, fields.get("event"), record_index,
            )
            ignored += 1
            continue

        raw_time = fields.get("time", "")
        try:
            timestamp = datetime.strptime(raw_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Loud, because a timestamp format we cannot read means real
            # punches are being lost and somebody has to know.
            log.error(
                "ADMS rtlog from %s: unreadable time %r, record dropped: %s",
                sn, raw_time, _clip(line, 300),
            )
            continue

        user_id = pin[:24]
        verify_raw = fields.get("verifytype", "")

        # Two dedup keys, both needed. `index` is the device's own unique
        # record ID and is the right key — it survives a replayed batch
        # exactly. The (user, timestamp) tuple is checked as well because
        # uq_attendance already enforces it at the database level, and letting
        # it fire would roll back the whole push.
        index_key = (sn, record_index)
        punch_key = (sn, user_id, timestamp)
        if index_key in seen_index or punch_key in seen_punch:
            continue

        if record_index:
            exists = db.query(AttendanceLog).filter_by(
                device_sn=sn, record_index=record_index
            ).first()
            if exists:
                seen_index.add(index_key)
                continue

        exists = db.query(AttendanceLog).filter_by(
            device_sn=sn, user_id=user_id, timestamp=timestamp
        ).first()
        if exists:
            seen_punch.add(punch_key)
            continue

        seen_index.add(index_key)
        seen_punch.add(punch_key)
        db.add(AttendanceLog(
            device_sn=sn,
            user_id=user_id,
            timestamp=timestamp,
            # inoutstatus is 0=In / 1=Out, which is what `status` means here
            # and what the HRM push sends as the direction field. `punch` is
            # the verify mode, so verifytype belongs there — not the other way
            # round.
            status=_to_int(fields.get("inoutstatus"), 0),
            punch=_verify_mode_int(verify_raw),
            source="adms_push",
            event_code=fields.get("event", "")[:16] or None,
            verify_type=verify_raw[:32] or None,
            record_index=record_index or None,
            # `time=` above arrives with no offset and no zone name. It is
            # stored exactly as sent; this is the label that says what it means.
            timezone=tz,
        ))
        stored += 1

    db.commit()
    log.info(
        "ADMS rtlog from %s: %d punch(es) stored, %d device event(s) ignored",
        sn, stored, ignored,
    )


def _tabledata_fields(line: str, tablename: str) -> dict:
    """One bulk-upload record → a dict. Keyed ``key=value`` pairs, TAB-separated.

    Every record repeats the table name at its own head, separated from the
    first pair by a single SPACE, with TAB between the pairs after that.
    Verbatim from VGU6254600603, tabs shown as ``\\t``::

        user uid=1\\tcardno=\\tpin=1\\tpassword=\\tgroup=1\\tstarttime=0\\t
        endtime=0\\tname=\\tprivilege=14\\tdisable=0\\tverify=0

    The prefix is stripped when present, and a line without it parses
    identically — a firmware that omits it, or repeats it only on the first
    record, still reads correctly.

    Same discipline as ``_rtlog_fields``: by key, never by position. ZKTeco has
    added columns to this table across firmware revisions, and a positional
    parse maps a card number onto a name the first time a vendor inserts one —
    silently, and into the employee table.
    """
    text = line.strip()
    prefix = f"{tablename} "
    if text[:len(prefix)].lower() == prefix.lower():
        text = text[len(prefix):]

    fields = {}
    for pair in text.split("\t"):
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        fields[key.strip().lower()] = value.strip()
    return fields


def _store_user_table(db: Session, sn: str, body: str) -> None:
    """``tabledata&tablename=user`` — the terminal's own user list.

    This is how employees arrive from a device that sits behind NAT, where the
    SDK pull on TCP 4370 can never reach. The write itself is delegated to
    ``employee_sync``, which the SDK pull also calls, so the two transports
    cannot disagree about a shared row; in particular the "fill in, never empty
    out" rule lives there, and it is what keeps an operator-entered name alive
    through an upload like the captured one, where every record has ``name=``.

    ``password``, ``group``, ``starttime``, ``endtime``, ``disable`` and
    ``verify`` have nowhere to go in the current schema. They are dropped
    rather than guessed at — the log line above keeps the raw record if they
    ever turn out to matter.
    """
    stored = set()
    skipped = 0

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _tabledata_fields(line, "user")
        pin = fields.get("pin", "")

        if not fields or not _is_person(pin):
            # One unreadable record must not cost the rest of the batch: the
            # device has already been told the whole upload was accepted and
            # will not send it again. Logged rather than dropped silently, for
            # the same reason every other unknown thing here is.
            log.warning(
                "ADMS user upload from %s: skipping unusable record %r", sn, _clip(line, 300)
            )
            skipped += 1
            continue

        # No dedupe-and-skip within the batch. If a device sends the same PIN
        # twice, letting both run means a second record can fill in a field the
        # first left empty, and the merge rule guarantees it cannot undo one.
        employee_sync.record_device_user(
            db, sn, pin,
            uid=fields.get("uid"),
            name=fields.get("name"),
            privilege=fields.get("privilege"),
            card=fields.get("cardno"),
        )
        stored.add(pin.strip())

    db.commit()
    log.info(
        "ADMS user upload from %s: %d user(s) stored, %d record(s) skipped",
        sn, len(stored), skipped,
    )


def _to_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _store_capabilities(db: Session, device: Device, body: str) -> None:
    """Keep the device's raw parameter line on its row, verbatim.

    Not parsed: nothing needs to understand it yet, and a parser written
    against an example rather than against real traffic would be a guess. As
    one text column it answers most of what is still unknown about this
    firmware — MachineType, FaceFunOn, the MultiBio* vectors — the moment a
    real device sends it.
    """
    text = (body or "").strip()
    if not text or device is None:
        return
    device.capabilities = text[:_CAPABILITIES_LIMIT]
    db.commit()


@router.get("/iclock/ping", response_class=PlainTextResponse)
def adms_ping(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal
    _touch(db, device, request)
    return PlainTextResponse(content="OK")


@router.get("/iclock/getrequest", response_class=PlainTextResponse)
def adms_getrequest(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    # The command queue is drained here, so an unapproved serial must never
    # reach it — otherwise anyone could consume another site's commands.
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal
    _touch(db, device, request)

    cmd = (
        db.query(DeviceCommand)
        .filter_by(device_sn=SN, status="pending")
        .order_by(DeviceCommand.created_at)
        .first()
    )
    if cmd:
        cmd.status = "sent"
        db.commit()
        return PlainTextResponse(content=cmd.command)

    return PlainTextResponse(content="OK")


@router.post("/iclock/devicecmd", response_class=PlainTextResponse)
async def adms_devicecmd(
    request: Request,
    SN: str = Query(...),
    ID: str = Query(default=""),
    db: Session = Depends(get_db),
):
    _, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    cmd = (
        db.query(DeviceCommand)
        .filter_by(device_sn=SN, status="sent")
        .order_by(DeviceCommand.created_at)
        .first()
    )
    if cmd:
        cmd.status = "acknowledged"
        db.commit()

    return PlainTextResponse(content="OK")


# ---------------------------------------------------------------------------
# Security PUSH: registration and configuration download
#
# Neither endpoint exists in the Attendance protocol, so a legacy device never
# calls them and adding them cannot affect the two production serials at all.
# ---------------------------------------------------------------------------

@router.api_route("/iclock/registry", methods=["POST", "GET"], response_class=PlainTextResponse)
async def adms_registry(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    """Register an access-control device and hand it a RegistryCode.

    This is the endpoint whose absence produced a 405 and a 15-second
    registration loop: with no route declared, the request fell past every
    router to the SPA's StaticFiles mount, which serves GET and HEAD only.

    The reply body is exactly ``RegistryCode=<code>`` with no trailing
    newline. Returning a bare ``OK`` here — which several third-party servers
    do — is precisely the "no registration code returned" state that sends the
    device back to the start of the handshake, which is the bug being fixed.

    A device that is not approved is refused with 406, the status this
    protocol defines for a failed registration. Registration is the point at
    which an unknown serial would otherwise be handed a working session, so
    the trust check matters more here than anywhere else.
    """
    device, refusal = _authorise(
        SN, request, db,
        refusal_status=_REGISTRY_REFUSAL_STATUS,
        # The protocol describes the failure as "406 instead of the
        # registration code", with no body. An empty body also tells a prober
        # even less than the word "Unauthorized" does.
        refusal_body="",
    )
    if refusal:
        return refusal

    raw = await request.body()
    body = raw.decode("utf-8", errors="ignore")

    # Only a device speaking Security PUSH knows this endpoint exists, so
    # reaching it is conclusive — more so than DeviceType, which is a setting.
    _set_protocol(db, device, "acc", "POST /iclock/registry", client_ip(request))

    # The body is one long comma-separated key=value line describing every
    # capability the device has. Stored verbatim; registration succeeds
    # whether or not the server understands a word of it.
    _store_capabilities(db, device, body)
    log.info("ADMS registry from %s: %s", SN, _clip(body))

    registry_code, _session_id = _acc_identity(db, device)
    _touch(db, device, request)

    return PlainTextResponse(content=f"RegistryCode={registry_code}")


@router.api_route("/iclock/push", methods=["POST", "GET"], response_class=PlainTextResponse)
async def adms_push(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    """Configuration download — and, more importantly, the SessionID.

    Registered for both methods deliberately: the protocol document's prose
    says GET while its own worked example shows POST, and there is no way to
    tell from here which one this firmware picked.

    The SessionID must be present in the reply. The device folds it, together
    with the RegistryCode and its serial, into the token it sends back on
    every later request. We never validate that token — approved-serial plus
    CIDR allowlist is a stronger check than a hash of values we handed out in
    cleartext — but omitting the SessionID risks the device computing its
    token over nothing, and there is no upside to finding out what it does then.
    """
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    _set_protocol(db, device, "acc", "POST /iclock/push", client_ip(request))
    _registry_code, session_id = _acc_identity(db, device)
    _touch(db, device, request)

    log.info("ADMS push (config download) for %s", SN)
    return PlainTextResponse(content=_acc_push_block(session_id))


# ---------------------------------------------------------------------------
# Catch-all
# ---------------------------------------------------------------------------

@router.api_route(
    "/iclock/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    response_class=PlainTextResponse,
    include_in_schema=False,
)
async def adms_unknown(request: Request, path: str):
    """Name, in the log, every /iclock/* request no route above handles.

    Declared last, so it can only catch what the real routes did not.

    This is the highest-value defensive line in the module, and it is here
    because of how the Security PUSH incident actually presented: an
    undeclared ``/iclock/registry`` fell through every router to the SPA's
    StaticFiles mount, which answers a POST with 405 because it implements
    GET and HEAD only. The device looped every 15 seconds and the server said
    nothing about what it had been asked for. With this route the same event
    is a log line naming the method, the path and the body — and no /iclock/*
    request ever reaches the static mount again.

    It answers 404 rather than 200 on purpose. There is a documented firmware
    behaviour where a 200 on an unexpected reply makes the device treat its
    setup as complete and drop into command-poll-only mode until it is power
    cycled; a non-2xx keeps it retrying, which is the recoverable failure.
    No device state is touched and nothing is authorised here — the request is
    not part of any protocol we implement, so there is nothing to authorise it
    *for*. It is recorded and refused.
    """
    body = ""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        try:
            body = (await request.body()).decode("utf-8", errors="ignore")
        except Exception:      # a truncated or oversized body must still log
            body = "<unreadable>"

    log.warning(
        "ADMS: unhandled /iclock request — method=%s path=/iclock/%s query=%r "
        "client=%s user_agent=%r body=%s",
        request.method, path, str(request.query_params), client_ip(request),
        request.headers.get("user-agent", ""), _clip(body),
    )
    return PlainTextResponse(content="Not Found", status_code=404)
