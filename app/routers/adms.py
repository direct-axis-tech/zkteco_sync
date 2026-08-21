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
import threading
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app import audit, config
from app.database import get_db
from app.models import (
    AttendanceLog, BiometricTemplate, Device, DeviceCommandOutbox, EmployeePhoto,
)
from app.net import client_ip, ip_in_cidrs
from app.services import commands, employee_sync, pairing, provisioning

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
# needs from the log — storing the content (E2's `biodata`, E5's `biophoto`
# and `userpic`) is not a reason to start dumping it into the journal too.
# Lowercased for comparison — `ATTPHOTO` is the one table the vendor spells in
# capitals.
_BLOB_TABLES = frozenset({
    "biodata", "biophoto", "userpic", "identitycard", "templatev10", "attphoto",
})

# Which of the blob tables are actually parsed and written to a row, rather
# than summarised in the log and dropped. Only affects the "(stored)" /
# "(not stored)" note on that log line.
_STORED_BLOB_TABLES = frozenset({"biodata", "biophoto", "userpic"})

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

    Interaction with a manual override (E6, ``Device.protocol_pinned``): every
    call site below is the device itself producing strong, on-the-wire
    evidence of which protocol it speaks — ``DeviceType=acc`` on a handshake,
    an ``ATTLOG`` push, or a call to an endpoint that exists only in one
    protocol. That evidence is never suppressed, even for a device an operator
    has just pinned: a genuinely reconfigured terminal must still self-heal,
    exactly as D9 intended, or the pin would trap it on the wrong protocol
    forever. What changes is visibility — a pinned device that gets
    reclassified this way has its pin cleared *and* the audit row says so
    explicitly, so this never reads as a silent revert of an operator's
    choice. An unpinned device behaves exactly as before E6.
    """
    if device is None or device.protocol == protocol:
        return
    previous = device.protocol
    was_pinned = device.protocol_pinned
    device.protocol = protocol
    if was_pinned:
        device.protocol_pinned = False
    db.commit()
    log.warning(
        "ADMS: device %s protocol %s -> %s (%s)%s",
        device.serial_number, previous, protocol, reason,
        " — this OVERRIDES an operator's manual pin, now cleared" if was_pinned else "",
    )
    detail = f"{previous} -> {protocol} ({reason})"
    if was_pinned:
        detail += "; overriding manual pin, pin cleared"
    audit.record(
        db, "device", "adms_protocol_change",
        target=device.serial_number, ip=ip,
        detail=detail,
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

        count = _log_bulk_payload("tabledata", SN, tablename, count, raw, body)
        _store_bulk_table(db, SN, tablename, body, source="tabledata")

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
# Bulk payloads: one log rule and one dispatch, shared by every transport
#
# The same keyed-TSV payload reaches this server two ways — pushed by the
# device as `cdata?table=tabledata` (§3.7), or returned by the device in answer
# to a `DATA QUERY` on `/iclock/querydata` (§3.13, E9). The bytes are
# identical, so the parsers must be too: one table, one parser, whichever door
# it came through. Anything else and a `user` record would mean two different
# things depending on whether the operator asked for it or the device
# volunteered it.
# ---------------------------------------------------------------------------

def _log_bulk_payload(source: str, sn: str, tablename: str, count: str,
                      raw: bytes, body: str) -> str:
    """Record one bulk payload's arrival, and return the count to acknowledge.

    Blob tables are summarised by size and record count; everything else is
    kept whole up to ``_TABLEDATA_LOG_LIMIT``. See the constants above for why
    the two limits differ so much.

    The returned count is the device's own ``count=`` when it sent one, and a
    record tally when it did not — so the acknowledgement is well-formed
    either way.
    """
    records = len([ln for ln in body.splitlines() if ln.strip()])
    if not count:
        count = str(records)

    low = tablename.lower()
    if low in _BLOB_TABLES:
        # `biodata` (E2) and `biophoto`/`userpic` (E5) are stored below;
        # `identitycard`, `templatev10` and `attphoto` are still out of
        # scope and genuinely discarded after this summary.
        stored_note = "stored" if low in _STORED_BLOB_TABLES else "not stored"
        log.info(
            "ADMS %s from %s: tablename=%s count=%s (%s) "
            "body=%d bytes in %d record(s) [base64, not logged]",
            source, sn, tablename, count, stored_note, len(raw), records,
        )
    else:
        log.info(
            "ADMS %s from %s: tablename=%s count=%s body=%s",
            source, sn, tablename, count, _clip(body, _TABLEDATA_LOG_LIMIT),
        )
    return count


def _store_bulk_table(db: Session, sn: str, tablename: str, body: str,
                      source: str = "tabledata") -> bool:
    """Hand one bulk payload to the parser that owns its table.

    Returns True if a parser took it, False if the table is one nothing here
    understands — the caller acknowledges either way.

    Every parser is wrapped the same way and for the same reason: the
    acknowledgement matters more than the ingest. A device that does not see
    the reply it expects is documented to retry the upload forever, so a parse
    or database fault has to be loud in the log and invisible on the wire.
    """
    low = tablename.lower()

    if low == "user":
        handler, args = _store_user_table, (db, sn, body)
    elif low == "biodata":
        handler, args = _store_biodata_table, (db, sn, body)
    elif low in ("biophoto", "userpic"):
        handler, args = _store_photo_table, (db, sn, body, low)
    else:
        return False

    try:
        handler(*args)
    except Exception:
        log.exception(
            "ADMS %s from %s: %s upload could not be stored; "
            "acknowledging anyway so the device does not retry forever",
            source, sn, low,
        )
        db.rollback()
    return True


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


def _store_biodata_table(db: Session, sn: str, body: str) -> None:
    """``tabledata&tablename=biodata`` — biometric templates (fingerprint,
    face, or any other modality ``type`` turns out to carry) pushed by a
    Security PUSH terminal.

    Stored in ``BiometricTemplate`` (see ``app/models.py`` for why that is a
    new table and not ``FingerprintTemplate``), keyed on ``(user_id, type,
    no)`` and upserted — a re-upload of the same template updates the
    existing row rather than duplicating it, so a device that resends its
    whole set on reconnect converges instead of accumulating.

    Every field survives verbatim, including ``duress``, ``index``,
    ``majorver``, ``minorver`` and ``format`` — none of them are understood
    or acted on here, only carried, because E4 needs the exact values to
    reconstruct a ``DATA UPDATE BIODATA`` command later. ``tmp`` is stored as
    the base64 text the device sent, never decoded.

    ``pin``, ``type`` and ``no`` are the identity of a record — without a
    usable value for each there is nowhere to upsert to — so a record missing
    any of them, or with no ``tmp`` at all, is skipped rather than guessed at,
    the same discipline ``_store_user_table`` uses for ``pin``.
    """
    stored = set()
    skipped = 0

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _tabledata_fields(line, "biodata")
        pin = fields.get("pin", "").strip()[:24]
        type_value = _to_int(fields.get("type"), default=None)
        no_value = _to_int(fields.get("no"), default=None)
        tmp = fields.get("tmp", "").strip()

        if not pin or type_value is None or no_value is None or not tmp:
            log.warning(
                "ADMS biodata upload from %s: skipping unusable record %r", sn, _clip(line, 300)
            )
            skipped += 1
            continue

        row = (
            db.query(BiometricTemplate)
            .filter_by(user_id=pin, type=type_value, no=no_value)
            .first()
        )
        if row is None:
            row = BiometricTemplate(user_id=pin, type=type_value, no=no_value)
            db.add(row)

        row.record_index = _to_int(fields.get("index"))
        row.valid = _to_int(fields.get("valid"))
        row.duress = _to_int(fields.get("duress"))
        row.majorver = _to_int(fields.get("majorver"))
        row.minorver = _to_int(fields.get("minorver"))
        row.format = _to_int(fields.get("format"))
        row.tmp = tmp
        row.source_device_sn = sn

        # Same reason as _store_user_table: makes the row visible to the next
        # line in this same batch, so two records for the same key merge
        # instead of racing the unique constraint.
        db.flush()
        stored.add((pin, type_value, no_value))

    db.commit()
    log.info(
        "ADMS biodata upload from %s: %d template(s) stored, %d record(s) skipped",
        sn, len(stored), skipped,
    )


def _store_photo_table(db: Session, sn: str, body: str, tablename: str) -> None:
    """``tabledata&tablename=biophoto`` / ``tablename=userpic`` — face photos
    pushed by a Security PUSH terminal (E5).

    On the operator's own capture (VGU6254600603, pins 1/2/3) the two tables
    carry the SAME image: identical ``filename``, identical ``size``, and
    every byte the log kept before its own line-length cap is character-for-
    character identical between the two for every pin observed. Rather than
    guessing which upload should win, both are stored — see
    ``EmployeePhoto`` for why a shared table keyed on ``(user_id, source)``
    is safer than collapsing them into one row.

    Upserted like ``_store_biodata_table``: a device resending its whole
    photo set on reconnect converges instead of accumulating. ``content`` is
    the base64 text the device sent, stored as-is — never decoded, re-encoded
    or re-compressed.

    ``pin`` and ``content`` are the identity of a usable record — without a
    person to attach it to, or any bytes at all, there is nowhere to store it
    — so a record missing either is skipped rather than guessed at, same as
    every other table parser in this module.
    """
    stored = set()
    skipped = 0

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _tabledata_fields(line, tablename)
        pin = fields.get("pin", "").strip()[:24]
        content = fields.get("content", "").strip()

        if not pin or not content:
            log.warning(
                "ADMS %s upload from %s: skipping unusable record %r",
                tablename, sn, _clip(line, 300),
            )
            skipped += 1
            continue

        row = (
            db.query(EmployeePhoto)
            .filter_by(user_id=pin, source=tablename)
            .first()
        )
        if row is None:
            row = EmployeePhoto(user_id=pin, source=tablename)
            db.add(row)

        row.filename = fields.get("filename", "").strip()[:255] or None
        # `type` only appears on biophoto records; a re-upload under the same
        # source that omits it must not clobber a previously-seen value with
        # None, so absence — not falsiness — decides whether it is touched.
        if "type" in fields:
            row.type = _to_int(fields.get("type"), default=None)
        row.size = _to_int(fields.get("size"), default=None)
        row.content = content
        row.source_device_sn = sn

        # Same reason as _store_biodata_table: makes the row visible to the
        # next line in this same batch, so two records for the same key merge
        # instead of racing the unique constraint.
        db.flush()
        stored.add(pin)

    db.commit()
    log.info(
        "ADMS %s upload from %s: %d photo(s) stored, %d record(s) skipped",
        tablename, sn, len(stored), skipped,
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

    # Delivery, retry and the attempt counter all live in one place —
    # app/services/commands.py — because E3 and E4 both queue work through it
    # and must not grow second opinions about what "delivered" means.
    lines = commands.next_commands(db, SN)
    if lines:
        # §3.8: `C:<id>:<command>`, several separated by LF. The id matters:
        # it is what the device quotes back at /iclock/devicecmd, and it is
        # the only thing that lets an acknowledgement be matched to the
        # command it is actually about.
        return PlainTextResponse(content="\n".join(lines))

    # Nothing owed. "OK" is the idle answer every implementation gives and the
    # device treats it as a heartbeat acknowledgement.
    return PlainTextResponse(content="OK")


def _parse_devicecmd(raw: str) -> list:
    """Parse the acknowledgements in a ``/iclock/devicecmd`` body.

    §3.9 specifies ``ID=${XXX}&Return=${XXX}&CMD=${XXX}&SN=${XXX}`` —
    ampersand-separated in the **body**, not the query. Real firmware is less
    tidy than the spec, so this accepts what devices are known to send:

    * the value of ``CMD`` contains a space (``CMD=DATA UPDATE``) and is not
      percent-encoded, so this splits on ``&`` and ``=`` directly rather than
      trusting a strict form parser;
    * some builds report several results in one POST, one per line, so each
      line is parsed separately;
    * ``Return`` may be signed (``Return=-14`` is a documented device-side
      error), so it is parsed as a signed integer.

    Returns ``[{"id": int, "return_code": int, "cmd": str}, …]``, skipping any
    fragment without a usable numeric ``ID``. Never raises: a malformed ack is
    worth a log line, not a 500 that makes the device retry the whole command.
    """
    results = []
    for line in raw.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue

        fields = {}
        for pair in line.split("&"):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            fields[key.strip().lower()] = value.strip()

        raw_id = fields.get("id", "")
        if not raw_id.lstrip("-").isdigit():
            continue

        raw_return = fields.get("return", "")
        results.append({
            "id": int(raw_id),
            # A missing Return is not silently treated as success: 0 is the
            # device saying "done", and absence is the device saying nothing.
            "return_code": int(raw_return) if raw_return.lstrip("-").isdigit() else None,
            "cmd": fields.get("cmd", ""),
        })

    return results


@router.post("/iclock/devicecmd", response_class=PlainTextResponse)
async def adms_devicecmd(
    request: Request,
    SN: str = Query(...),
    ID: str = Query(default=""),
    Return: str = Query(default=""),
    db: Session = Depends(get_db),
):
    """The device reporting what became of a command it was given.

    This used to acknowledge the *oldest* ``sent`` command for the serial and
    throw ``Return=`` away. With one command ever in flight that is invisible;
    with a real queue it concludes the wrong command every time — marking a
    failure as a success and leaving the command that actually ran to be
    retried until it is declared failed. Both now come from the device's own
    report: the id it names, and the code it returned.
    """
    _, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    raw = (await request.body()).decode("utf-8", errors="ignore")

    # Logged in full, at INFO, on every single ack — not only on the ones that
    # fail to parse. No acknowledgement from real hardware has ever been
    # observed by this application: 469 getrequest polls in the operator's
    # capture and not one devicecmd, because the queue was empty until E3
    # started provisioning people. The spec (§3.9) says these fields arrive
    # form-encoded in the body; §3.8's own example writes them as a query
    # string. Both are parsed below and neither is confirmed, so the first
    # real ack has to be readable from the log alone — which of the two the
    # firmware used, exactly how it framed it, and what it said — while the
    # operator is standing at the terminal watching. This costs one line per
    # concluded command and nothing at all when the queue is idle.
    log.info(
        "devicecmd from %s: body=%r query=%r content_type=%r",
        SN, raw[:500], str(request.query_params)[:500],
        request.headers.get("content-type", ""),
    )

    acks = _parse_devicecmd(raw)

    # The spec puts these in the body and that is what this parses first, but
    # §3.8's own example is written as a query string and no capture from the
    # operator's terminal has ever contained a devicecmd request — the device
    # has been polling getrequest for a queue that was never given anything to
    # deliver. So the query parameters are honoured as a fallback rather than
    # assuming which of the two this firmware will use.
    if not acks and ID.strip().lstrip("-").isdigit():
        acks = [{
            "id": int(ID.strip()),
            "return_code": int(Return.strip()) if Return.strip().lstrip("-").isdigit() else None,
            "cmd": request.query_params.get("CMD", ""),
        }]

    if not acks:
        log.warning(
            "devicecmd from %s carried no parseable ID= (body=%r, query=%r) — "
            "no command concluded",
            SN, raw[:200], str(request.query_params)[:200],
        )
        return PlainTextResponse(content="OK")

    for ack in acks:
        if ack["return_code"] is None:
            # Cannot be called a success and must not be called a rejection.
            # Left outstanding so the ordinary retry path gets another chance.
            log.warning(
                "devicecmd from %s reported ID=%s with no Return= — command "
                "left outstanding rather than guessed at",
                SN, ack["id"],
            )
            continue

        # Read the command body before concluding it: acknowledging moves the
        # row out of the outbox and deletes it, and what it *said* is how we
        # know what the device just confirmed. The device's own CMD= field is
        # no use for this — it carries "DATA UPDATE", not the record.
        outstanding = (
            db.query(DeviceCommandOutbox)
            .filter_by(id=ack["id"], device_sn=SN)
            .first()
        )
        body = outstanding.command if outstanding else ""

        outcome = commands.acknowledge(db, SN, ack["id"], ack["return_code"], ack["cmd"])

        if outcome == "acknowledged":
            # A confirmed `DATA UPDATE user` is the one moment the ADMS
            # transport learns that a person really is on this terminal, so it
            # is where the device_employees link is written — through the same
            # single writer the SDK path uses, never inline here.
            provisioning.note_acknowledged(db, SN, body)
            # And the mirror image (E8). A confirmed `DATA DELETE user` is the
            # only moment this application is entitled to say the person is
            # off that terminal — the link is dropped here and not one second
            # earlier, because until this ack arrives the delete was merely
            # queued and the person could still open the door.
            provisioning.note_revocation_acknowledged(db, SN, body)
            db.commit()
        elif outcome == "rejected":
            # The mirror image, and the reason E4 can queue a biometric behind
            # a user record at all. A refused `DATA UPDATE user` means this
            # terminal does not have the person — so any template still queued
            # for them here has nothing to attach to and is withdrawn with the
            # reason recorded, rather than being delivered to a device that
            # will either refuse it or file it against nobody.
            if provisioning.pin_from_user_command(body):
                provisioning.withdraw_orphaned_templates(db, SN)
                db.commit()

    # Always "OK": the device has already done the work, and refusing its
    # report only makes it repeat the command.
    return PlainTextResponse(content="OK")


# ---------------------------------------------------------------------------
# /iclock/querydata — the answer to a DATA QUERY (E9)
#
# CONFIRMED from the operator's BioFace A1 (VGU6254600603, 2026-08-21 07:22
# UTC), which is the only reason this endpoint exists. push-protocol.md §3.12
# listed `/iclock/querydata` as folklore because it appears in neither vendor
# document; the device then used it. The captured request, verbatim:
#
#     POST /iclock/querydata?SN=VGU6254600603&type=tabledata&cmdid=1
#          &tablename=user&count=3&packcnt=1&packidx=1
#     user uid=1<HT>cardno=<HT>pin=1<HT>…<HT>privilege=14<HT>disable=0<HT>verify=0
#     user uid=2<HT>…
#     user uid=3<HT>…
#
# Three facts follow from it, and each one is load-bearing:
#
# 1. **The body is a tabledata body.** Same keyed TSV, same repeated table-name
#    prefix, same tables. So it is parsed by the same parsers (E1/E2/E5) and
#    not by new ones — see `_store_bulk_table`.
#
# 2. **`cmdid` is the acknowledgement.** A device answering a DATA QUERY never
#    POSTs /iclock/devicecmd; it quotes the command id here instead. Nothing
#    else will ever conclude that outbox row, so if this endpoint does not, the
#    command retries on backoff and is eventually declared failed — after it
#    already succeeded and its answer was stored.
#
# 3. **`packcnt`/`packidx` split a payload across requests.** The capture reads
#    1/1 because three user records are about 375 bytes. A `biophoto` answer is
#    ~100 KB per person and MAX_REQUEST_BYTES caps one request at 2 MB, so a
#    real photo query will arrive in pieces. Parsing a piece is the failure
#    mode this whole section is built around: `_store_photo_table` cannot tell
#    a truncated base64 photo from a small one, and would store the fragment as
#    a complete image. So nothing is parsed until the last packet lands.
# ---------------------------------------------------------------------------

# Part-received transfers, keyed (serial, cmdid, tablename). Guarded by a lock
# because uvicorn runs the sync endpoints in a thread pool: two packets of the
# same transfer can be in flight at once.
#
# WHY MEMORY, given it does not survive a restart mid-transfer: because an
# incomplete transfer is worth nothing. Its command is deliberately left
# outstanding until the payload is whole (see `_conclude_query`), so a restart
# that drops the buffer leaves the DATA QUERY in the outbox, the device is
# handed it again on its next poll, and it re-answers from the start. The
# recovery path is the one the queue already has. The alternative — a table of
# half-payloads — would put megabytes of provably useless data in the
# operator's database to save a re-query that costs seconds.
_transfers = {}
_transfers_lock = threading.Lock()


def _transfer_key(sn: str, cmdid: str, tablename: str) -> tuple:
    """What makes two packets part of the same answer.

    Serial and cmdid alone would do it in theory; `tablename` is in the key as
    well because it costs nothing and it means a firmware that reuses a command
    id across two different tables cannot splice a `user` list into the middle
    of a photo.
    """
    return (sn, cmdid, tablename.lower())


def _expire_transfers(now: float) -> None:
    """Drop transfers nobody has added to in a while. Caller holds the lock.

    A device that starts a nine-packet answer and then reboots would otherwise
    pin its buffer until the process restarts. Logged at WARNING with the
    packets that did arrive, because a query that was answered and then
    abandoned half way is exactly the kind of thing that is invisible until
    somebody asks why an employee has no photo.
    """
    ttl = config.QUERYDATA_TRANSFER_TTL_SECONDS
    for key in [k for k, e in _transfers.items() if now - e["updated"] > ttl]:
        entry = _transfers.pop(key)
        log.warning(
            "ADMS querydata: abandoning incomplete transfer %r after %.0fs — "
            "%d of %s packet(s), %d byte(s) received and discarded; command %s "
            "was NOT concluded, so the device will be asked again",
            key, now - entry["updated"], len(entry["parts"]),
            entry["packcnt"], entry["bytes"], key[1] or "<none>",
        )


def _join_packets(parts: dict, tablename: str) -> str:
    """Reassemble the fragments of one transfer, in packet order.

    Concatenated with nothing between them. The model this assumes is that the
    device is chunking one byte stream, in which case plain concatenation
    reproduces the original exactly and inserting a separator would corrupt any
    record unlucky enough to straddle a boundary — a base64 photo with a
    newline injected into it is a photo that no longer decodes.

    The one case that model does not cover is a firmware that splits strictly
    on record boundaries and drops the trailing newline, which would glue the
    last record of one packet onto the first of the next. That case is repaired
    here, and it can be repaired safely: the join only inserts a newline when
    the next fragment *starts with the table-name prefix*, and `"user "`,
    `"biodata "`, `"biophoto "` cannot occur inside a base64 blob — the base64
    alphabet has no space in it. So a mid-record split never triggers it and a
    record-boundary split always does.
    """
    prefix = f"{tablename} ".lower()
    pieces = []
    for _index, fragment in sorted(parts.items()):
        if (
            pieces
            and not pieces[-1].endswith(("\n", "\r"))
            and prefix.strip()
            and fragment[:len(prefix)].lower() == prefix
        ):
            pieces.append("\n")
        pieces.append(fragment)
    return "".join(pieces)


def _accept_packet(sn: str, cmdid: str, tablename: str, body: str,
                   packidx: int, packcnt: int):
    """Buffer one packet; return the whole payload once the last one arrives.

    Returns the reassembled text when the transfer is complete, or ``None``
    while it is still short — and ``None`` is the answer that means "store
    nothing and conclude nothing yet".

    Completion is ``len(parts) >= packcnt`` rather than "indices 1..packcnt are
    all present". Both are true for a well-behaved device; the count form also
    survives a firmware that indexes from 0, which is a plausible difference
    between builds and not worth stalling a real transfer over. Re-delivery of
    a packet already held overwrites it and does not advance the count, so a
    device retrying packet 1 of 3 can never complete a transfer by repetition.
    """
    key = _transfer_key(sn, cmdid, tablename)
    now = time.monotonic()

    with _transfers_lock:
        _expire_transfers(now)

        entry = _transfers.get(key)
        if entry is not None and entry["packcnt"] != packcnt:
            # The device changed its mind about how long the answer is, which
            # means this is a fresh answer to the same query rather than a
            # continuation of the old one. Keeping the old fragments would
            # splice two different payloads together.
            log.warning(
                "ADMS querydata from %s: transfer %r restarted (packcnt %s -> %s); "
                "%d earlier packet(s) discarded",
                sn, key, entry["packcnt"], packcnt, len(entry["parts"]),
            )
            entry = None

        if entry is None:
            if len(_transfers) >= config.QUERYDATA_MAX_TRANSFERS:
                # Evict the least recently touched rather than refuse the new
                # one: the stalled transfers are the ones worth losing.
                oldest = min(_transfers, key=lambda k: _transfers[k]["updated"])
                _transfers.pop(oldest)
                log.warning(
                    "ADMS querydata: %d transfers already part-received (limit %d) — "
                    "evicted the stalest, %r",
                    len(_transfers) + 1, config.QUERYDATA_MAX_TRANSFERS, oldest,
                )
            entry = {"parts": {}, "packcnt": packcnt, "bytes": 0, "updated": now}
            _transfers[key] = entry

        entry["parts"][packidx] = body
        entry["updated"] = now
        entry["bytes"] = sum(len(p) for p in entry["parts"].values())

        if entry["bytes"] > config.QUERYDATA_MAX_TRANSFER_BYTES:
            _transfers.pop(key, None)
            log.error(
                "ADMS querydata from %s: transfer %r exceeded "
                "QUERYDATA_MAX_TRANSFER_BYTES (%d > %d) — discarded unparsed. "
                "Nothing was stored and command %s was NOT concluded; raise the "
                "limit if this payload is legitimate.",
                sn, key, entry["bytes"], config.QUERYDATA_MAX_TRANSFER_BYTES,
                cmdid or "<none>",
            )
            return None

        if len(entry["parts"]) < packcnt:
            log.info(
                "ADMS querydata from %s: packet %s/%s of %r buffered "
                "(%d packet(s), %d byte(s) so far) — nothing parsed and no "
                "command concluded until the transfer is complete",
                sn, packidx, packcnt, key, len(entry["parts"]), entry["bytes"],
            )
            return None

        _transfers.pop(key, None)
        return _join_packets(entry["parts"], tablename)


def _conclude_query(db: Session, sn: str, cmdid: str) -> None:
    """Conclude the outbox command this payload is the answer to.

    Only ever called once a transfer is complete. Concluding on packet 1 of 3
    would delete the outbox row while two thirds of the answer were still in
    flight: if the device then stopped, the command would read as a success
    whose result nobody has, and the retry that would have recovered it has
    already been thrown away.

    Delegated to `commands.acknowledge` rather than reimplemented, so this
    shares one definition of "concluded" with /iclock/devicecmd — including its
    DELETE-is-the-arbiter atomicity, which is what makes a re-delivered answer
    converge instead of writing a second history row.
    """
    if not cmdid.lstrip("-").isdigit():
        # A query answer with no id we can match. Worth saying out loud: the
        # payload is stored, but some outbox command is now going to retry
        # despite having been answered.
        log.warning(
            "ADMS querydata from %s: no usable cmdid=%r — the payload was "
            "stored but no command could be concluded, so it will be retried",
            sn, cmdid,
        )
        return

    # Return=0: the device did what it was asked and this payload is the
    # proof. There is no Return field on a querydata request to read it from —
    # answering the query at all *is* the success report.
    commands.acknowledge(db, sn, int(cmdid), 0, "DATA QUERY", source="querydata")


def _querydata_ack(tablename: str, count: str) -> str:
    """What to answer. See config.QUERYDATA_ACK_STYLE — this is not confirmed.

    Sent on every packet, not only the last: each packet is its own HTTP
    request, and an unanswered one is a retried one.
    """
    if config.QUERYDATA_ACK_STYLE == "ok" or not tablename:
        return "OK"
    return f"{tablename}={count}"


@router.api_route("/iclock/querydata", methods=["POST", "GET"],
                  response_class=PlainTextResponse)
async def adms_querydata(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    """Receive a device's answer to a `DATA QUERY`, and conclude the command.

    Authorised exactly like every other ADMS endpoint, and for a sharper reason
    than most: this one writes employees, biometric templates and photos from
    an unauthenticated request. The only thing standing between that and a
    stranger filling the employee table is `_authorise`, so it runs before a
    byte of the body is read.

    GET is registered defensively. Nothing has ever been seen using it and it
    carries no body, but a firmware that used it would otherwise fall to the
    catch-all's 404 and start the very retry loop this unit is closing.
    """
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal

    raw = b"" if request.method in ("GET", "HEAD") else await request.body()
    body = raw.decode("utf-8", errors="ignore")

    tablename = _query(request, "tablename").strip()
    cmdid = _query(request, "cmdid").strip()
    count = _query(request, "count").strip()
    packcnt = max(1, _to_int(_query(request, "packcnt"), 1))
    packidx = _to_int(_query(request, "packidx"), 1)

    # One line naming everything the request declared, on every packet. This
    # endpoint is two days old and derived from a single capture; the first
    # multi-packet transfer and the first unfamiliar `type=` both have to be
    # readable from the log alone.
    log.info(
        "ADMS querydata from %s: type=%r tablename=%r cmdid=%r count=%r "
        "packet=%s/%s bytes=%d method=%s",
        SN, _query(request, "type"), tablename, cmdid, count,
        packidx, packcnt, len(raw), request.method,
    )

    _touch(db, device, request)

    if not tablename:
        # Nothing to dispatch on and nothing to acknowledge with. Kept whole in
        # the log rather than dropped — the same rule as the catch-all — and
        # answered so the device stops asking.
        log.warning(
            "ADMS querydata from %s with no tablename: query=%r body=%s",
            SN, str(request.query_params), _clip(body, _TABLEDATA_LOG_LIMIT),
        )
        return PlainTextResponse(content="OK")

    ack = _querydata_ack(tablename, count or str(
        len([ln for ln in body.splitlines() if ln.strip()])
    ))

    payload = _accept_packet(SN, cmdid, tablename, body, packidx, packcnt)
    if payload is None:
        # Still short, or discarded for being oversized. Either way: nothing
        # parsed, nothing concluded, and the device told its packet arrived so
        # it sends the next one instead of repeating this one.
        return PlainTextResponse(content=ack)

    _log_bulk_payload("querydata", SN, tablename, count, payload.encode("utf-8"), payload)

    if not _store_bulk_table(db, SN, tablename, payload, source="querydata"):
        # A table nothing here parses. Logged in full and acknowledged, exactly
        # as the cdata catch-all does: the reason we know this endpoint exists
        # at all is that an unrecognised request was logged instead of dropped.
        log.warning(
            "ADMS querydata from %s: no parser for tablename=%r — payload "
            "logged and acknowledged, not stored: %s",
            SN, tablename, _clip(payload, _TABLEDATA_LOG_LIMIT),
        )

    # Last, and only now. The command is concluded once its answer is whole and
    # has been offered to a parser — including a parser that refused it, since
    # the device did answer and re-asking would earn the same reply.
    _conclude_query(db, SN, cmdid)

    return PlainTextResponse(content=ack)


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
