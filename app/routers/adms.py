import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AttendanceLog, Device, DeviceCommand
from app.net import client_ip, ip_in_cidrs
from app.services import pairing

router = APIRouter(tags=["adms"])

log = logging.getLogger(__name__)

# These four endpoints are the only ones reachable without credentials, so a
# refusal says nothing a prober could learn from: not whether the serial is
# known, not whether it is merely awaiting approval, not whether an IP rule
# exists. The reason goes to the log, where the operator can see it.
_REFUSAL_BODY = "Unauthorized"
_REFUSAL_STATUS = 401


def _refuse(sn: str, ip: str, reason: str) -> PlainTextResponse:
    log.warning("ADMS refused: serial=%s ip=%s reason=%s", sn, ip, reason)
    return PlainTextResponse(content=_REFUSAL_BODY, status_code=_REFUSAL_STATUS)


def _touch(db: Session, device: Device, request: Request) -> None:
    """Mark a device as heard from, recording where it was heard from.

    The address stored is the resolved client address, never
    ``request.client.host`` — behind Apache that is only ever the proxy."""
    device.last_seen = datetime.now(timezone.utc)
    device.is_online = True
    device.last_ip = client_ip(request)
    db.commit()


def _authorise(sn: str, request: Request, db: Session):
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

    if not device:
        if not pairing.is_open(db):
            return None, _refuse(sn, ip, "unknown serial, pairing window closed")
        db.add(Device(
            serial_number=sn,
            ip_address=ip,
            port=4370,
            name="Unknown Device",
            status="pending",
            last_ip=ip,
        ))
        db.commit()
        log.warning(
            "ADMS: new serial %s from %s filed for approval (pairing window open)", sn, ip
        )
        return None, _refuse(sn, ip, "awaiting approval")

    if device.status != "approved":
        # Still worth recording where it is calling from — that is what the
        # operator needs in order to recognise it in the approval queue.
        if device.last_ip != ip:
            device.last_ip = ip
            db.commit()
        return None, _refuse(sn, ip, f"device status is {device.status}")

    if device.ip_check_enabled and not ip_in_cidrs(ip, device.allowed_cidrs):
        if device.last_ip != ip:
            device.last_ip = ip
            db.commit()
        return None, _refuse(sn, ip, "source address outside the device allowlist")

    return device, None


@router.get("/iclock/cdata", response_class=PlainTextResponse)
def adms_handshake(
    request: Request,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device, refusal = _authorise(SN, request, db)
    if refusal:
        return refusal
    _touch(db, device, request)

    body = "\n".join([
        f"GET OPTION FROM: {SN}",
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
    return PlainTextResponse(content=body)


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

    if table != "ATTLOG":
        return PlainTextResponse(content="OK")

    raw = await request.body()
    body = raw.decode("utf-8", errors="ignore")

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
            device_sn=SN, user_id=user_id, timestamp=timestamp
        ).first()
        if not exists:
            db.add(AttendanceLog(
                device_sn=SN,
                user_id=user_id,
                timestamp=timestamp,
                status=status,
                punch=punch,
                source="adms_push",
            ))

    db.commit()

    _touch(db, device, request)

    return PlainTextResponse(content="OK")


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
