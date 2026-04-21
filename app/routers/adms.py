from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AttendanceLog, Device, DeviceCommand
from app.services.poller import pull_device

router = APIRouter(tags=["adms"])


def _ensure_registered(
    sn: str, ip: str, db: Session, background_tasks: BackgroundTasks
) -> Device:
    device = db.query(Device).filter_by(serial_number=sn).first()
    if not device:
        device = Device(
            serial_number=sn,
            ip_address=ip,
            port=4370,
            name="Unknown Device",
        )
        db.add(device)
        db.commit()
        db.refresh(device)
        background_tasks.add_task(pull_device, sn)
    return device


@router.get("/iclock/cdata", response_class=PlainTextResponse)
def adms_handshake(
    request: Request,
    background_tasks: BackgroundTasks,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device = _ensure_registered(SN, request.client.host, db, background_tasks)
    device.last_seen = datetime.utcnow()
    device.is_online = True
    db.commit()

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
    background_tasks: BackgroundTasks,
    SN: str = Query(...),
    table: str = Query(default=""),
    db: Session = Depends(get_db),
):
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

    device = _ensure_registered(SN, request.client.host, db, background_tasks)
    device.last_seen = datetime.utcnow()
    device.is_online = True
    db.commit()

    return PlainTextResponse(content="OK")


@router.get("/iclock/ping", response_class=PlainTextResponse)
def adms_ping(
    request: Request,
    background_tasks: BackgroundTasks,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device = _ensure_registered(SN, request.client.host, db, background_tasks)
    device.last_seen = datetime.utcnow()
    device.is_online = True
    db.commit()
    return PlainTextResponse(content="OK")


@router.get("/iclock/getrequest", response_class=PlainTextResponse)
def adms_getrequest(
    request: Request,
    background_tasks: BackgroundTasks,
    SN: str = Query(...),
    db: Session = Depends(get_db),
):
    device = _ensure_registered(SN, request.client.host, db, background_tasks)
    device.last_seen = datetime.utcnow()
    device.is_online = True
    db.commit()

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
    SN: str = Query(...),
    ID: str = Query(default=""),
    db: Session = Depends(get_db),
):
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
