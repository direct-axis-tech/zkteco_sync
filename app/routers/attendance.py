from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.deps import require_auth

from app import config
from app.database import get_db
from app.models import AttendanceLog, Device
from app.schemas import AttendanceOut

router = APIRouter(prefix="/attendance", tags=["attendance"], dependencies=[Depends(require_auth)])


def _build_query(db, device_sn, user_id, from_date, to_date):
    q = db.query(AttendanceLog)
    if device_sn:
        q = q.filter(AttendanceLog.device_sn == device_sn)
    if user_id:
        q = q.filter(AttendanceLog.user_id == user_id)
    if from_date:
        q = q.filter(AttendanceLog.timestamp >= from_date)
    if to_date:
        q = q.filter(AttendanceLog.timestamp <= to_date)
    return q


@router.get("")
def list_attendance(
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(50, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    q = _build_query(db, device_sn, user_id, from_date, to_date)
    total = q.count()
    rows = q.order_by(AttendanceLog.timestamp.desc()).offset(offset).limit(limit).all()

    # A punch time is the device's own wall-clock with no offset, so it is
    # meaningless without a label. Records stamped at ingest carry their own;
    # rows that predate the column resolve to their device's zone, and then to
    # the configured default. The same order the HRM push uses — the UI must
    # never show a time it cannot say the meaning of, and must never invent
    # one by re-zoning it into the viewer's locale.
    device_zones = dict(db.query(Device.serial_number, Device.timezone).all())

    items = []
    for r in rows:
        item = AttendanceOut.model_validate(r)
        if not item.timezone:
            item.timezone = device_zones.get(r.device_sn) or config.DEFAULT_DEVICE_TIMEZONE
        items.append(item)

    return {"total": total, "items": items}
