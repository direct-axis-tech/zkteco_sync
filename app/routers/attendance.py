from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.deps import require_auth

from app.database import get_db
from app.models import AttendanceLog
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
    return {
        "total": total,
        "items": [AttendanceOut.model_validate(r) for r in rows],
    }
