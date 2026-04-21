from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.deps import require_auth

from app.database import get_db
from app.models import AttendanceLog
from app.schemas import AttendanceOut

router = APIRouter(prefix="/attendance", tags=["attendance"], dependencies=[Depends(require_auth)])


@router.get("", response_model=List[AttendanceOut])
def list_attendance(
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    q = db.query(AttendanceLog)
    if device_sn:
        q = q.filter(AttendanceLog.device_sn == device_sn)
    if user_id:
        q = q.filter(AttendanceLog.user_id == user_id)
    if from_date:
        q = q.filter(AttendanceLog.timestamp >= from_date)
    if to_date:
        q = q.filter(AttendanceLog.timestamp <= to_date)
    return q.order_by(AttendanceLog.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/count")
def count_attendance(
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(AttendanceLog)
    if device_sn:
        q = q.filter(AttendanceLog.device_sn == device_sn)
    if user_id:
        q = q.filter(AttendanceLog.user_id == user_id)
    if from_date:
        q = q.filter(AttendanceLog.timestamp >= from_date)
    if to_date:
        q = q.filter(AttendanceLog.timestamp <= to_date)
    return {"count": q.count()}
