from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_auth
from app.models import HrmIntegration
from app.services.hrm_sync import run_sync

router = APIRouter(prefix="/hrm-sync", tags=["hrm-sync"], dependencies=[Depends(require_auth)])


class HrmConfigUpdate(BaseModel):
    endpoint: Optional[str] = None
    secret: Optional[str] = None
    location_id: Optional[str] = None
    interval_seconds: Optional[int] = None
    timezone: Optional[str] = None
    enabled: Optional[bool] = None
    last_synced_id: Optional[int] = None


def _get_or_create(db: Session) -> HrmIntegration:
    row = db.query(HrmIntegration).filter_by(id=1).first()
    if not row:
        row = HrmIntegration(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _serialize(row: HrmIntegration) -> dict:
    return {
        "endpoint":          row.endpoint,
        "secret":            row.secret,
        "location_id":       row.location_id,
        "interval_seconds":  row.interval_seconds,
        "timezone":          row.timezone,
        "enabled":           row.enabled,
        "last_synced_id":    row.last_synced_id,
        "last_run_at":       row.last_run_at,
        "records_last_push": row.records_last_push,
        "total_pushed":      row.total_pushed,
        "last_error":        row.last_error,
    }


@router.get("")
def get_config(db: Session = Depends(get_db)):
    return _serialize(_get_or_create(db))


@router.put("")
def update_config(payload: HrmConfigUpdate, db: Session = Depends(get_db)):
    row = _get_or_create(db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/run")
def trigger_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_sync)
    return {"message": "Sync started"}
