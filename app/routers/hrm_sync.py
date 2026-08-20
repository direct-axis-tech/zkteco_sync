from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import audit
from app.database import get_db
from app.deps import require_admin, require_auth
from app.models import HrmIntegration, User
from app.net import client_ip
from app.services.hrm_sync import run_sync

router = APIRouter(prefix="/hrm-sync", tags=["hrm-sync"], dependencies=[Depends(require_auth)])


# `timezone` is gone from both this shape and the response (D10). A punch's
# timezone is a property of the record that carries it, not of the HRM
# connection: one global setting could only ever be right for one device, and
# it was being applied to a digit string it had no relationship to. The
# hrm_integration.timezone column is deliberately left in place — migrations
# here are additive-only and dropping it would gain nothing — but nothing
# reads it any more.
class HrmConfigUpdate(BaseModel):
    endpoint: Optional[str] = None
    secret: Optional[str] = None
    location_id: Optional[str] = None
    interval_seconds: Optional[int] = None
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
        "secret_set":        bool(row.secret),
        "location_id":       row.location_id,
        "interval_seconds":  row.interval_seconds,
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
def update_config(
    payload: HrmConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = _get_or_create(db)
    updates = payload.model_dump(exclude_unset=True)
    # secret is write-only: the client never sees the current value, so a
    # blank or omitted one must mean "leave it alone", not "erase it". Only
    # a genuinely new, non-empty secret is allowed to overwrite it.
    secret_changed = bool(updates.get("secret"))
    if "secret" in updates and not updates["secret"]:
        updates.pop("secret")
    for field, value in updates.items():
        setattr(row, field, value)
    db.commit()
    db.refresh(row)

    # Every field name that changed is fine to record — only the secret's
    # value must never appear in detail. "secret" survives in `updates` here
    # only when it was genuinely set (see the pop above).
    fields_changed = sorted(updates.keys())
    if fields_changed:
        audit.record(db, admin.username, "hrm_config_change", ip=client_ip(request),
                     detail=f"fields changed: {', '.join(fields_changed)}"
                     + (" (secret value not logged)" if secret_changed else ""))
    return _serialize(row)


@router.post("/run", dependencies=[Depends(require_admin)])
def trigger_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_sync)
    return {"message": "Sync started"}
