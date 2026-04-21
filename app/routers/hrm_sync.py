from fastapi import APIRouter, BackgroundTasks, Depends

from app.database import get_db
from app.deps import require_auth
from app.models import HrmSyncState
from app.services.hrm_sync import is_configured, run_sync

router = APIRouter(prefix="/hrm-sync", tags=["hrm-sync"], dependencies=[Depends(require_auth)])


@router.get("/status")
def get_status(db=Depends(get_db)):
    state = db.query(HrmSyncState).filter_by(id=1).first()
    return {
        "configured": is_configured(),
        "last_run_at": state.last_run_at if state else None,
        "last_synced_id": state.last_synced_id if state else 0,
        "records_last_push": state.records_last_push if state else 0,
        "total_pushed": state.total_pushed if state else 0,
        "last_error": state.last_error if state else None,
    }


@router.post("/run")
def trigger_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_sync)
    return {"message": "Sync started"}
