import json
import logging
import os
from datetime import datetime

import httpx

from app.database import SessionLocal
from app.models import AttendanceLog, Device, Employee, HrmSyncState

log = logging.getLogger(__name__)

BATCH_SIZE = 10_000


def _config():
    return {
        "endpoint": os.getenv("HRM_SYNC_ENDPOINT", "").strip(),
        "secret":   os.getenv("HRM_SYNC_SECRET", "").strip(),
        "loc":      os.getenv("HRM_SYNC_LOCATION_ID", "1").strip(),
        "tz":       os.getenv("HRM_SYNC_TIMEZONE", "UTC").strip(),
    }


def is_configured() -> bool:
    c = _config()
    return bool(c["endpoint"] and c["secret"])


def _get_or_create_state(db) -> HrmSyncState:
    state = db.query(HrmSyncState).filter_by(id=1).first()
    if not state:
        state = HrmSyncState(id=1)
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


def run_sync() -> dict:
    """Push new attendance records to the HRM server. Returns a result summary."""
    cfg = _config()
    if not cfg["endpoint"] or not cfg["secret"]:
        return {"skipped": True, "reason": "HRM sync not configured"}

    db = SessionLocal()
    try:
        state = _get_or_create_state(db)

        # Ask HRM server for the last ref_id it has
        try:
            resp = httpx.get(
                cfg["endpoint"],
                params={"loc": cfg["loc"]},
                timeout=30,
                follow_redirects=True,
            )
            resp.raise_for_status()
            last_id_text = resp.text.strip()
            if not last_id_text.isdigit():
                raise ValueError(f"HRM server returned unexpected response: {last_id_text!r}")
            last_id = int(last_id_text)
        except Exception as e:
            _save_error(db, state, f"Failed to fetch last ID from HRM: {e}")
            return {"error": str(e)}

        # Fetch new records
        rows = (
            db.query(AttendanceLog)
            .filter(AttendanceLog.id > last_id)
            .order_by(AttendanceLog.id)
            .all()
        )

        if not rows:
            _save_ok(db, state, pushed=0, last_id=last_id)
            return {"pushed": 0, "last_id": last_id}

        # Build employee and device name caches
        emp_cache = {
            e.user_id: e
            for e in db.query(Employee).all()
        }
        dev_cache = {
            d.serial_number: d
            for d in db.query(Device).all()
        }

        data = [
            _map_record(r, emp_cache, dev_cache, cfg["loc"], cfg["tz"])
            for r in rows
        ]

        # Push in batches
        total_pushed = 0
        for i in range(0, len(data), BATCH_SIZE):
            batch = data[i: i + BATCH_SIZE]
            try:
                resp = httpx.post(
                    cfg["endpoint"],
                    data={"key": cfg["secret"], "data": json.dumps(batch)},
                    params={"loc": cfg["loc"]},
                    timeout=120,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                total_pushed += len(batch)
            except Exception as e:
                _save_error(db, state, f"Batch {i // BATCH_SIZE} failed: {e}")
                return {"error": str(e), "pushed_so_far": total_pushed}

        new_last_id = rows[-1].id
        _save_ok(db, state, pushed=total_pushed, last_id=new_last_id)
        log.info("HRM sync: pushed %d records (last id %d)", total_pushed, new_last_id)
        return {"pushed": total_pushed, "last_id": new_last_id}

    except Exception as e:
        log.exception("HRM sync unexpected error")
        try:
            state = _get_or_create_state(db)
            _save_error(db, state, str(e))
        except Exception:
            pass
        return {"error": str(e)}
    finally:
        db.close()


def _map_record(r: AttendanceLog, emp_cache, dev_cache, loc, tz) -> dict:
    emp = emp_cache.get(r.user_id)
    dev = dev_cache.get(r.device_sn)
    return {
        "id":             r.id,
        "loc":            loc,
        "empid":          r.user_id,
        "authdatetime":   r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "authdate":       r.timestamp.strftime("%Y-%m-%d"),
        "authtime":       r.timestamp.strftime("%H:%M:%S"),
        "timezone":       tz,
        "status":         r.status,
        "devicename":     dev.name if dev and dev.name else r.device_sn,
        "deviceserialno": r.device_sn,
        "person":         emp.name if emp else "",
        "cardno":         emp.card if emp else "",
        "latitude":       "",
        "longitude":      "",
    }


def _save_ok(db, state: HrmSyncState, pushed: int, last_id: int):
    state.last_run_at = datetime.utcnow()
    state.records_last_push = pushed
    state.total_pushed = (state.total_pushed or 0) + pushed
    state.last_synced_id = last_id
    state.last_error = None
    db.commit()


def _save_error(db, state: HrmSyncState, msg: str):
    state.last_run_at = datetime.utcnow()
    state.last_error = msg
    db.commit()
    log.error("HRM sync error: %s", msg)
