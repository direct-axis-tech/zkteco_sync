import json
import logging
from datetime import datetime, timezone

import httpx

from app import config
from app.database import SessionLocal
from app.models import AttendanceLog, Device, Employee, HrmIntegration

log = logging.getLogger(__name__)

BATCH_SIZE = 10_000


def _get_or_create(db) -> HrmIntegration:
    row = db.query(HrmIntegration).filter_by(id=1).first()
    if not row:
        row = HrmIntegration(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def is_configured() -> bool:
    db = SessionLocal()
    try:
        row = _get_or_create(db)
        return bool(row.enabled and row.endpoint and row.secret)
    finally:
        db.close()


def run_sync() -> dict:
    """Push attendance records newer than last_synced_id to the HRM server."""
    db = SessionLocal()
    try:
        cfg = _get_or_create(db)

        if not cfg.enabled or not cfg.endpoint or not cfg.secret:
            return {"skipped": True, "reason": "Not configured or disabled"}

        last_id = cfg.last_synced_id or 0

        rows = (
            db.query(AttendanceLog)
            .filter(AttendanceLog.id > last_id)
            .order_by(AttendanceLog.id)
            .all()
        )

        if not rows:
            cfg.last_run_at = datetime.now(timezone.utc)
            cfg.records_last_push = 0
            db.commit()
            return {"pushed": 0, "last_synced_id": last_id}

        emp_cache = {e.user_id: e for e in db.query(Employee).all()}
        dev_cache = {d.serial_number: d for d in db.query(Device).all()}

        data = [_map(r, emp_cache, dev_cache, cfg.location_id) for r in rows]

        total_pushed = 0
        for i in range(0, len(data), BATCH_SIZE):
            batch = data[i: i + BATCH_SIZE]
            try:
                resp = httpx.post(
                    cfg.endpoint,
                    data={"key": cfg.secret, "data": json.dumps(batch)},
                    params={"loc": cfg.location_id},
                    timeout=120,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                total_pushed += len(batch)
            except Exception as e:
                cfg.last_run_at = datetime.now(timezone.utc)
                cfg.last_error = f"Batch {i // BATCH_SIZE} failed: {e}"
                db.commit()
                log.error("HRM sync batch error: %s", e)
                return {"error": str(e), "pushed_so_far": total_pushed}

        new_last_id = rows[-1].id
        cfg.last_run_at = datetime.now(timezone.utc)
        cfg.last_synced_id = new_last_id
        cfg.records_last_push = total_pushed
        cfg.total_pushed = (cfg.total_pushed or 0) + total_pushed
        cfg.last_error = None
        db.commit()

        log.info("HRM sync: pushed %d records (last_id=%d)", total_pushed, new_last_id)
        return {"pushed": total_pushed, "last_synced_id": new_last_id}

    except Exception as e:
        log.exception("HRM sync unexpected error")
        try:
            cfg = _get_or_create(db)
            cfg.last_run_at = datetime.now(timezone.utc)
            cfg.last_error = str(e)
            db.commit()
        except Exception:
            pass
        return {"error": str(e)}
    finally:
        db.close()


def _record_timezone(r: AttendanceLog, dev) -> str:
    """What this record's digits mean, in order of authority.

    The record's own snapshot first — it is the only value that was true at
    the moment the punch was stored. Then the device's current zone, for a row
    that predates the column. Then the configured default, so the HRM never
    receives a blank or missing timezone for a punch time that has no offset
    of its own: a silently unlabelled record is exactly the ambiguity that put
    punches four hours out in the first place.
    """
    return r.timezone or (dev.timezone if dev is not None else None) or config.DEFAULT_DEVICE_TIMEZONE


def _map(r: AttendanceLog, emp_cache, dev_cache, loc) -> dict:
    emp = emp_cache.get(r.user_id)
    dev = dev_cache.get(r.device_sn)
    return {
        "id":             r.id,
        "loc":            loc,
        "empid":          r.user_id,
        # No conversion, here or anywhere: these are the digits the device
        # reported, formatted and sent unchanged. What changed in D10 is only
        # where `timezone` comes from — the record's own snapshot instead of a
        # single global setting on the HRM config, which was a guess that
        # applied one answer to every device.
        "authdatetime":   r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "authdate":       r.timestamp.strftime("%Y-%m-%d"),
        "authtime":       r.timestamp.strftime("%H:%M:%S"),
        "timezone":       _record_timezone(r, dev),
        "status":         r.status,
        "devicename":     dev.name if dev and dev.name else r.device_sn,
        "deviceserialno": r.device_sn,
        "person":         emp.name if emp else "",
        "cardno":         emp.card if emp else "",
        "latitude":       "",
        "longitude":      "",
    }
