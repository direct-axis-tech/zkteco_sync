import logging
from datetime import datetime, timezone
from zk import ZK
from zk.exception import ZKErrorConnection, ZKErrorResponse, ZKNetworkError

from app import config
from app.database import SessionLocal
from app.models import AttendanceLog, Device
from app.services import employee_sync

log = logging.getLogger(__name__)


def _connect(device):
    zk = ZK(device.ip_address, port=device.port, timeout=30, password=device.comm_key or 0, verbose=False)
    try:
        return zk.connect()
    except ZKErrorResponse as exc:
        # See app/services/sdk.py:_connect for why this message match is the
        # only reliable way pyzk signals a rejected comm key.
        if str(exc) == "Unauthenticated":
            raise ZKErrorResponse("Device refused the connection — the configured comm key is likely wrong")
        raise


def pull_employees(serial_number: str) -> dict:
    log.info("pull_employees: starting for device %s", serial_number)
    result = {"users_synced": 0, "errors": []}
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            log.warning("pull_employees: device %s not found in DB", serial_number)
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
            log.info("pull_employees: connecting to %s (%s:%s)",
                     serial_number, device.ip_address, device.port)
            conn = _connect(device)
            conn.disable_device()

            for user in conn.get_users():
                # Deliberately the same writer the ADMS `tabledata&tablename=user`
                # upload uses (app/services/employee_sync.py). A device on the
                # LAN can be reachable over both TCP 4370 and the PUSH channel,
                # and two writers with different ideas of what an empty field
                # means would make the row flip-flop between them. The visible
                # change from the previous inline version: pyzk reports an
                # unnamed user as "" and a card-less user as 0, and neither now
                # overwrites a name or card that is already on the row.
                employee_sync.record_device_user(
                    db,
                    serial_number,
                    user.user_id,
                    uid=user.uid,
                    name=user.name,
                    privilege=user.privilege,
                    card=user.card,
                )
                result["users_synced"] += 1

            db.commit()
            device.last_seen = datetime.now(timezone.utc)
            device.is_online = True
            db.commit()
            log.info("pull_employees: done for %s — %d users synced",
                     serial_number, result["users_synced"])

        except (ZKErrorConnection, ZKNetworkError) as e:
            log.error("pull_employees: connection error for %s — %s", serial_number, e)
            result["errors"].append(str(e))
            device.is_online = False
            db.commit()
        except ZKErrorResponse as e:
            log.error("pull_employees: device %s refused authentication — %s", serial_number, e)
            result["errors"].append(str(e))
            db.rollback()
        except Exception as e:
            log.exception("pull_employees: unexpected error for %s", serial_number)
            result["errors"].append(str(e))
            db.rollback()
        finally:
            if conn:
                try:
                    conn.enable_device()
                    conn.disconnect()
                except Exception:
                    pass
    finally:
        db.close()

    return result


def pull_attendance(serial_number: str) -> dict:
    log.info("pull_attendance: starting for device %s", serial_number)
    result = {"attendance_synced": 0, "errors": []}
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            log.warning("pull_attendance: device %s not found in DB", serial_number)
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
            log.info("pull_attendance: connecting to %s (%s:%s)",
                     serial_number, device.ip_address, device.port)
            conn = _connect(device)
            conn.disable_device()

            records = conn.get_attendance()
            log.info("pull_attendance: device %s returned %d records from device",
                     serial_number, len(records))

            # Load the keys already stored for this device in one query, rather
            # than a SELECT per record (20k+ round-trips otherwise).
            existing = {
                (uid, ts)
                for uid, ts in db.query(
                    AttendanceLog.user_id, AttendanceLog.timestamp
                ).filter_by(device_sn=serial_number)
            }

            # Devices routinely report the same punch more than once in a single
            # pull, so dedupe within the batch too — the session has
            # autoflush=False, so the per-row check below can't see rows added
            # earlier in this loop, and a duplicate would trip uq_attendance and
            # roll back the entire pull.
            seen = set()
            new_rows = []
            for att in records:
                key = (str(att.user_id), att.timestamp)
                if key in existing or key in seen:
                    continue
                seen.add(key)
                new_rows.append(AttendanceLog(
                    device_sn=serial_number,
                    user_id=str(att.user_id),
                    timestamp=att.timestamp,
                    status=att.status,
                    punch=att.punch,
                    source="sdk_pull",
                    # pyzk hands back the device's own naive wall-clock, same
                    # as a PUSH record. Stored as-is and labelled, never
                    # converted (D10).
                    timezone=device.timezone or config.DEFAULT_DEVICE_TIMEZONE,
                ))

            db.bulk_save_objects(new_rows)
            result["attendance_synced"] = len(new_rows)

            db.commit()
            device.last_seen = datetime.now(timezone.utc)
            device.is_online = True
            db.commit()
            log.info("pull_attendance: done for %s — %d new records inserted",
                     serial_number, result["attendance_synced"])

        except (ZKErrorConnection, ZKNetworkError) as e:
            log.error("pull_attendance: connection error for %s — %s", serial_number, e)
            result["errors"].append(str(e))
            device.is_online = False
            db.commit()
        except ZKErrorResponse as e:
            log.error("pull_attendance: device %s refused authentication — %s", serial_number, e)
            result["errors"].append(str(e))
            db.rollback()
        except Exception as e:
            log.exception("pull_attendance: unexpected error for %s", serial_number)
            result["errors"].append(str(e))
            db.rollback()
        finally:
            if conn:
                try:
                    conn.enable_device()
                    conn.disconnect()
                except Exception:
                    pass
    finally:
        db.close()

    return result


def pull_device(serial_number: str) -> dict:
    """Sync everything: employees + attendance. Used by Sync All and auto-registration."""
    emp_result  = pull_employees(serial_number)
    att_result  = pull_attendance(serial_number)
    return {
        "users_synced":      emp_result["users_synced"],
        "attendance_synced": att_result["attendance_synced"],
        "errors":            emp_result["errors"] + att_result["errors"],
    }
