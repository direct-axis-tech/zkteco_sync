import logging
from datetime import datetime, timezone
from zk import ZK
from zk.exception import ZKErrorConnection, ZKNetworkError

from app.database import SessionLocal
from app.models import AttendanceLog, Device, DeviceEmployee, Employee

log = logging.getLogger(__name__)


def _connect(device):
    zk = ZK(device.ip_address, port=device.port, timeout=30, verbose=False)
    return zk.connect()


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
                emp = db.query(Employee).filter_by(user_id=str(user.user_id)).first()
                if emp:
                    emp.name = user.name
                    emp.privilege = user.privilege
                    emp.card = str(user.card)
                    emp.updated_at = datetime.now(timezone.utc)
                else:
                    emp = Employee(
                        user_id=str(user.user_id),
                        name=user.name,
                        privilege=user.privilege,
                        card=str(user.card),
                    )
                    db.add(emp)

                de = db.query(DeviceEmployee).filter_by(
                    device_sn=serial_number, user_id=str(user.user_id)
                ).first()
                if de:
                    de.uid = user.uid
                    de.synced_at = datetime.now(timezone.utc)
                else:
                    db.add(DeviceEmployee(
                        device_sn=serial_number,
                        user_id=str(user.user_id),
                        uid=user.uid,
                    ))
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
            for att in records:
                exists = db.query(AttendanceLog).filter_by(
                    device_sn=serial_number,
                    user_id=str(att.user_id),
                    timestamp=att.timestamp,
                ).first()
                if not exists:
                    db.add(AttendanceLog(
                        device_sn=serial_number,
                        user_id=str(att.user_id),
                        timestamp=att.timestamp,
                        status=att.status,
                        punch=att.punch,
                        source="sdk_pull",
                    ))
                    result["attendance_synced"] += 1

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
