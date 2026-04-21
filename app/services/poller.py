from datetime import datetime, timezone
from zk import ZK
from zk.exception import ZKErrorConnection, ZKNetworkError

from app.database import SessionLocal
from app.models import AttendanceLog, Device, DeviceEmployee, Employee


def _connect(device):
    zk = ZK(device.ip_address, port=device.port, timeout=30, verbose=False)
    return zk.connect()


def pull_employees(serial_number: str) -> dict:
    result = {"users_synced": 0, "errors": []}
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
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

        except (ZKErrorConnection, ZKNetworkError) as e:
            result["errors"].append(str(e))
            device.is_online = False
            db.commit()
        except Exception as e:
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
    result = {"attendance_synced": 0, "errors": []}
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
            conn = _connect(device)
            conn.disable_device()

            for att in conn.get_attendance():
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

        except (ZKErrorConnection, ZKNetworkError) as e:
            result["errors"].append(str(e))
            device.is_online = False
            db.commit()
        except Exception as e:
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
