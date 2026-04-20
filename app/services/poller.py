from datetime import datetime
from zk import ZK
from zk.exception import ZKErrorConnection, ZKNetworkError

from app.database import SessionLocal
from app.models import Device, Employee, DeviceEmployee, AttendanceLog


def pull_device(serial_number: str) -> dict:
    result = {"users_synced": 0, "attendance_synced": 0, "errors": []}

    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            result["errors"].append("Device not found")
            return result

        zk = ZK(device.ip_address, port=device.port, timeout=30, verbose=False)
        conn = None
        try:
            conn = zk.connect()
            conn.disable_device()

            # --- Sync users ---
            users = conn.get_users()
            for user in users:
                emp = db.query(Employee).filter_by(user_id=str(user.user_id)).first()
                if emp:
                    emp.name = user.name
                    emp.privilege = user.privilege
                    emp.card = str(user.card)
                    emp.updated_at = datetime.utcnow()
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
                    de.synced_at = datetime.utcnow()
                else:
                    de = DeviceEmployee(
                        device_sn=serial_number,
                        user_id=str(user.user_id),
                        uid=user.uid,
                    )
                    db.add(de)

                result["users_synced"] += 1

            db.commit()

            # --- Sync attendance ---
            attendances = conn.get_attendance()
            for att in attendances:
                exists = db.query(AttendanceLog).filter_by(
                    device_sn=serial_number,
                    user_id=str(att.user_id),
                    timestamp=att.timestamp,
                ).first()
                if not exists:
                    log = AttendanceLog(
                        device_sn=serial_number,
                        user_id=str(att.user_id),
                        timestamp=att.timestamp,
                        status=att.status,
                        punch=att.punch,
                        source="sdk_pull",
                    )
                    db.add(log)
                    result["attendance_synced"] += 1

            db.commit()

            device.last_seen = datetime.utcnow()
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
