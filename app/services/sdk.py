from contextlib import contextmanager

from zk import ZK
from zk.exception import ZKErrorConnection, ZKNetworkError

from app.database import SessionLocal
from app.models import Device, DeviceEmployee


@contextmanager
def device_connection(device: Device):
    """
    Context manager that opens a pyzk connection and guarantees disconnect on exit.
    Usage:
        with device_connection(device) as conn:
            conn.get_users()
    """
    zk_instance = ZK(device.ip_address, port=device.port, timeout=30, verbose=False)
    conn = zk_instance.connect()
    try:
        yield conn
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def enroll_user_task(serial_number: str, user_id: str, finger_id: int) -> None:
    """
    Background task: tells the device to start a live fingerprint enrollment session.
    Blocks up to ~3 minutes waiting for the person to scan their finger 3 times.
    Creates its own DB session because it runs after the HTTP request has ended.
    """
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            return
        de = db.query(DeviceEmployee).filter_by(device_sn=serial_number, user_id=user_id).first()
        if not de:
            return

        zk_instance = ZK(device.ip_address, port=device.port, timeout=60, verbose=False)
        conn = None
        try:
            conn = zk_instance.connect()
            conn.enroll_user(uid=de.uid, temp_id=finger_id, user_id=user_id)
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
    finally:
        db.close()
