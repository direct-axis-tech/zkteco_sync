from datetime import datetime
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from zk.exception import ZKErrorConnection, ZKNetworkError
from zk.finger import Finger

from app.database import get_db
from app.models import Device, DeviceCommand, DeviceEmployee, Employee, FingerprintTemplate
from app.schemas import (
    CommandCreate, DeviceCreate, DeviceInfoOut, DeviceOut,
    EnrollRequest, FingerprintTemplateOut, LcdRequest,
    SetTimeRequest, UnlockRequest,
)
from app.services.poller import pull_device
from app.services.sdk import device_connection, enroll_user_task

router = APIRouter(prefix="/devices", tags=["devices"])


def _get_device_or_404(sn: str, db: Session) -> Device:
    device = db.query(Device).filter_by(serial_number=sn).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=List[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()


@router.post("", response_model=DeviceOut, status_code=201)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)):
    if db.query(Device).filter_by(serial_number=payload.serial_number).first():
        raise HTTPException(status_code=409, detail="Device already registered")
    device = Device(**payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{sn}", response_model=DeviceOut)
def get_device(sn: str, db: Session = Depends(get_db)):
    return _get_device_or_404(sn, db)


@router.delete("/{sn}", status_code=204)
def delete_device(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    db.delete(device)
    db.commit()


# ---------------------------------------------------------------------------
# SDK pull (background)
# ---------------------------------------------------------------------------

@router.post("/{sn}/pull")
def trigger_pull(sn: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    _get_device_or_404(sn, db)
    background_tasks.add_task(pull_device, sn)
    return {"message": "Pull started", "device": sn}


# ---------------------------------------------------------------------------
# ADMS command queue
# ---------------------------------------------------------------------------

@router.post("/{sn}/commands", status_code=201)
def queue_command(sn: str, payload: CommandCreate, db: Session = Depends(get_db)):
    _get_device_or_404(sn, db)
    cmd = DeviceCommand(device_sn=sn, command=payload.command)
    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    return {"id": cmd.id, "device_sn": sn, "command": cmd.command, "status": cmd.status}


# ---------------------------------------------------------------------------
# Device info
# ---------------------------------------------------------------------------

@router.get("/{sn}/info", response_model=DeviceInfoOut)
def get_device_info(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.read_sizes()
            return {
                "serial_number": conn.get_serialnumber(),
                "firmware_version": conn.get_firmware_version(),
                "platform": conn.get_platform(),
                "device_name": conn.get_device_name(),
                "mac": conn.get_mac(),
                "face_version": conn.get_face_version(),
                "fp_version": conn.get_fp_version(),
                "pin_width": conn.get_pin_width(),
                "network": conn.get_network_params(),
                "sizes": {
                    "users": getattr(conn, "users", 0),
                    "fingers": getattr(conn, "fingers", 0),
                    "records": getattr(conn, "records", 0),
                    "cards": getattr(conn, "cards", 0),
                    "faces": getattr(conn, "faces", 0),
                    "users_cap": getattr(conn, "users_cap", 0),
                    "fingers_cap": getattr(conn, "fingers_cap", 0),
                    "rec_cap": getattr(conn, "rec_cap", 0),
                    "faces_cap": getattr(conn, "faces_cap", 0),
                },
            }
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Device clock
# ---------------------------------------------------------------------------

@router.get("/{sn}/time")
def get_device_time(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            t = conn.get_time()
            return {"device_sn": sn, "time": t.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/time")
def set_device_time(sn: str, payload: SetTimeRequest, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    if payload.sync:
        target = datetime.utcnow()
    elif payload.dt:
        try:
            target = datetime.fromisoformat(payload.dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid datetime format — use ISO 8601")
    else:
        raise HTTPException(status_code=400, detail="Provide sync=true or a dt value")
    try:
        with device_connection(device) as conn:
            conn.set_time(target)
            return {"device_sn": sn, "time_set": target.isoformat()}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Door control
# ---------------------------------------------------------------------------

@router.post("/{sn}/unlock")
def unlock_door(sn: str, payload: UnlockRequest, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.unlock(time=payload.seconds)
            return {"device_sn": sn, "unlocked_for_seconds": payload.seconds}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.get("/{sn}/lock")
def get_lock_state(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            locked = conn.get_lock_state()
            return {"device_sn": sn, "locked": locked}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Device control
# ---------------------------------------------------------------------------

@router.post("/{sn}/restart")
def restart_device(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.restart()
            return {"device_sn": sn, "message": "Device restarting"}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/lcd")
def write_lcd(sn: str, payload: LcdRequest, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.write_lcd(payload.line, payload.text)
            return {"device_sn": sn, "line": payload.line, "text": payload.text}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/lcd", status_code=204)
def clear_lcd(sn: str, db: Session = Depends(get_db)):
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.clear_lcd()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# User sync: push/remove individual users on a device
# ---------------------------------------------------------------------------

@router.post("/{sn}/users/{user_id}/push")
def push_user_to_device(sn: str, user_id: str, db: Session = Depends(get_db)):
    """
    Write an employee record from DB onto the device.
    If the user already exists on the device, updates their record.
    If new, the device auto-assigns a uid which we store in device_employees.
    """
    device = _get_device_or_404(sn, db)
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    try:
        with device_connection(device) as conn:
            users_on_device = conn.get_users()  # also initialises conn.next_uid
            existing = next((u for u in users_on_device if u.user_id == str(user_id)), None)

            uid = existing.uid if existing else None
            pre_uid = conn.next_uid  # pyzk will assign this if uid is None

            conn.set_user(
                uid=uid,
                name=emp.name,
                privilege=emp.privilege,
                user_id=emp.user_id,
                card=int(emp.card) if emp.card and emp.card != "0" else 0,
            )

            actual_uid = uid if uid is not None else pre_uid

            de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
            if de:
                de.uid = actual_uid
                de.synced_at = datetime.utcnow()
            else:
                db.add(DeviceEmployee(device_sn=sn, user_id=user_id, uid=actual_uid))
            db.commit()

        return {"device_sn": sn, "user_id": user_id, "uid": actual_uid, "message": "User pushed to device"}
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/users/{user_id}", status_code=204)
def remove_user_from_device(sn: str, user_id: str, db: Session = Depends(get_db)):
    """Remove a user from the device. Does not delete the employee from DB."""
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device")
    try:
        with device_connection(device) as conn:
            conn.delete_user(uid=de.uid, user_id=user_id)
        db.delete(de)
        db.commit()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Attendance: clear device memory
# ---------------------------------------------------------------------------

@router.delete("/{sn}/attendance", status_code=204)
def clear_device_attendance(sn: str, db: Session = Depends(get_db)):
    """Wipe attendance logs from device memory. Does not touch our DB."""
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            conn.clear_attendance()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Fingerprint templates
# ---------------------------------------------------------------------------

@router.post("/{sn}/templates/pull", response_model=List[FingerprintTemplateOut])
def pull_templates(sn: str, db: Session = Depends(get_db)):
    """
    Pull all fingerprint templates from device and save to DB.
    Overwrites existing DB record for the same (user_id, finger_id) pair.
    """
    device = _get_device_or_404(sn, db)
    try:
        with device_connection(device) as conn:
            users = conn.get_users()
            uid_map = {u.uid: u.user_id for u in users}
            fingers = conn.get_templates()

            result = []
            for finger in fingers:
                user_id = uid_map.get(finger.uid)
                if not user_id:
                    continue
                packed = finger.json_pack()
                ft = db.query(FingerprintTemplate).filter_by(
                    user_id=user_id, finger_id=finger.fid
                ).first()
                if ft:
                    ft.valid = finger.valid
                    ft.template = packed["template"]
                    ft.source_device_sn = sn
                else:
                    ft = FingerprintTemplate(
                        user_id=user_id,
                        finger_id=finger.fid,
                        valid=finger.valid,
                        template=packed["template"],
                        source_device_sn=sn,
                    )
                    db.add(ft)
                result.append(ft)

            db.commit()
            for r in result:
                db.refresh(r)
            return result
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.post("/{sn}/users/{user_id}/templates/push")
def push_templates_to_device(sn: str, user_id: str, db: Session = Depends(get_db)):
    """
    Copy fingerprint templates stored in DB onto the device.
    Typical workflow: pull from Device A, then push to Devices B, C, D.
    The user must already exist on the target device (call /push first).
    """
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device — call /push first")

    templates = db.query(FingerprintTemplate).filter_by(user_id=user_id).all()
    if not templates:
        raise HTTPException(status_code=404, detail="No fingerprint templates in DB for this employee")

    try:
        with device_connection(device) as conn:
            users = conn.get_users()
            device_user = next((u for u in users if u.user_id == str(user_id)), None)
            if not device_user:
                raise HTTPException(status_code=422, detail="User not found on device — call /push first")

            fingers = [
                Finger.json_unpack({
                    "uid": device_user.uid,  # uid on THIS device, not the source device
                    "fid": ft.finger_id,
                    "valid": ft.valid,
                    "template": ft.template,
                })
                for ft in templates
            ]
            conn.save_user_template(device_user, fingers)

        return {
            "device_sn": sn,
            "user_id": user_id,
            "templates_pushed": len(fingers),
        }
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


@router.delete("/{sn}/users/{user_id}/templates/{finger_id}", status_code=204)
def delete_user_template(sn: str, user_id: str, finger_id: int, db: Session = Depends(get_db)):
    """Delete a specific finger template from device and from DB."""
    device = _get_device_or_404(sn, db)
    de = db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first()
    if not de:
        raise HTTPException(status_code=404, detail="User not enrolled on this device")
    try:
        with device_connection(device) as conn:
            conn.delete_user_template(uid=de.uid, temp_id=finger_id, user_id=user_id)
        ft = db.query(FingerprintTemplate).filter_by(user_id=user_id, finger_id=finger_id).first()
        if ft:
            db.delete(ft)
            db.commit()
    except (ZKErrorConnection, ZKNetworkError):
        raise HTTPException(status_code=503, detail="Could not connect to device")


# ---------------------------------------------------------------------------
# Live enrollment
# ---------------------------------------------------------------------------

@router.post("/{sn}/users/{user_id}/enroll", status_code=202)
def enroll_user(
    sn: str,
    user_id: str,
    payload: EnrollRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Trigger a live fingerprint enrollment on the device.
    Returns immediately (202). The device will prompt the person to scan their
    finger 3 times. Check DB templates after ~30s to confirm success.
    The user must already exist on the device (call /push first).
    """
    _get_device_or_404(sn, db)
    if not db.query(DeviceEmployee).filter_by(device_sn=sn, user_id=user_id).first():
        raise HTTPException(status_code=404, detail="User not enrolled on this device — call /push first")
    background_tasks.add_task(enroll_user_task, sn, user_id, payload.finger_id)
    return {
        "message": "Enrollment started — person must scan their finger on the device",
        "device_sn": sn,
        "user_id": user_id,
        "finger_id": payload.finger_id,
    }
