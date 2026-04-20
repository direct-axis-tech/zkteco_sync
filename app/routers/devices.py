from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import Device, DeviceCommand
from app.schemas import CommandCreate, DeviceCreate, DeviceOut
from app.services.poller import pull_device

router = APIRouter(prefix="/devices", tags=["devices"])


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
    device = db.query(Device).filter_by(serial_number=sn).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.delete("/{sn}", status_code=204)
def delete_device(sn: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter_by(serial_number=sn).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()


@router.post("/{sn}/pull")
def trigger_pull(sn: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not db.query(Device).filter_by(serial_number=sn).first():
        raise HTTPException(status_code=404, detail="Device not found")
    background_tasks.add_task(pull_device, sn)
    return {"message": "Pull started", "device": sn}


@router.post("/{sn}/commands", status_code=201)
def queue_command(sn: str, payload: CommandCreate, db: Session = Depends(get_db)):
    if not db.query(Device).filter_by(serial_number=sn).first():
        raise HTTPException(status_code=404, detail="Device not found")
    cmd = DeviceCommand(device_sn=sn, command=payload.command)
    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    return {"id": cmd.id, "device_sn": sn, "command": cmd.command, "status": cmd.status}
