from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import DeviceEmployee, Employee, FingerprintTemplate
from app.schemas import DeviceEmployeeOut, EmployeeOut, FingerprintTemplateOut

router = APIRouter(prefix="/employees", tags=["employees"])


@router.get("", response_model=List[EmployeeOut])
def list_employees(db: Session = Depends(get_db)):
    return db.query(Employee).order_by(Employee.name).all()


@router.get("/{user_id}", response_model=EmployeeOut)
def get_employee(user_id: str, db: Session = Depends(get_db)):
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp


@router.get("/{user_id}/devices", response_model=List[DeviceEmployeeOut])
def get_employee_devices(user_id: str, db: Session = Depends(get_db)):
    if not db.query(Employee).filter_by(user_id=user_id).first():
        raise HTTPException(status_code=404, detail="Employee not found")
    return db.query(DeviceEmployee).filter_by(user_id=user_id).all()


@router.get("/{user_id}/templates", response_model=List[FingerprintTemplateOut])
def get_employee_templates(user_id: str, db: Session = Depends(get_db)):
    if not db.query(Employee).filter_by(user_id=user_id).first():
        raise HTTPException(status_code=404, detail="Employee not found")
    return db.query(FingerprintTemplate).filter_by(user_id=user_id).all()
