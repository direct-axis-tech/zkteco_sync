from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List

from app import audit
from app.database import get_db
from app.deps import require_admin, require_auth
from app.models import DeviceEmployee, Employee, FingerprintTemplate, User
from app.net import client_ip
from app.schemas import (
    DeviceEmployeeOut, EmployeeCreate, EmployeeOut, EmployeeUpdate,
    FingerprintTemplateOut,
)
from app.services import employee_sync

router = APIRouter(prefix="/employees", tags=["employees"], dependencies=[Depends(require_auth)])


@router.get("", response_model=List[EmployeeOut])
def list_employees(db: Session = Depends(get_db)):
    return db.query(Employee).order_by(Employee.name).all()


@router.post("", response_model=EmployeeOut, status_code=201)
def create_employee(
    payload: EmployeeCreate,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Add a person centrally, before any terminal has heard of them.

    Creating them here does not put them on a device — that is an explicit,
    per-device decision (POST /devices/{sn}/users/{user_id}/push), because
    which doors somebody may open is not something to infer.

    Admin-only, and audited: this is the row a door permission will later be
    attached to.

    The write goes through employee_sync, which is the only module that writes
    `employees`. It has one entry point for devices (fill in, never empty out)
    and one for operators (say what you mean); this is the second.
    """
    try:
        emp = employee_sync.create_employee(
            db,
            payload.user_id,
            name=payload.name,
            privilege=payload.privilege,
            card=payload.card,
        )
    except ValueError as exc:
        # 409, not 400: the request is well-formed, the PIN is simply taken.
        raise HTTPException(status_code=409, detail=str(exc))

    db.commit()
    db.refresh(emp)
    audit.record(db, admin.username, "employee_create", target=emp.user_id,
                 ip=client_ip(request))
    return emp


@router.get("/{user_id}", response_model=EmployeeOut)
def get_employee(user_id: str, db: Session = Depends(get_db)):
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp


@router.patch("/{user_id}", response_model=EmployeeOut)
def update_employee(
    user_id: str,
    payload: EmployeeUpdate,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Edit a person. An operator may clear a field; a device may not.

    Only the fields present in the request body are touched — `exclude_unset`
    is what separates "the operator deleted the name" from "the operator did
    not mention the name", and the whole employee-writer rule rests on it.

    This does not re-push anything. A device already holding this person keeps
    the old record until they are pushed again, and saying so is more honest
    than a silent fan-out to every terminal.
    """
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    changed = employee_sync.apply_operator_edit(
        db, emp, **payload.model_dump(exclude_unset=True)
    )
    db.commit()
    db.refresh(emp)

    if changed:
        audit.record(db, admin.username, "employee_update", target=user_id,
                     ip=client_ip(request), detail=", ".join(sorted(changed)))
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
