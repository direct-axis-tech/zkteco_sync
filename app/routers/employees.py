import base64
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import List

from app import audit
from app.database import get_db
from app.deps import require_admin, require_auth
from app.models import (
    BiometricTemplate, Device, DeviceEmployee, Employee, EmployeePhoto,
    FingerprintTemplate, User,
)
from app.net import client_ip
from app.schemas import (
    BiometricTemplateOut, DeviceEmployeeOut, EmployeeCreate, EmployeeOut,
    EmployeeUpdate, FingerprintTemplateOut,
)
from app.services import employee_sync

log = logging.getLogger(__name__)

router = APIRouter(prefix="/employees", tags=["employees"], dependencies=[Depends(require_auth)])

# Preference order when both tables have a photo for the same person: `biophoto`
# first. E5's own capture shows the two are the same image on real hardware, so
# this only matters on a firmware that genuinely diverges from that, and
# `biophoto` is the table §3.7 documents as the comparison photo — the one the
# terminal itself treats as canonical for matching.
_PHOTO_SOURCE_PREFERENCE = ("biophoto", "userpic")


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


@router.delete("/{user_id}")
def delete_employee(
    user_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Remove a person from the system entirely. Admin-only, audited.

    Before E14 the only way to do this was SQL by hand — every operator who
    wanted a test record or a departed employee gone had to be handed a
    one-off script. This is that workaround, made real and safe.

    **Refused while any device still holds this person** (a `device_employees`
    link exists for them, on any device). That link means a real door still
    recognises this pin; deleting only the server row would leave that
    credential live with no record of it anywhere — an invisible way in,
    which is worse than the gap this endpoint closes. The error names every
    door that still needs revoking first. `device_employees` is written only
    on a confirmed device acknowledgement (E3/E8), so this check is never
    fooled by a revocation that is merely queued — a still-outstanding
    revocation leaves the link in place and this refuses exactly the same as
    an untouched enrolment.

    **What is cascaded, and what survives**: see
    :func:`app.services.employee_sync.delete_employee`. In short — every
    enrolment and credential record goes (`device_employees`,
    `biometric_templates`, `employee_photos`, `fingerprint_templates`);
    `attendance_logs` never does, because a punch is historical fact already
    pushed to the operator's HRM.

    **This is not necessarily final.** If a device that was never told about
    this deletion still holds the pin locally (should not happen if the
    refusal above did its job, but a device can also enrol a pin the server
    has never heard of), a later sync will re-create the employee row from
    what the terminal reports — that is E1/E9 doing exactly what they are
    supposed to do, ingesting what the device actually has. The UI says so
    up front so it does not read as a bug later.
    """
    emp = db.query(Employee).filter_by(user_id=user_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    links = db.query(DeviceEmployee).filter_by(user_id=user_id).all()
    if links:
        serials = sorted({link.device_sn for link in links})
        devices = {
            d.serial_number: d.name
            for d in db.query(Device).filter(Device.serial_number.in_(serials)).all()
        }
        doors = [devices.get(sn) or sn for sn in serials]
        raise HTTPException(
            status_code=409,
            detail=(
                f"{user_id} is still enrolled on {len(doors)} door"
                f"{'s' if len(doors) != 1 else ''}: {', '.join(doors)}. "
                "Revoke them from each door first, and wait for the device to "
                "confirm the removal — deleting the record here while a door "
                "still holds the credential would leave an invisible way in "
                "with no record of it anywhere."
            ),
        )

    cascaded = employee_sync.delete_employee(db, user_id)
    db.commit()

    audit.record(
        db, admin.username, "employee_delete", target=user_id,
        ip=client_ip(request),
        detail=(
            f"cascaded device_employees={cascaded['device_employees']} "
            f"biometric_templates={cascaded['biometric_templates']} "
            f"employee_photos={cascaded['employee_photos']} "
            f"fingerprint_templates={cascaded['fingerprint_templates']}; "
            "attendance_logs kept"
        ),
    )
    return {
        "user_id": user_id,
        "status": "deleted",
        "cascaded": cascaded,
        "message": (
            f"{user_id} removed from the system. Attendance history is kept "
            "— those rows are historical fact and already reached the HRM. "
            "If a device still holds this pin, a future sync will re-create "
            "the employee record from what the terminal reports; that is "
            "correct behaviour, not a bug."
        ),
    }


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


@router.get("/{user_id}/biometrics", response_model=List[BiometricTemplateOut])
def get_employee_biometrics(user_id: str, db: Session = Depends(get_db)):
    """What this person has enrolled at a terminal, and where.

    Separate from `/templates`, which is the SDK-era fingerprint table, because
    the two have different provenance and different field sets (see
    BiometricTemplate). This is the list an operator reads before deciding to
    copy somebody's enrolment to a second door.

    The template bytes themselves are not returned — see BiometricTemplateOut.
    `source_device_sn` is the field that matters here: it is the one terminal
    each of these will never be pushed back to.
    """
    if not db.query(Employee).filter_by(user_id=user_id).first():
        raise HTTPException(status_code=404, detail="Employee not found")
    rows = (
        db.query(BiometricTemplate)
        .filter_by(user_id=user_id)
        .order_by(BiometricTemplate.type, BiometricTemplate.no, BiometricTemplate.id)
        .all()
    )
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "type": r.type,
            "no": r.no,
            "record_index": r.record_index,
            "valid": r.valid,
            "duress": r.duress,
            "majorver": r.majorver,
            "minorver": r.minorver,
            "format": r.format,
            "tmp_bytes": len(r.tmp or ""),
            "source_device_sn": r.source_device_sn,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }
        for r in rows
    ]


@router.get("/{user_id}/photo")
def get_employee_photo(user_id: str, db: Session = Depends(get_db)):
    """The person's captured face photo, decoded and served as an image.

    Deliberately its own endpoint rather than a field on EmployeeOut. A photo
    is ~100 KB of base64 on the wire; inlining that into every row of the
    employee list would turn a 45-person listing into several megabytes on
    every load. This way the browser's own <img> tag fetches and caches it
    exactly once, and the list response stays small.

    biophoto and userpic hold the same image on every capture seen so far
    (E5) — biophoto is preferred, userpic served as a fallback for a device
    that only ever pushes one of the two. See EmployeePhoto and
    _PHOTO_SOURCE_PREFERENCE.
    """
    if not db.query(Employee).filter_by(user_id=user_id).first():
        raise HTTPException(status_code=404, detail="Employee not found")

    row = None
    for source in _PHOTO_SOURCE_PREFERENCE:
        row = db.query(EmployeePhoto).filter_by(user_id=user_id, source=source).first()
        if row is not None:
            break

    if row is None:
        raise HTTPException(status_code=404, detail="No photo captured for this employee")

    try:
        image_bytes = base64.b64decode(row.content, validate=False)
    except Exception:
        log.warning(
            "employee photo for %s (source=%s): stored content is not decodable base64",
            user_id, row.source,
        )
        raise HTTPException(status_code=404, detail="Stored photo is not decodable")

    return Response(
        content=image_bytes,
        # Every capture seen so far is a `.jpg` upload (§3.7's own examples
        # too); there is no stored mime type to read back instead.
        media_type="image/jpeg",
        headers={"Cache-Control": "private, max-age=300"},
    )
