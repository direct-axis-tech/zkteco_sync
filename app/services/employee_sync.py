"""The one place an employee row is written. Every source comes through here.

Three sources now write people, and they do not mean the same thing by an
empty field. Two of them are devices reporting what they hold — "this person
exists on this terminal":

* the **SDK pull** (``app/services/poller.pull_employees``), which reaches out
  over TCP 4370 and reads ``get_users()``;
* the **Security PUSH bulk upload** (``tabledata&tablename=user``, handled in
  ``app/routers/adms.py``), which arrives unsolicited over HTTP because a
  NATted device can only ever push.

The third is an **operator typing into the UI** (E3), who is the authority on
the row rather than a witness to it, and for whom clearing a field is a real
instruction. That difference is handled by having two entry points into this
one module — see "The other kind of source" further down — not by a second
writer somewhere else.

A device behind NAT is reachable by exactly one of those. A device on the LAN
can be reachable by both, and then the two must agree. If each transport had
its own writer with its own idea of what an empty field means, an
operator-entered name would survive one path and be erased by the other, and
the row would flip-flop on every poll. Hence: one writer, one rule, called by
both.

**The rule: a source may fill a field in, but never empty one out.** Terminals
routinely report a user with no name and no card — every one of the three
records in the BioFace A1 capture does — and that absence is the device having
nothing to say, not an instruction to erase what an operator typed.

The two conventions that follow from it:

* ``None`` and ``""`` both mean "this source has nothing to say about this
  field". They are indistinguishable on the wire (``name=`` is what an unnamed
  user looks like) so they are treated the same here.
* ``privilege`` is the exception: ``0`` is a real value (an ordinary user, as
  opposed to ``14`` for an admin), so it is applied whenever the field was
  present at all. Only an absent or unparseable ``privilege`` is ignored.

Nothing here commits. Both callers own their own transaction — the poller
commits once per pull, the ADMS handler once per upload — and a helper that
committed mid-loop would break the batch semantics of either. Each helper does
``flush()`` so that a second record for the same person inside one batch sees
the first one instead of racing it into a unique-constraint violation.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import (
    BiometricTemplate, DeviceEmployee, Employee, EmployeePhoto,
    FingerprintTemplate,
)

log = logging.getLogger(__name__)

# Column widths, from app/models.py. Values are clipped rather than rejected:
# a name one character over the limit is not a reason to lose the record.
_USER_ID_LIMIT = 24
_NAME_LIMIT = 100
_CARD_LIMIT = 20

# What a device sends for "this user has no card". The SDK path reports it as
# the integer 0 and Employee.card defaults to the string "0", so neither of
# these is a card number and neither may overwrite one.
_NO_CARD = {"", "0"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _blank(value) -> bool:
    """Did the source say nothing about this field?"""
    return value is None or str(value).strip() == ""


def _int_or_none(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def upsert_employee(db: Session, user_id, *, name=None, privilege=None, card=None):
    """Create or update the ``employees`` row for one device user ID.

    Keyed on ``user_id`` — the device's ``pin`` — because that is already the
    key ``AttendanceLog.user_id`` joins on and the key the SDK path uses. The
    device-local ``uid`` is deliberately *not* the key: it is a per-device
    sequence number that differs between two terminals holding the same person.

    Returns the ``Employee``, or ``None`` if the record carried no usable ID.
    """
    user_id = str(user_id).strip()[:_USER_ID_LIMIT] if user_id is not None else ""
    if not user_id:
        return None

    emp = db.query(Employee).filter_by(user_id=user_id).first()
    created = emp is None
    if created:
        # The placeholder for "the device sent no name" is the empty string,
        # not an invented one. Every list in the UI already falls back to the
        # user ID when the name is empty, so an unnamed enrolment shows up as
        # its PIN — which is true — rather than as a plausible-looking name
        # that is not.
        emp = Employee(user_id=user_id, name="", privilege=0, card="0")
        db.add(emp)

    changed = created

    if not _blank(name):
        value = str(name).strip()[:_NAME_LIMIT]
        if emp.name != value:
            emp.name = value
            changed = True

    # 0 is a legitimate privilege, so presence is what counts, not truthiness.
    priv = _int_or_none(privilege)
    if priv is not None and emp.privilege != priv:
        emp.privilege = priv
        changed = True

    if not _blank(card) and str(card).strip() not in _NO_CARD:
        value = str(card).strip()[:_CARD_LIMIT]
        if emp.card != value:
            emp.card = value
            changed = True

    if changed:
        emp.updated_at = _now()

    # Makes the row visible to the next query in this same transaction, so a
    # batch containing the same PIN twice merges rather than duplicating.
    db.flush()
    return emp


def link_device_employee(db: Session, device_sn: str, user_id: str, uid=None):
    """Record that ``user_id`` is enrolled on ``device_sn``.

    ``uid`` is the terminal's own slot number for that person. It is stored
    because the SDK write path addresses users by it, and it is per-device —
    hence the ``(device_sn, user_id)`` unique key rather than a global one.
    ``synced_at`` is refreshed on every sighting even when nothing changed:
    its meaning is "last confirmed present on this device".
    """
    device_sn = str(device_sn or "").strip()
    user_id = str(user_id or "").strip()[:_USER_ID_LIMIT]
    if not device_sn or not user_id:
        return None

    link = db.query(DeviceEmployee).filter_by(
        device_sn=device_sn, user_id=user_id
    ).first()
    if link is None:
        # uid is NOT NULL with no default. A device that omits it gets 0,
        # which is what an un-slotted record means; it is never guessed from
        # the PIN, because a wrong slot number would make a later SDK write
        # address the wrong user.
        link = DeviceEmployee(
            device_sn=device_sn, user_id=user_id, uid=_int_or_none(uid) or 0
        )
        db.add(link)
    else:
        new_uid = _int_or_none(uid)
        if new_uid is not None:
            link.uid = new_uid
        link.synced_at = _now()

    db.flush()
    return link


def unlink_device_employee(db: Session, device_sn: str, user_id: str) -> bool:
    """Record that ``user_id`` is no longer on ``device_sn``. True if a row went.

    The mirror of :func:`link_device_employee`, and the only place a
    `device_employees` row is destroyed, for the same reason there is only one
    place they are created: this row is the app's whole answer to "is this
    person on that door", and two different pieces of code with two different
    ideas of when it stops being true is exactly how a revocation ends up
    claimed but not performed.

    Deliberately says nothing about *why*. The SDK transport calls this having
    just watched the device delete the user; the ADMS transport calls it only
    when the terminal acknowledges the delete command. Both are the same fact
    by the time they get here — the person is off that device — and neither is
    allowed to assert it any earlier.

    Does not commit; the caller owns the transaction.
    """
    device_sn = str(device_sn or "").strip()
    user_id = str(user_id or "").strip()[:_USER_ID_LIMIT]
    if not device_sn or not user_id:
        return False

    link = db.query(DeviceEmployee).filter_by(
        device_sn=device_sn, user_id=user_id
    ).first()
    if link is None:
        return False

    db.delete(link)
    db.flush()
    log.info("%s is no longer enrolled on %s", user_id, device_sn)
    return True


# ---------------------------------------------------------------------------
# The other kind of source: an operator, typing
# ---------------------------------------------------------------------------
#
# Everything above is a *device* reporting what it holds, where silence means
# "nothing to say" and may never erase what somebody typed. An operator is the
# opposite kind of source: they are the authority on this row, and clearing a
# field is a thing they are allowed to mean.
#
# So the two are told apart at the door, not inside the rule. A device calls
# record_device_user() and gets fill-in-never-empty-out. An operator calls
# create_employee()/apply_operator_edit() and gets exactly what they asked
# for, including empty. Both still write through this one module, so there is
# still exactly one thing that writes `employees` — which is the property E1
# established by *removing* a competing writer, and which is worth more than
# the convenience of a second one.
#
# The distinction is carried by the caller supplying a field at all: the API
# layer passes only the keys the operator actually sent (Pydantic's
# exclude_unset), so "" means clear this and absent means leave it alone.

# Sentinel for "this key was not supplied". Distinct from None, because None
# is a perfectly good way for an operator to mean "empty".
_UNSET = object()


def create_employee(db: Session, user_id, *, name="", privilege=0, card=""):
    """Create one employee row from operator input.

    Raises ValueError if the user_id is missing or already taken — a PIN is
    the device's primary key for a person, so silently merging into somebody
    else's row would be the worst possible outcome of a typo.
    """
    user_id = str(user_id or "").strip()[:_USER_ID_LIMIT]
    if not user_id:
        raise ValueError("A user ID (PIN) is required")

    if db.query(Employee).filter_by(user_id=user_id).first():
        raise ValueError(f"User ID {user_id} already exists")

    emp = Employee(
        user_id=user_id,
        name=str(name or "").strip()[:_NAME_LIMIT],
        privilege=_int_or_none(privilege) or 0,
        # "0" not "": the column's own convention for "no card", shared with
        # the device and with every fallback in the UI.
        card=(str(card or "").strip()[:_CARD_LIMIT] or "0"),
    )
    db.add(emp)
    db.flush()
    log.info("employee %s created by an operator", user_id)
    return emp


def apply_operator_edit(db: Session, emp: Employee, *,
                        name=_UNSET, privilege=_UNSET, card=_UNSET):
    """Apply a deliberate edit. Unlike a device, an operator may empty a field.

    Only the fields passed are touched. Returns the set of field names that
    actually changed, so the caller can audit the edit rather than the
    request.
    """
    changed = set()

    if name is not _UNSET:
        value = str(name or "").strip()[:_NAME_LIMIT]
        if emp.name != value:
            emp.name = value
            changed.add("name")

    if privilege is not _UNSET:
        value = _int_or_none(privilege)
        if value is not None and emp.privilege != value:
            emp.privilege = value
            changed.add("privilege")

    if card is not _UNSET:
        # An operator clearing the card field means "this person has no card",
        # which the column spells "0" — the same value the device sends for it.
        value = str(card or "").strip()[:_CARD_LIMIT] or "0"
        if emp.card != value:
            emp.card = value
            changed.add("card")

    if changed:
        emp.updated_at = _now()
        log.info("employee %s edited by an operator: %s",
                 emp.user_id, ", ".join(sorted(changed)))

    db.flush()
    return changed


def delete_employee(db: Session, user_id: str):
    """Remove one person from the system, per an operator's deliberate ask.

    Returns a dict of cascade counts keyed by table name, or ``None`` if no
    such employee exists.

    **What goes, and why it is safe to cascade it**: ``device_employees``,
    ``biometric_templates``, ``employee_photos``, ``fingerprint_templates``.
    Every one of these keys on ``user_id`` and describes an enrolment or a
    credential — it exists only because this person was on a device, and it
    is meaningless once the person is gone.

    **What stays, and why it must**: ``attendance_logs``. A punch is
    historical fact, not a live fact about the person — it already happened,
    it has already been pushed to the operator's HRM, and
    ``hrm_integration.last_synced_id`` points into that same table. Deleting
    attendance rows here would silently rewrite payroll history and
    desynchronise the sync pointer from what the HRM actually holds. Nothing
    in this function touches ``attendance_logs``, and nothing else in this
    module may either — see the module docstring's "one writer" rule, which
    this is the deletion half of.

    **This function does not check whether the person is still enrolled
    anywhere.** That is a *refusal*, not a cascade decision, and it belongs
    to the caller (the router), which can name the doors in its error
    message — something this module has no business knowing how to phrase.
    Calling this while a `device_employees` link exists would delete the
    server's only record of a credential a door still holds; it must not
    happen, and the router's 409 is what prevents it.

    Does not commit — the caller owns the transaction, like everything else
    here.
    """
    user_id = str(user_id or "").strip()[:_USER_ID_LIMIT]
    emp = db.query(Employee).filter_by(user_id=user_id).first() if user_id else None
    if emp is None:
        return None

    # Order does not matter — none of these reference each other — but this
    # is also every table this function is allowed to touch, so it doubles
    # as documentation of the cascade if a reader greps only this function.
    counts = {
        "device_employees": (
            db.query(DeviceEmployee).filter_by(user_id=user_id).delete()
        ),
        "biometric_templates": (
            db.query(BiometricTemplate).filter_by(user_id=user_id).delete()
        ),
        "employee_photos": (
            db.query(EmployeePhoto).filter_by(user_id=user_id).delete()
        ),
        "fingerprint_templates": (
            db.query(FingerprintTemplate).filter_by(user_id=user_id).delete()
        ),
    }
    db.delete(emp)
    db.flush()
    log.warning(
        "employee %s deleted by an operator — cascaded %s; attendance_logs "
        "left untouched",
        user_id, counts,
    )
    return counts


def record_device_user(
    db: Session,
    device_sn: str,
    user_id,
    *,
    uid=None,
    name=None,
    privilege=None,
    card=None,
):
    """One person, as reported by one device: the employee row plus the link.

    This is the entry point both transports call. Keeping it a single function
    is what guarantees the SDK pull and the ADMS push cannot drift apart in
    what they write.
    """
    emp = upsert_employee(db, user_id, name=name, privilege=privilege, card=card)
    if emp is None:
        return None, None
    return emp, link_device_employee(db, device_sn, emp.user_id, uid)
