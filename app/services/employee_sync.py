"""The one place an employee row is written from a device.

Two transports deliver the same fact — "this person exists on this terminal":

* the **SDK pull** (``app/services/poller.pull_employees``), which reaches out
  over TCP 4370 and reads ``get_users()``;
* the **Security PUSH bulk upload** (``tabledata&tablename=user``, handled in
  ``app/routers/adms.py``), which arrives unsolicited over HTTP because a
  NATted device can only ever push.

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

from app.models import DeviceEmployee, Employee

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
