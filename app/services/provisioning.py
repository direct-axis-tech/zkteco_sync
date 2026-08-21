"""Putting a person onto an access-control terminal, over the command queue.

The workflow this serves is the operator's, taken from BioTime: create the
person centrally, push them to a door, then walk up to that door and enrol a
face or a finger *on the terminal*. The device uploads the resulting template
back by itself (that is E1/E2).

Two things are pushed down from here, and they are deliberately separate
calls:

* :func:`provision` sends the *identity* — the person record and the door
  permission. It sends no biometric at all; the person enrols one at the
  terminal afterwards.
* :func:`push_templates` sends a *biometric already captured somewhere else*,
  so that somebody enrolled at one door works at every door without walking
  back to each one. That is the highest-consequence thing this application
  does: the bytes it queues become a credential on physical door hardware, so
  they are replayed verbatim from storage and never reconstructed, guessed or
  normalised (see :func:`biodata_command`).

Two commands, not one
---------------------
This is the whole reason this module exists as more than a format string.
On an `acc` terminal the person record and the door permission live in two
different tables:

    DATA UPDATE user Pin=…<HT>CardNo=…<HT>…<HT>Privilege=…
    DATA UPDATE userauthorize Pin=…<HT>AuthorizeTimezoneId=…

Send only the first and the terminal knows the person, lets them enrol, shows
their name on a successful verification — and refuses to open the door. That
half-success is hard to diagnose from the server side, because everything the
server can see says the push worked. §3.8 records that the authorization "is
delivered together with the user information", and that is what
:func:`provision` does: both commands, queued together, in that order.

There is no equivalent step on an attendance terminal, which is why it is easy
to miss and why it is spelled out at this length.

Queued is not delivered
-----------------------
Nothing in this module talks to a device. A ZKTeco terminal on ADMS is never
dialled; it collects work on its next `GET /iclock/getrequest`, roughly every
ten seconds, and reports the outcome afterwards. So :func:`provision` returns
the outbox rows it created and callers must describe that as *queued*. Delivery
and retry belong to app/services/commands.py, which is the only thing that
dispatches, and is not reimplemented here.

Who writes device_employees
---------------------------
Not this module, and not at push time. `device_employees` means "this person
is on this terminal", and until the device has acknowledged the user command
that is a hope, not a fact. :func:`note_acknowledged` writes the link when the
acknowledgement arrives, through employee_sync.link_device_employee — the same
single writer the SDK path uses. The SDK transport writes it synchronously
because there it *is* a fact by the time the call returns.
"""

import logging
import re

from sqlalchemy.orm import Session

from app import config
from app.models import (
    BiometricTemplate, DeviceCommandOutbox, DeviceEmployee, Employee,
)
from app.services import commands, employee_sync

log = logging.getLogger(__name__)

# The field separator inside one command is a TAB; the command *name* is
# space-separated and multiple records are LF-separated (§3.8). Named because
# a literal "\t" buried in an f-string is the kind of thing a later edit
# silently turns into a space.
HT = "\t"

# Characters that would corrupt the wire format if they appeared inside a
# value: a TAB invents a field boundary, a newline invents a whole record.
# Stripped rather than rejected — a name with a stray tab in it is a reason to
# clean the name, not to refuse to provision the person.
_WIRE_BREAKERS = re.compile(r"[\t\r\n]+")

# "This user has no card", as both the device and this database express it.
_NO_CARD = {"", "0"}


def _wire_safe(value) -> str:
    """One field value, with anything that would break the framing removed."""
    if value is None:
        return ""
    return _WIRE_BREAKERS.sub(" ", str(value)).strip()


def _card_field(card) -> str:
    """`CardNo=` — the device's own convention for "no card" is 0.

    Every user in the BioFace A1 capture uploaded as `cardno=0`, and
    Employee.card defaults to the string "0" for the same reason, so 0 is what
    a cardless person is pushed back down as.
    """
    value = _wire_safe(card)
    return "0" if value in _NO_CARD else value


def user_command(employee: Employee) -> str:
    """The `DATA UPDATE user` line for one person, §3.8 field order.

    Verbatim from the vendor's own example, which is the field order used
    here character for character::

        DATA UPDATE user Pin=1<HT>CardNo=<n><HT>Password=234<HT>Group=0<HT>
        StartTime=0<HT>EndTime=0<HT>Name=<s><HT>Privilege=0

    Field by field:

    ``Pin``
        The employee's user_id. This is the key everything else joins on —
        attendance records, the authorization command below, the biometric
        the person is about to enrol at the terminal.
    ``CardNo``
        0 when there is no card. See :func:`_card_field`.
    ``Password``
        Sent **empty**. This application has no concept of a device keypad
        password, and the people it provisions verify by face or finger.
        Worth knowing, because DATA UPDATE is an upsert: pushing a person who
        already has a keypad password set on the terminal will clear it.
    ``Group``
        config.PROVISION_USER_GROUP (0 by default, as in the vendor example).
        Access-group membership is not how this application grants access.
    ``StartTime`` / ``EndTime``
        0 and 0 — no validity window, i.e. the person does not expire. A real
        date pair here would be the device-side way to time-box an employment.
    ``Name``
        May legitimately be empty: a terminal-enrolled person often has no
        name at all, and an empty name shows as the PIN rather than as an
        invented one.
    ``Privilege``
        0 = ordinary user, 14 = device administrator. Taken from the employee
        row, which the UI defaults to 0 — pushing 14 hands somebody the
        terminal's own menus, so it is deliberately not implicit.
    """
    return (
        "DATA UPDATE user "
        + HT.join([
            f"Pin={_wire_safe(employee.user_id)}",
            f"CardNo={_card_field(employee.card)}",
            "Password=",
            f"Group={int(config.PROVISION_USER_GROUP)}",
            "StartTime=0",
            "EndTime=0",
            f"Name={_wire_safe(employee.name)}",
            f"Privilege={int(employee.privilege or 0)}",
        ])
    )


def authorize_command(user_id, timezone_id: int = None) -> str:
    """The `DATA UPDATE userauthorize` line — the door permission itself.

    ``timezone_id`` names a weekly schedule stored on the device. The default
    comes from config.PROVISION_AUTHORIZE_TIMEZONE_ID, which documents why 1
    rather than 0. A configured 0 is honoured — a site may genuinely want to
    provision people who cannot yet open anything — but it is said out loud,
    because the resulting symptom (verifies fine, door stays shut) otherwise
    looks like a hardware fault.
    """
    tz = config.PROVISION_AUTHORIZE_TIMEZONE_ID if timezone_id is None else timezone_id
    tz = int(tz)
    if tz == 0:
        log.warning(
            "provisioning %s with AuthorizeTimezoneId=0: the terminal will "
            "recognise this person and still refuse them at the door. Set "
            "PROVISION_AUTHORIZE_TIMEZONE_ID to a real access time zone (1 is "
            "the factory-default 24-hour one) if that is not intended.",
            user_id,
        )
    return f"DATA UPDATE userauthorize Pin={_wire_safe(user_id)}{HT}AuthorizeTimezoneId={tz}"


def commands_for(employee: Employee) -> list:
    """Both command bodies for one person, in the order they must be sent."""
    return [user_command(employee), authorize_command(employee.user_id)]


def provision(db: Session, device_sn: str, employee: Employee) -> list:
    """Queue one person onto one `acc` terminal. Returns the outbox rows.

    Queued, not delivered: the device collects these on its next poll and
    acknowledges afterwards. Callers must not report this as done.
    """
    rows = [commands.queue(db, device_sn, body) for body in commands_for(employee)]
    log.info(
        "provisioning %s onto %s: queued command ids %s (user + userauthorize) "
        "— awaiting the device's next getrequest",
        employee.user_id, device_sn, [r.id for r in rows],
    )
    return rows


# ---------------------------------------------------------------------------
# What an acknowledgement means
# ---------------------------------------------------------------------------

# Matches only the person-record command, and only its Pin. `userauthorize`
# deliberately does not match: a door permission acknowledged for somebody the
# terminal never accepted is not evidence that the person is on the device.
_USER_PIN = re.compile(r"^DATA UPDATE user\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE)


def pin_from_user_command(command: str):
    """The Pin in a `DATA UPDATE user` command, or None if it is not one."""
    match = _USER_PIN.match((command or "").strip())
    if not match:
        return None
    return match.group(1).strip() or None


def note_acknowledged(db: Session, device_sn: str, command: str):
    """The device confirmed a user command: record the person as being on it.

    This is the moment `device_employees` earns its row for the ADMS
    transport, and it goes through the same employee_sync writer the SDK path
    uses. ``uid`` is left unset (0, "un-slotted"): the terminal assigns its
    own slot number and never tells us what it chose, and inventing one would
    make a later SDK write address the wrong user.

    Does not commit — the caller owns the transaction.
    """
    user_id = pin_from_user_command(command)
    if not user_id:
        return None
    link = employee_sync.link_device_employee(db, device_sn, user_id)
    log.info(
        "device %s acknowledged the user record for %s — provisioned; the "
        "person can now enrol a face or finger at that terminal",
        device_sn, user_id,
    )
    return link


# ---------------------------------------------------------------------------
# Biometric templates: enrol once, work everywhere
# ---------------------------------------------------------------------------
#
# A template captured at one door is stored by E2 exactly as the device sent
# it — every field, including the ones nothing reads — so that this module can
# hand it to another door unchanged. Nothing here computes, decodes, converts
# or defaults any part of a template: if a value were wrong, the credential
# written to a real access-control terminal would be wrong, and the symptom
# would be somebody else's face opening a door.

# The wire field names in the *command* are CamelCase while the *upload* uses
# lowercase (§3.7 vs §3.8). That asymmetry is the vendor's, is documented, and
# is not a mismatch to tidy up: `Tmp` and `tmp` are the same value on two
# different wires.
_BIODATA_FIELDS = (
    ("Pin", "user_id"),
    ("No", "no"),
    ("Index", "record_index"),   # `index` is reserved SQL; the value is unchanged
    ("Valid", "valid"),
    ("Duress", "duress"),
    ("Type", "type"),
    ("MajorVer", "majorver"),
    ("MinorVer", "minorver"),
    ("Format", "format"),
    ("Tmp", "tmp"),
)


def biodata_command(template: BiometricTemplate) -> str:
    """The `DATA UPDATE BIODATA` line for one stored template, §3.8 field order.

    Verbatim from the vendor's own access-control SDK command constants::

        DATA UPDATE BIODATA Pin={0}<HT>No={1}<HT>Index={2}<HT>Valid={3}<HT>
        Duress={4}<HT>Type={5}<HT>MajorVer={6}<HT>MinorVer={7}<HT>
        Format={8}<HT>Tmp={9}

    Every field comes from a column E2 filled from the device's own upload.
    ``Type`` is passed through as the number it is — 1 and 9 have been seen in
    the field and read as fingerprint and visible-light face, but nothing here
    branches on that and nothing should start: the modality is the device's
    business, this is a replay.

    ``Tmp`` is a few KB of base64 and is never decoded. It is *validated*
    rather than sanitised: a TAB or a newline inside it would invent a field
    or record boundary and hand the terminal a different template than the one
    stored. Silently stripping the character would corrupt a credential, so
    this raises instead and the caller reports the template as unsendable.
    """
    values = []
    for wire_name, column in _BIODATA_FIELDS:
        value = getattr(template, column)
        if value is None:
            raise ValueError(
                f"template {getattr(template, 'id', '?')} has no {column}; "
                f"a BIODATA command cannot be built from an incomplete record"
            )
        if wire_name == "Tmp":
            if _WIRE_BREAKERS.search(str(value)):
                raise ValueError(
                    f"template {getattr(template, 'id', '?')} contains a tab or "
                    f"newline in Tmp, which would break the wire framing; "
                    f"refusing to alter biometric data to make it fit"
                )
            values.append(f"Tmp={value}")
            continue
        values.append(f"{wire_name}={_wire_safe(value)}")

    return "DATA UPDATE BIODATA " + HT.join(values)


def templates_for_device(db: Session, device_sn: str, user_id: str):
    """This person's stored templates, split into what may be sent and what may not.

    Returns ``(sendable, from_this_device)``.

    **A template is never pushed back to the device it came from.** That is
    what ``BiometricTemplate.source_device_sn`` is for. At best it is wasted
    work on a queue that moves one command per ten seconds; at worst it
    overwrites a device's own live enrolment record with this server's copy of
    it, which is a corruption path with no upside — the device already has the
    original.

    Ordered by (type, no) so a given push is reproducible rather than
    depending on insertion order.
    """
    rows = (
        db.query(BiometricTemplate)
        .filter(BiometricTemplate.user_id == str(user_id))
        .order_by(BiometricTemplate.type, BiometricTemplate.no, BiometricTemplate.id)
        .all()
    )
    sendable = [r for r in rows if r.source_device_sn != device_sn]
    own = [r for r in rows if r.source_device_sn == device_sn]
    return sendable, own


def template_commands(templates) -> tuple:
    """Build every command first, queue nothing. ``(commands, unsendable)``.

    Building the whole batch before anything is queued is deliberate: a person
    whose templates cannot all be expressed on the wire should not end up with
    a half-sent enrolment and a user record queued for templates that will
    never follow.
    """
    bodies, unsendable = [], []
    for template in templates:
        try:
            bodies.append(biodata_command(template))
        except ValueError as exc:
            unsendable.append((template, str(exc)))
            log.error(
                "template %s for %s cannot be sent: %s",
                template.id, template.user_id, exc,
            )
    return bodies, unsendable


def is_on_device(db: Session, device_sn: str, user_id: str) -> bool:
    """Has this terminal confirmed it holds this person?

    `device_employees` earns its row only when the device acknowledges the
    user record (E3), so this is a fact rather than a hope — which is exactly
    what "may a template be sent without sending the person first" needs.
    """
    return (
        db.query(DeviceEmployee)
        .filter_by(device_sn=device_sn, user_id=str(user_id))
        .first()
        is not None
    )


def push_templates(
    db: Session,
    device_sn: str,
    employee: Employee,
    bodies: list,
    with_user_record: bool,
) -> list:
    """Queue one person's templates onto one terminal. Returns the outbox rows.

    Order matters and is guaranteed by construction
    -----------------------------------------------
    A template for a Pin the terminal has never heard of has nothing to attach
    to. So when the device has not already confirmed the person
    (:func:`is_on_device`), the user record and door permission are queued
    *first*, in the same call, and the templates behind them.

    That ordering survives delivery because the outbox is FIFO per device:
    `commands._eligible` orders by ``created_at, id``, so the user record is
    always offered on an earlier poll than the templates queued after it. The
    device therefore receives the person before the credential, every time.

    What FIFO does **not** guarantee — and this is the honest part — is that
    the user record was *accepted*. Delivery order is not success order: if
    the terminal refuses the user command, or never acknowledges it, the
    templates behind it are still owed to that device. That residual is not
    papered over; :func:`withdraw_orphaned_templates` withdraws them and
    records why, so the operator sees a failure instead of a silent
    half-success.
    """
    rows = []
    if with_user_record:
        rows.extend(provision(db, device_sn, employee))
    rows.extend(commands.queue(db, device_sn, body) for body in bodies)
    log.info(
        "queued %s biometric template(s) for %s onto %s%s — command ids %s; "
        "queued, not delivered",
        len(bodies), employee.user_id, device_sn,
        " (behind the user record, which the device has not confirmed yet)"
        if with_user_record else " (the device already holds this person)",
        [r.id for r in rows],
    )
    return rows


# ---------------------------------------------------------------------------
# The half-success this unit refuses to leave silent
# ---------------------------------------------------------------------------

_BIODATA_PIN = re.compile(r"^DATA UPDATE BIODATA\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE)


def pin_from_biodata_command(command: str):
    """The Pin in a `DATA UPDATE BIODATA` command, or None if it is not one."""
    match = _BIODATA_PIN.match((command or "").strip())
    if not match:
        return None
    return match.group(1).strip() or None


def withdraw_orphaned_templates(db: Session, device_sn: str = None) -> list:
    """Retire template commands whose person is not going to be on that device.

    A queued template is orphaned when, for the same device and Pin:

    * the terminal has not confirmed the person (no `device_employees` row —
      written only on a real acknowledgement), **and**
    * no user record for them is still outstanding in that device's outbox.

    Which leaves exactly one reading: the user command was concluded and it
    concluded *failed* — refused with a non-zero ``Return``, or handed over
    the maximum number of times and never acknowledged — or the person has
    since been taken off the terminal. Delivering a biometric behind that is
    the silent half-success this unit exists to prevent, so the command is
    concluded ``failed`` with the reason recorded, where the UI shows it
    alongside anything the device refused outright.

    Called from two places, because a user record can fail in two ways: from
    the acknowledgement path the moment a refusal arrives (app/routers/adms.py)
    and from the scheduled sweep, which is what catches the user record that
    was never acknowledged at all (app/main.py).

    Returns the ids withdrawn. Does not raise: a sweep must not fall over.
    """
    query = db.query(DeviceCommandOutbox)
    if device_sn:
        query = query.filter(DeviceCommandOutbox.device_sn == device_sn)
    outstanding = query.order_by(DeviceCommandOutbox.id).all()

    templates = [
        (row, pin) for row, pin in
        ((row, pin_from_biodata_command(row.command)) for row in outstanding)
        if pin
    ]
    if not templates:
        return []

    # Every user record still owed to a device, so a template waiting behind
    # one that simply has not been collected yet is left alone.
    awaiting_user_record = {
        (row.device_sn, pin_from_user_command(row.command))
        for row in outstanding
        if pin_from_user_command(row.command)
    }

    withdrawn = []
    for row, pin in templates:
        if (row.device_sn, pin) in awaiting_user_record:
            continue
        if is_on_device(db, row.device_sn, pin):
            continue

        row_id, row_sn = row.id, row.device_sn
        if commands.conclude(
            db, row, "failed",
            last_error=(
                f"withdrawn: {row_sn} has no confirmed user record for Pin={pin}, "
                f"so this template had nothing to attach to"
            ),
        ):
            withdrawn.append(row_id)
            log.warning(
                "withdrew queued template command %s for %s on %s: the user "
                "record was refused or never acknowledged, so the template "
                "was not sent to a terminal that does not have the person",
                row_id, pin, row_sn,
            )
    return withdrawn
