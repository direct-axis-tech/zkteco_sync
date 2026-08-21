"""Putting a person onto an access-control terminal, over the command queue.

The workflow this serves is the operator's, taken from BioTime: create the
person centrally, push them to a door, then walk up to that door and enrol a
face or a finger *on the terminal*. The device uploads the resulting template
back by itself (that is E1/E2). Nothing here sends a biometric — it sends the
identity the biometric will later attach to.

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
from app.models import Employee
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
