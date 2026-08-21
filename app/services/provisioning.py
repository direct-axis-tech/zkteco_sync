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


# ---------------------------------------------------------------------------
# Taking a person off a terminal (E8)
# ---------------------------------------------------------------------------
#
# Everything above this line grants access. This is the half that takes it
# away, and it is the half where the asymmetry of this whole design bites.
#
# Granting is allowed to be slow. If a `DATA UPDATE user` sits in the outbox
# for a day because the terminal is unplugged, the consequence is that
# somebody cannot get in yet — annoying, visible, self-correcting. Revoking is
# not allowed to be slow in the same way: while a `DATA DELETE user` sits in
# the outbox, the person it names can still open that door, and *nothing at
# the door itself* says otherwise. The queue's tolerance of offline devices,
# which is a feature everywhere else in this application, is here a safety
# problem. That is why revocation gets a shorter retry schedule
# (commands.backoff_for), an ERROR-level log line when it is given up on
# (commands.conclude) and a UI that refuses to describe a queued delete as a
# completed one.
#
# What is CONFIRMED, and what is not
# ----------------------------------
# `DATA DELETE user Pin=<n>` is verbatim from §3.8's own worked example
# (`C:296:DATA DELETE user Pin=1`). It is the only delete shape the protocol
# reference gives a literal example for, and it is the load-bearing one.
#
# `DATA DELETE userauthorize Pin=<n>` is DERIVED, not quoted: the generic
# grammar `DATA DELETE <table> …` is documented, the table name
# `userauthorize` is confirmed, and `Pin` is confirmed as its key from the
# UPDATE shape. See :func:`authorize_delete_command` for why it is sent
# anyway, and what happens if the terminal has already removed it.
#
# There is NO biometric delete here. Not a guessed one, not an UNVERIFIED one
# — none. See :func:`revoke_commands_for`.


def user_delete_command(user_id) -> str:
    """`DATA DELETE user Pin=<n>` — verbatim from §3.8.

    Quoted from the protocol reference's own example, `C:296:DATA DELETE user
    Pin=1`, which is the single command shape in this module that needs no
    derivation at all. One field, no TABs: unlike the UPDATE shapes there is
    nothing else to say, because the Pin identifies the record and the record
    is what goes.
    """
    return f"DATA DELETE user Pin={_wire_safe(user_id)}"


def authorize_delete_command(user_id) -> str:
    """`DATA DELETE userauthorize Pin=<n>` — the door permission, explicitly.

    DERIVED, not quoted. §3.8 gives the generic form `DATA DELETE <table> …`,
    gives `userauthorize` as a real table, and gives `Pin` as its key. What it
    does *not* say anywhere is whether deleting the user also deletes that
    user's authorization row. Both readings are plausible and the spec settles
    neither, so this takes the safer of the two: send it, and do not depend on
    a cascade nobody has observed.

    The cost of being wrong in each direction is what decides it.

    * If the terminal *does* cascade, this command is redundant. Worst case it
      answers with a non-zero Return meaning "no such record", which is
      surfaced honestly (see the UI wording) and costs nothing but a poll.
    * If the terminal does *not* cascade and this were omitted, a
      `userauthorize` row would outlive the person it belonged to. That is
      the half-revocation this unit exists to prevent, and it is invisible
      from the server: everything we can see would say the delete worked.

    A redundant command is cheap; a stale door permission is not.
    """
    return f"DATA DELETE userauthorize Pin={_wire_safe(user_id)}"


def revoke_commands_for(user_id) -> list:
    """Both delete bodies for one person, in the order they must be sent.

    The user record goes FIRST, and the order is the whole argument.

    A terminal collects one command per poll. If it collects exactly one and
    then loses power for a week, the one it got should be the one that
    actually revokes. That is `DATA DELETE user`: it is the confirmed shape,
    and removing the person's record removes the terminal's ability to
    recognise them at all, whatever it does about permissions. The
    authorization delete alone would leave the person still enrolled and rely
    on the device treating a missing `userauthorize` row as "no doors" — very
    probably true, entirely unverified, and not something to bet a door on.

    So: the definitely-sufficient command first, the belt-and-braces one
    behind it.

    On biometrics — the question this unit was told to ANSWER, not guess at
    -------------------------------------------------------------------
    There is no template delete here, and that is a finding rather than an
    omission. §3.8 reproduces ZKTeco's own access-control SDK command
    constants (`namanhho/BioMatrix`, `Access/Commands.cs`), which the protocol
    reference rates as the highest-weight source it has. That enumeration
    contains `DATA UPDATE BIODATA`, `DATA UPDATE biophoto`, `DATA UPDATE
    templatev10`, `DATA UPDATE facev7`, `DATA QUERY tablename=biodata` and
    `DATA COUNT biodata` — and exactly one delete, for `user`. The vendor's
    own SDK exposes no way to delete a biometric row on its own.

    The reading that makes that consistent is that biometrics belong to the
    user record and go when it goes; a terminal offering no biometric delete
    at all, and thus no way ever to remove a face from an access controller,
    is not a credible design. So removing the person is what removes their
    templates, and `DATA DELETE user Pin=<n>` is the whole revocation.

    Stated as what it is: an inference from an absence, marked UNVERIFIED
    against real hardware, and the reason nothing here invents a delete for a
    biometric table. Inventing one and shipping it as known would be guessing
    at a command that writes physical door hardware, and if the guess were
    wrong the terminal would refuse it and the operator would be shown a
    failure for something that had, in fact, already worked.
    """
    return [user_delete_command(user_id), authorize_delete_command(user_id)]


# `DATA DELETE user Pin=…` only. `DATA DELETE userauthorize Pin=…` must not
# match: an acknowledged permission delete is not evidence that the person is
# off the terminal, and it is the person being off the terminal that the
# `device_employees` row means. The `\s+` after `user` is what keeps the two
# apart — "userauthorize" has no whitespace at that position.
_DELETE_USER_PIN = re.compile(r"^DATA DELETE user\s+Pin=([^\t]*)", re.IGNORECASE)

# Any `DATA UPDATE <table> … Pin=…` — the push commands a revocation
# contradicts. Deliberately generic over the table so a future push command
# for a table this unit has never heard of is withdrawn too.
_PUSH_PIN = re.compile(r"^DATA UPDATE \S+\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE)


def pin_from_revocation_command(command: str):
    """The Pin in a `DATA DELETE user` command, or None if it is not one."""
    match = _DELETE_USER_PIN.match((command or "").strip())
    if not match:
        return None
    return match.group(1).strip() or None


def pin_from_push_command(command: str):
    """The Pin in any `DATA UPDATE <table>` command, or None."""
    match = _PUSH_PIN.match((command or "").strip())
    if not match:
        return None
    return match.group(1).strip() or None


def is_revocation_command(command: str) -> bool:
    """True for either half of a revocation, for filtering the outbox."""
    text = (command or "").strip()
    return bool(
        _DELETE_USER_PIN.match(text)
        or re.match(r"^DATA DELETE userauthorize\s+Pin=", text, re.IGNORECASE)
    )


def pin_from_any_delete_command(command: str):
    """The Pin in either delete command, or None. For grouping, not for acting."""
    text = (command or "").strip()
    match = re.match(r"^DATA DELETE \S+\s+Pin=([^\t]*)", text, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip() or None


def outstanding_revocations(db: Session, device_sn: str = None, user_id: str = None) -> list:
    """Outbox rows that are part of a revocation, optionally narrowed.

    "Outstanding" is the honest word and the one the UI uses: the command is
    still owed to a device, which means the person it names has *not* been
    confirmed removed, which means they may still be able to open that door.
    """
    query = db.query(DeviceCommandOutbox)
    if device_sn:
        query = query.filter(DeviceCommandOutbox.device_sn == device_sn)
    rows = [r for r in query.order_by(DeviceCommandOutbox.id).all()
            if is_revocation_command(r.command)]
    if user_id is not None:
        rows = [r for r in rows
                if pin_from_any_delete_command(r.command) == str(user_id)]
    return rows


def withdraw_pushes_for(db: Session, device_sn: str, user_id: str, reason: str) -> list:
    """Retire every queued push for this (device, Pin). Returns the ids.

    A queued `DATA UPDATE user` and a queued `DATA DELETE user` for the same
    person on the same door are two instructions that contradict each other,
    and the outbox is FIFO, so leaving both in it means the device performs
    whichever was queued first and then the other — in the worst ordering,
    deleting the person and then putting them straight back.

    Same mechanism E4 built for orphaned templates: the command is concluded
    ``failed`` with the reason recorded, so it appears in the device's history
    and in the person's "not delivered" list rather than silently evaporating.
    Called *before* the deletes are queued, so the outbox never holds the
    contradiction at all.
    """
    withdrawn = []
    for row in db.query(DeviceCommandOutbox).filter(
        DeviceCommandOutbox.device_sn == device_sn
    ).order_by(DeviceCommandOutbox.id).all():
        if pin_from_push_command(row.command) != str(user_id):
            continue
        row_id, name = row.id, row.command.split("\t")[0]
        if commands.conclude(db, row, "failed", last_error=reason):
            withdrawn.append(row_id)
            log.warning(
                "withdrew queued push %s (%s) for %s on %s: %s",
                row_id, name, user_id, device_sn, reason,
            )
    return withdrawn


def revoke(db: Session, device_sn: str, user_id: str) -> tuple:
    """Queue one person's removal from one `acc` terminal.

    Returns ``(rows, withdrawn)`` — the outbox rows created and the ids of any
    contradicting pushes retired to make room for them.

    Writes nothing to `device_employees`. That row is this application's claim
    that the person is on that door, and it survives until the terminal
    acknowledges the delete (:func:`note_revocation_acknowledged`). Removing
    it here would be the mirror of the bug E3 fixed on the way in: a local
    record asserting a device state that no device has confirmed. Worse in
    this direction, because it would read as "revoked" on a screen while the
    person walks through the door.
    """
    withdrawn = withdraw_pushes_for(
        db, device_sn, user_id,
        reason=f"withdrawn: {user_id} is being removed from {device_sn}",
    )
    rows = [commands.queue(db, device_sn, body)
            for body in revoke_commands_for(user_id)]
    log.warning(
        "revoking %s from %s: queued command ids %s (user + userauthorize)%s "
        "— NOT yet revoked at the door; the terminal must collect and "
        "acknowledge these first",
        user_id, device_sn, [r.id for r in rows],
        f", withdrew {len(withdrawn)} contradicting push(es)" if withdrawn else "",
    )
    return rows, withdrawn


def note_revocation_acknowledged(db: Session, device_sn: str, command: str):
    """The terminal confirmed a user delete: the person really is off it now.

    The exact mirror of :func:`note_acknowledged`, and the only thing in the
    ADMS transport allowed to drop the link. Goes through
    employee_sync.unlink_device_employee, the single deleter, rather than
    reaching for the table here.

    Does not commit — the caller owns the transaction.
    """
    user_id = pin_from_revocation_command(command)
    if not user_id:
        return False
    removed = employee_sync.unlink_device_employee(db, device_sn, user_id)
    log.info(
        "device %s acknowledged the deletion of %s — revoked and confirmed at "
        "the door%s",
        device_sn, user_id,
        "" if removed else " (no local enrolment record existed to clear)",
    )
    return removed


def cancel_revocation(db: Session, device_sn: str, user_id: str, by: str) -> list:
    """Take an outstanding revocation back out of the outbox. Returns the ids.

    Exists because of what happens on the other side of the collision: a push
    for somebody with a revocation still outstanding is REFUSED, not
    interleaved (see the 409 in app/routers/devices.py). Refusing without
    offering a way out would strand an operator behind an offline terminal
    with no way to re-grant access, so this is the way out — and it is a
    deliberate, audited, named act rather than a side effect of clicking
    "push" again.

    Concluded ``failed`` rather than deleted outright: the log row is the
    record that somebody decided not to revoke after all, which is exactly the
    kind of thing an access-control system should not be able to forget.
    """
    cancelled = []
    for row in outstanding_revocations(db, device_sn, user_id):
        row_id, name = row.id, row.command.split("\t")[0]
        if commands.conclude(
            db, row, "failed",
            last_error=f"revocation cancelled by {by} before the device collected it",
        ):
            cancelled.append(row_id)
            log.warning(
                "revocation command %s (%s) for %s on %s CANCELLED by %s — "
                "this person keeps their access to that door",
                row_id, name, user_id, device_sn, by,
            )
    return cancelled


# ---------------------------------------------------------------------------
# Asking the terminal for what it already holds (E12)
# ---------------------------------------------------------------------------
#
# Everything above pushes *down*. This section pulls *up*, and it is here
# rather than in a module of its own for one reason: every byte this
# application ever puts on an `acc` wire should be greppable in one file, next
# to the evidence that justifies it.
#
# There is no synchronous read on this transport. A `DATA QUERY` is queued
# like any other command, collected on the device's next `GET
# /iclock/getrequest`, and answered by the device POSTing the table back to
# `/iclock/querydata` — possibly across several packets — where E9 reassembles
# and ingests it and concludes the command by its `cmdid`. So a caller here
# gets an outbox row, never data, and must say *queued*.
#
# EVIDENCE GRADES. These three strings are not extrapolations. Each was
# collected by the operator's own BioFace A1 (VGU6254600603) on 2026-08-21 and
# answered with real records, so they are reproduced verbatim — including the
# capital `Type` on biophoto and the lowercase `type` on biodata, which is how
# the device was actually asked. Do not "normalise" them.
#
#   user     -> 3 records, one packet
#   biophoto -> 3 photos across 3 packets, reassembled and stored
#   biodata  -> 6 templates, one packet
#
# ONE BIODATA QUERY, NOT ONE PER MODALITY. The device IGNORES the type filter:
# `filter=type=9` and `filter=type=1` returned byte-identical bodies (6
# records, 7002 bytes both times), covering face and fingerprint together. A
# loop over modalities would ask the same question twice, occupy the queue for
# a second poll cycle, and re-ingest rows E2's upsert would only overwrite
# with themselves.

# The user table: name, card, privilege, password — the person records.
QUERY_USERS = "DATA QUERY tablename=user,fielddesc=*,filter=*"

# Enrolled photographs. Large, and the one query observed to arrive in
# multiple packets.
QUERY_PHOTOS = "DATA QUERY tablename=biophoto,fielddesc=*,filter=Type=9"

# Biometric templates, ALL modalities in one answer (see above).
QUERY_TEMPLATES = "DATA QUERY tablename=biodata,fielddesc=*,filter=type=9"

# Why there is no attendance entry here, in the module an author would grep
# before adding one.
#
# It is NOT known whether an `acc` terminal will answer a server-issued query
# for its transaction table, and no such command has ever been observed. What
# IS known is that these devices push punches up on their own as `rtlog`, and
# that the operator has already watched punches from a period when this server
# was unreachable arrive afterwards — so the buffer drains over the push
# channel without being asked.
#
# Inventing `DATA QUERY tablename=transaction` and wiring it to a menu item
# would therefore produce, at best, a button that appears to work and does
# nothing, and at worst one that wedges the outbox on a command the firmware
# never answers, retrying on backoff until it exhausts. An honest "not
# applicable here" is strictly better than either. A test greps this package
# and fails if such a command ever appears.
NO_ATTENDANCE_QUERY = (
    "Attendance is not pulled from an access-control terminal. It arrives by "
    "itself: the device pushes each punch up as an rtlog record as it happens, "
    "and re-sends what it buffered once it can reach the server again. There "
    "is no confirmed command for asking one of these terminals for its "
    "transaction table, and none has been invented here — a button that "
    "silently does nothing would be worse than one that says it does not apply."
)


def queue_query(db: Session, device_sn: str, command: str) -> tuple:
    """Queue one ``DATA QUERY``, reusing an identical one already outstanding.

    Returns ``(row, created)``.

    Clicking Sync twice should not cost two poll cycles. A query carries no
    arguments and no state, so a second identical one outstanding on the same
    device asks a question already asked and answers it with the same rows —
    it just puts the real work ten seconds further away, at
    COMMAND_BATCH_SIZE=1. Reusing the outstanding row is honest about that:
    the caller is told which command id to watch, and it is the one that will
    actually answer.

    Only ``pending`` and ``sent`` rows are reused. A concluded query is
    history; asking again is exactly what the operator means.
    """
    existing = (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.device_sn == device_sn,
                DeviceCommandOutbox.command == command,
                DeviceCommandOutbox.status.in_(("pending", "sent")))
        .order_by(DeviceCommandOutbox.id)
        .first()
    )
    if existing:
        log.info("query already outstanding for %s as command %s: %s",
                 device_sn, existing.id, command)
        return existing, False
    return commands.queue(db, device_sn, command), True


def query_users(db: Session, device_sn: str) -> tuple:
    """Ask an `acc` terminal for its user table."""
    return queue_query(db, device_sn, QUERY_USERS)


def query_photos(db: Session, device_sn: str) -> tuple:
    """Ask an `acc` terminal for its enrolled photographs."""
    return queue_query(db, device_sn, QUERY_PHOTOS)


def query_templates(db: Session, device_sn: str) -> tuple:
    """Ask an `acc` terminal for its biometric templates — one query, all types."""
    return queue_query(db, device_sn, QUERY_TEMPLATES)


def query_everything(db: Session, device_sn: str) -> tuple:
    """All three confirmed queries, in the order they are worth having.

    Returns ``(rows, created_count)``. Attendance is deliberately not among
    them; see :data:`NO_ATTENDANCE_QUERY`.

    People first, because a photo or a template whose Pin we cannot name is
    not much use; photos before templates only because the operator can see a
    photo went wrong and cannot see that about a template.
    """
    rows, created = [], 0
    for command in (QUERY_USERS, QUERY_PHOTOS, QUERY_TEMPLATES):
        row, was_new = queue_query(db, device_sn, command)
        rows.append(row)
        created += 1 if was_new else 0
    log.info("sync-all queued for %s: command ids %s (%s new) — "
             "awaiting the device's next getrequest",
             device_sn, [r.id for r in rows], created)
    return rows, created
