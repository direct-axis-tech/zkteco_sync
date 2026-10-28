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

import base64
import binascii
import logging
import re

from sqlalchemy.orm import Session

from app import config, keypad_password
from app.models import (
    BiometricTemplate, DeviceCommandLog, DeviceCommandOutbox, DeviceEmployee,
    Employee, FingerprintTemplate,
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


def _password_field(employee: Employee):
    """The value a user command carries for the person's keypad password, or
    None when none is stored or the current key cannot open it.

    Never the digits: the command is a database row and a line in the
    Commands drawer long before it is a line on the wire, so it carries the
    sealed value and commands.wire_line opens it at dispatch
    (keypad_password.in_command / revealed).
    """
    if not keypad_password.unseal(employee.keypad_password):
        return None
    return keypad_password.in_command(employee.keypad_password)


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
        The person's stored keypad password (Employee.keypad_password), as
        a sealed placeholder the dispatcher opens only on the wire — see
        :func:`_password_field`. **Empty** when none is stored, as before
        passwords were kept: DATA UPDATE is an upsert, so pushing a person
        with no stored password clears one set at the terminal's keypad.
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
            f"Password={_password_field(employee) or ''}",
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
# The `att` side: one command, because there is no door permission
# ---------------------------------------------------------------------------
#
# An attendance terminal keeps the person in a single table, USERINFO, so the
# whole push is one `DATA UPDATE USERINFO` line (Attendance PUSH 2.4.1
# §12.1.1.1). From the document; not yet observed on hardware. What HAS been
# observed is the other direction: the BioPro SA20 CPV2232560497 answering
# `DATA QUERY USERINFO` on 2026-10-19 with lines of exactly these fields,
#
#     USER PIN=036<HT>Name=…<HT>Pri=0<HT>Passwd=<HT>Card=<HT>Grp=1<HT>
#     TZ=0000000100000000<HT>Verify=0<HT>ViceCard=<HT>StartDatetime=0<HT>…
#
# which is where the fixed values below come from.

# Group 1 is the document's default ("group 1 by default") and what the SA20
# reported for every person enrolled at its keypad.
ATT_USER_GROUP = 1

# The SA20's own value for every person enrolled at its keypad. Digits 1-4 are
# 0000, which §12.1.1.1 reads as "use the group time period" — the person
# punches whenever the group may. Sent rather than left to the firmware because
# what a terminal defaults a missing TZ to is not documented, and a person the
# terminal treats as outside their time period is refused at the reader while
# everything the server can see says the push worked.
ATT_USER_TIME_ZONES = "0000000100000000"

# Appendix 7: 0 is "finger vein or face or fingerprint or card or password
# (automatic identification)" — whatever the person has enrolled. Also what
# the SA20 reported for its own people.
ATT_USER_VERIFY = 0


def att_user_command(employee: Employee) -> str:
    """The `DATA UPDATE USERINFO` line for one person, §12.1.1.1 field order.

    The document's shape is
    ``PIN Name Pri Passwd Card Grp TZ Verify ViceCard``; this sends it with
    two fields left out. Field by field:

    ``PIN``
        The employee's user_id, as the string it is. Leading zeros are part of
        the identity on these terminals (`036` and `0036` are two people on the
        SA20), so it is never turned into a number.
    ``Name``
        May be empty, as on the acc side: the terminal then shows the PIN.
    ``Pri``
        0 = ordinary user, 14 = super administrator (§12.1.1.1's table; the
        SA20's admins report 14). From the employee row, never implied.
    ``Passwd`` — sent only when one is stored
        The person's stored keypad password, as a sealed placeholder the
        dispatcher opens only on the wire (:func:`_password_field`). With
        none stored it is left out: ``Passwd=`` empty would assert that the
        person has none, and DATA UPDATE is an upsert, so on a terminal that
        merges fields it would wipe a password set at the keypad. Left out, a
        terminal that merges keeps it, and one that replaces the record clears
        it either way. The vendor's own sample records (§12.5.2, `DATA UPDATE
        USERINFO PIN=1 Name=1 Pri=0 Passwd=1 Grp=1`) leave fields out the same
        way.
    ``Card``
        The card number as a string (§12.1.1.1's format b). "No card" is
        ``Card=`` empty, which is how the SA20 reports a cardless person — the
        "0" this database stores for "no card" is never sent, because on this
        wire it would be a card numbered 0.
    ``Grp`` / ``TZ`` / ``Verify``
        :data:`ATT_USER_GROUP`, :data:`ATT_USER_TIME_ZONES`,
        :data:`ATT_USER_VERIFY` — what the terminal itself reports for the
        people enrolled at it, so a person pushed from here is set up the same
        way as one enrolled at the keypad.
    ``ViceCard`` — not sent
        A secondary card this application has no notion of, left alone for
        the same reason as ``Passwd``.
    """
    card = _wire_safe(employee.card)
    password = _password_field(employee)
    return (
        "DATA UPDATE USERINFO "
        + HT.join([
            f"PIN={_wire_safe(employee.user_id)}",
            f"Name={_wire_safe(employee.name)}",
            f"Pri={int(employee.privilege or 0)}",
            *([f"Passwd={password}"] if password else []),
            f"Card={'' if card in _NO_CARD else card}",
            f"Grp={ATT_USER_GROUP}",
            f"TZ={ATT_USER_TIME_ZONES}",
            f"Verify={ATT_USER_VERIFY}",
        ])
    )


def provision_att(db: Session, device_sn: str, employee: Employee) -> list:
    """Queue one person onto one `att` terminal. Returns the outbox rows.

    One row, returned as a list so a caller answers the same way it does for
    :func:`provision`. Queued, not delivered: the link to the device is
    written when the terminal acknowledges (:func:`note_acknowledged`).
    """
    rows = [commands.queue(db, device_sn, att_user_command(employee))]
    log.info(
        "provisioning %s onto %s: queued command id %s (USERINFO) — awaiting "
        "the device's next getrequest",
        employee.user_id, device_sn, rows[0].id,
    )
    return rows


# ---------------------------------------------------------------------------
# What an acknowledgement means
# ---------------------------------------------------------------------------

# Matches only the person-record command, and only its Pin: `DATA UPDATE user
# Pin=…` on an `acc` terminal, `DATA UPDATE USERINFO PIN=…` on an `att` one
# (case-insensitive, which is what lets `Pin=` match `PIN=`). `userauthorize`
# deliberately does not match: a door permission acknowledged for somebody the
# terminal never accepted is not evidence that the person is on the device.
_USER_PIN = re.compile(
    r"^DATA UPDATE (?:user|USERINFO)\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE
)


def pin_from_user_command(command: str):
    """The Pin in a `DATA UPDATE user` or `DATA UPDATE USERINFO` command, or
    None if it is not one."""
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

    **A template is not pushed back to the device it came from — while that
    device still holds the person.** That is what
    ``BiometricTemplate.source_device_sn`` is for. Sending one back is wasted
    work at best, and at worst it overwrites a device's own live enrolment
    record with this server's copy of it: a corruption path with no upside,
    because the device already has the original.

    **"The device already has the original" is a claim, so it is now checked.**
    It was previously assumed, and it is false in exactly the case that needs
    this most: a terminal whose enrolment database was wiped, and a person
    revoked from a door who is being re-added. In both, the server holds the
    only surviving copy of a template the device itself captured, and the old
    rule refused to give it back — the restore was blocked by a guard whose
    premise no longer held.

    ``is_on_device`` answers it from ``device_employees``, which earns its row
    only when the terminal acknowledges the user record. So the guard now
    applies when it is true that the device has the person, and lifts when it
    is not. A live enrolment is protected exactly as before; a wiped or
    revoked one is restorable.

    (The old docstring also called this "wasted work on a queue that moves one
    command per ten seconds". Measured on real hardware 2026-08-31, a terminal
    with a full outbox collects about 2.2 commands per second — ``RequestDelay``
    governs an idle queue, not a busy one.)

    Ordered by (type, no) so a given push is reproducible rather than
    depending on insertion order.
    """
    rows = (
        db.query(BiometricTemplate)
        .filter(BiometricTemplate.user_id == str(user_id))
        .order_by(BiometricTemplate.type, BiometricTemplate.no, BiometricTemplate.id)
        .all()
    )
    return _withhold_while_held(db, device_sn, user_id, rows)


def _withhold_while_held(db: Session, device_sn: str, user_id: str, rows) -> tuple:
    """``(sendable, from_this_device)``: the rule of :func:`templates_for_device`,
    for any stored template that records its ``source_device_sn``."""
    # One query, not one per row: the answer is the same for every template
    # this person has, because it is a fact about the person and the device.
    if not is_on_device(db, device_sn, user_id):
        return rows, []
    sendable = [r for r in rows if r.source_device_sn != device_sn]
    own = [r for r in rows if r.source_device_sn == device_sn]
    return sendable, own


def template_commands(templates, build=None) -> tuple:
    """Build every command first, queue nothing. ``(commands, unsendable)``.

    Building the whole batch before anything is queued is deliberate: a person
    whose templates cannot all be expressed on the wire should not end up with
    a half-sent enrolment and a user record queued for templates that will
    never follow.

    ``build`` turns one stored template into its command and raises
    ValueError for one that cannot go on the wire: :func:`biodata_command`
    (the default) for an `acc` terminal, :func:`att_fingerprint_command` for
    an `att` one.
    """
    build = build or biodata_command
    bodies, unsendable = [], []
    for template in templates:
        try:
            bodies.append(build(template))
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
    queue_person=None,
) -> list:
    """Queue one person's templates onto one terminal. Returns the outbox rows.

    ``queue_person`` queues the user record that leads them when one is
    needed: :func:`provision` (the default, user record and door permission)
    for an `acc` terminal, :func:`provision_att` (one USERINFO) for an `att`
    one.

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
        rows.extend((queue_person or provision)(db, device_sn, employee))
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
# Fingerprints onto an attendance terminal
# ---------------------------------------------------------------------------
#
# The same push, the same rules, from the other table. An attendance terminal
# reports its fingerprints as `FP PIN=…⇥FID=…⇥Size=…⇥Valid=…⇥TMP=<base64>`
# lines on cdata?table=OPERLOG, and adms._store_operlog keeps each in
# `fingerprint_templates` as the hex of the decoded bytes — the form pyzk's
# `Finger.json_pack()` gives the SDK pull on a LAN terminal too. The command
# below is the inverse of that parse.

# §12.1.1.3: "FID=${XXX}: Finger number, valued from 0 – 9."
ATT_FINGER_IDS = range(10)


def att_fingerprint_command(template: FingerprintTemplate) -> str:
    """The `DATA UPDATE FINGERTMP` line for one stored fingerprint.

    Attendance PUSH 2.4.1 §12.1.1.3, from the document; not yet observed on
    hardware::

        DATA UPDATE FINGERTMP PIN=<s><HT>FID=<n><HT>Size=<n><HT>Valid=<n><HT>TMP=<base64>

    ``PIN``
        The user_id verbatim, as the string it is: `036` and `0036` are two
        people on the SA20.
    ``FID``
        0–9, the document's range. Anything else is refused rather than sent
        for the terminal to file somewhere unknown.
    ``Size``
        The length of the base64 ``TMP`` text, not of the raw template.
        §12.1.1.3 defines it as "Length of binary data of the finger template
        after base64 coding", and the SA20's own `FP` upload lines agree:
        their ``Size`` equals the length of their ``TMP`` string. A wrong
        Size is what Appendix 1's -9 ("The transmitted template data does not
        match the given size") answers.
    ``Valid``
        As stored: 1 normal, 3 duress, 0 invalid (§12.1.1.3's table). Passed
        through, never interpreted, like ``Type`` on the `acc` side.
    ``TMP``
        Base64 of the raw template, decoded from the stored hex. That is the
        exact inverse of what adms._store_operlog did with the terminal's
        upload, so a template goes out byte for byte as it arrived. Base64 has
        no TAB or newline to break the framing; a stored value that is not
        hex is refused, never repaired, because a "repaired" template is a
        different credential.

    §12.1.1.3 also notes the command takes fingerprint algorithm versions up
    to 10.0. The SA20 stores ZKFinger VX10.0; whether a template captured on
    another model is accepted by the target terminal is a hardware question.
    """
    ref = f"fingerprint {getattr(template, 'id', '?')}"
    if template.finger_id not in ATT_FINGER_IDS:
        raise ValueError(
            f"{ref} is finger {template.finger_id}; §12.1.1.3 only numbers "
            f"fingers 0-9"
        )
    if template.valid is None:
        raise ValueError(f"{ref} has no valid flag; refusing to guess one")
    try:
        raw = bytes.fromhex(template.template or "")
    except ValueError:
        raise ValueError(
            f"{ref} is not stored as hex, so its bytes are unknown; refusing "
            f"to alter biometric data to make it fit"
        ) from None
    if not raw:
        raise ValueError(f"{ref} is empty; there is no template to send")

    tmp = base64.b64encode(raw).decode("ascii")
    return (
        "DATA UPDATE FINGERTMP "
        + HT.join([
            f"PIN={_wire_safe(template.user_id)}",
            f"FID={int(template.finger_id)}",
            f"Size={len(tmp)}",
            f"Valid={int(template.valid)}",
            f"TMP={tmp}",
        ])
    )


def fingerprints_for_device(db: Session, device_sn: str, user_id: str):
    """This person's stored fingerprints, ``(sendable, from_this_device)``.

    The rule of :func:`templates_for_device`, on `fingerprint_templates`: a
    fingerprint is not sent back to the terminal that captured it while that
    terminal still holds the person, and is once it does not. After a Sync
    every person an attendance terminal reported is linked to it
    (employee_sync.record_device_user), so the fingerprints that came with
    them are withheld from it exactly as an `acc` terminal's own are.

    Ordered by finger so a given push is reproducible.
    """
    rows = (
        db.query(FingerprintTemplate)
        .filter(FingerprintTemplate.user_id == str(user_id))
        .order_by(FingerprintTemplate.finger_id, FingerprintTemplate.id)
        .all()
    )
    return _withhold_while_held(db, device_sn, user_id, rows)


# ---------------------------------------------------------------------------
# The half-success this unit refuses to leave silent
# ---------------------------------------------------------------------------

# A queued template on either kind of terminal: `DATA UPDATE BIODATA Pin=…`
# on `acc`, `DATA UPDATE FINGERTMP PIN=…` on `att` (case-insensitive, which is
# what lets `Pin=` match `PIN=`). A FINGERTMP for a PIN the terminal does not
# hold is refused with Appendix 1's -10 ("The user specified by PIN does not
# exist in the equipment"), so it is withdrawn behind a failed USERINFO for the
# same reason a BIODATA is behind a failed `user`.
_TEMPLATE_PIN = re.compile(
    r"^DATA UPDATE (?:BIODATA|FINGERTMP)\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE
)


def pin_from_template_command(command: str):
    """The Pin in a `DATA UPDATE BIODATA` or `DATA UPDATE FINGERTMP` command,
    or None if it is not one."""
    match = _TEMPLATE_PIN.match((command or "").strip())
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

    # A remote enrolment (`ENROLL_FP`) is withdrawn on the same terms: it names
    # a PIN the terminal must hold, and delivered behind a refused USERINFO it
    # would open an enrolment screen for somebody the terminal does not have.
    templates = [
        (row, pin) for row, pin in
        ((row, pin_from_template_command(row.command)
          or pin_from_enrolment_command(row.command)) for row in outstanding)
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
        what = ("there was nobody there to enrol"
                if pin_from_enrolment_command(row.command)
                else "this template had nothing to attach to")
        if commands.conclude(
            db, row, "failed",
            last_error=(
                f"withdrawn: {row_sn} has no confirmed user record for Pin={pin}, "
                f"so {what}"
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
#
# An attendance terminal is revoked with ONE command, `DATA DELETE USERINFO
# PIN=<n>` (Attendance PUSH 2.4.1 §12.1.2.1), from the document and not yet
# observed on hardware. See :func:`att_user_delete_command`. Everything after
# the queueing — tracking until acknowledged, unlinking on Return=0, blocking
# pushes meanwhile, cancelling, grouping — is the same lifecycle, because the
# parsers below recognise both shapes.


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


def att_user_delete_command(user_id) -> str:
    """`DATA DELETE USERINFO PIN=<n>` — one person off an `att` terminal.

    Attendance PUSH 2.4.1 §12.1.2.1, from the document; not yet observed on
    hardware. The PIN goes out verbatim, as the string it is: leading zeros
    are part of the identity on these terminals (`036` and `0036` are two
    people on the SA20), so it is never turned into a number.

    This one command is the whole revocation, biometrics included. §12.1.2.1
    says the delete removes "specified user information, including
    fingerprint template, face template and user photo", so a separate
    `DATA DELETE FINGERTMP PIN=<n>` (§12.1.2.2) would be redundant — and a
    second command is a second chance of a split revocation, the person's
    record gone and a refusal on their templates reported as a failure for
    something that had already happened. It is the same conclusion the `acc`
    side reached (:func:`revoke_commands_for`): biometrics belong to the
    person record and go when it goes. Here the document says so outright.

    There is no door-permission half either: an attendance terminal keeps the
    person in a single table, USERINFO, exactly as the push
    (:func:`att_user_command`) found.
    """
    return f"DATA DELETE USERINFO PIN={_wire_safe(user_id)}"


# The person-record delete, on either kind of terminal: `DATA DELETE user
# Pin=…` on `acc`, `DATA DELETE USERINFO PIN=…` on `att` (case-insensitive,
# which is what lets `Pin=` match `PIN=`). `DATA DELETE userauthorize Pin=…`
# must not match: an acknowledged permission delete is not evidence that the
# person is off the terminal, and it is the person being off the terminal that
# the `device_employees` row means. The `\s+` after the table name is what
# keeps the two apart — "userauthorize" has no whitespace at that position.
_DELETE_USER_PIN = re.compile(
    r"^DATA DELETE (?:user|USERINFO)\s+Pin=([^\t]*)", re.IGNORECASE
)
_DELETE_ATT_USER = re.compile(r"^DATA DELETE USERINFO\s", re.IGNORECASE)

# Any `DATA UPDATE <table> … Pin=…` — the push commands a revocation
# contradicts. Deliberately generic over the table so a future push command
# for a table this unit has never heard of is withdrawn too.
_PUSH_PIN = re.compile(r"^DATA UPDATE \S+\s+(?:.*?\t)?Pin=([^\t]*)", re.IGNORECASE)


def pin_from_revocation_command(command: str):
    """The Pin in a `DATA DELETE user` or `DATA DELETE USERINFO` command, or
    None if it is not one."""
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
    """True for either half of an `acc` revocation and for the single command
    of an `att` one, for filtering the outbox."""
    text = (command or "").strip()
    return bool(
        _DELETE_USER_PIN.match(text)
        or re.match(r"^DATA DELETE userauthorize\s+Pin=", text, re.IGNORECASE)
    )


def pin_from_any_delete_command(command: str):
    """The Pin in any revocation command, `PIN=` of `att` included, or None.
    For grouping, not for acting."""
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

    A queued remote enrolment (`ENROLL_FP`) goes too. It is not a `DATA
    UPDATE`, but it contradicts the delete the same way: delivered first, it
    either has the person enrol a finger the delete then takes away, or opens
    an enrolment screen at which nobody is standing.
    """
    withdrawn = []
    for row in db.query(DeviceCommandOutbox).filter(
        DeviceCommandOutbox.device_sn == device_sn
    ).order_by(DeviceCommandOutbox.id).all():
        pin = pin_from_push_command(row.command) or pin_from_enrolment_command(row.command)
        if pin != str(user_id):
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
    """
    return _queue_revocation(db, device_sn, user_id,
                             revoke_commands_for(user_id), "user + userauthorize")


def revoke_att(db: Session, device_sn: str, user_id: str) -> tuple:
    """Queue one person's removal from one `att` terminal: one row,
    :func:`att_user_delete_command`. Returns ``(rows, withdrawn)`` as
    :func:`revoke` does, and keeps the same rule about the link.
    """
    return _queue_revocation(db, device_sn, user_id,
                             [att_user_delete_command(user_id)], "USERINFO")


def _queue_revocation(db: Session, device_sn: str, user_id: str,
                      bodies: list, what: str) -> tuple:
    """Withdraw the contradicting pushes, then queue ``bodies``.

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
    rows = [commands.queue(db, device_sn, body) for body in bodies]
    log.warning(
        "revoking %s from %s: queued command ids %s (%s)%s "
        "— NOT yet revoked at the door; the terminal must collect and "
        "acknowledge these first",
        user_id, device_sn, [r.id for r in rows], what,
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


def _outstanding_role_status(row: DeviceCommandOutbox) -> dict:
    """One outstanding half of a revocation, as it sits in the outbox."""
    return {
        "outstanding": True,
        "state": row.status,  # 'pending' or 'sent' — never anything else here
        "return_code": None,
        "last_error": None,
        "attempts": row.attempts,
        "created_at": row.created_at,
        "sent_at": row.sent_at,
        "concluded_at": None,
        "command": row.command,
    }


def _concluded_role_status(row: DeviceCommandLog) -> dict:
    """One concluded half of a revocation, read off history — never off the
    outbox being empty (E8's gate caught exactly that confusion once)."""
    return {
        "outstanding": False,
        "state": commands.history_verdict(
            row.outcome, row.return_code, row.last_error, row.command,
        ),
        "return_code": row.return_code,
        "last_error": row.last_error,
        "attempts": row.attempts,
        "created_at": row.created_at,
        "sent_at": row.sent_at,
        "concluded_at": row.concluded_at,
        "command": row.command,
    }


def revocation_groups(db: Session, device_sn: str, user_id: str = None) -> list:
    """One entry per revocation this device still owes somebody — grouped by
    the person it names, not by the two commands E8 sends to carry it out
    (E13).

    Only pins with at least one half still outstanding appear at all: that
    matches what the panel has always shown (a fully concluded revocation has
    nothing left to warn about), and keeps this cheap — no unbounded scan of
    history. What changes is that the OTHER half is looked up honestly,
    wherever it actually is, rather than assumed to be in the same state.
    If it already concluded — acknowledged, refused, or cancelled — while its
    sibling is still outstanding, that is reported as a split, not averaged
    away into one tidy card. `still_open` is read straight off
    `device_employees`, the single record of whether the terminal still
    recognises this person (E8) — not inferred from either command's state,
    which is exactly the inference that produced a false "confirmed removal"
    once before.

    An `att` revocation is one command, so it has a `user` half and no
    `userauthorize` half at all; ``has_door_permission`` says so, so that the
    missing half is read as absent by design rather than as a split.
    """
    pins = {}
    att_pins = set()
    for row in outstanding_revocations(db, device_sn, user_id):
        role = "user" if pin_from_revocation_command(row.command) else "userauthorize"
        pin = pin_from_any_delete_command(row.command)
        pins.setdefault(pin, {})[role] = _outstanding_role_status(row)
        if _DELETE_ATT_USER.match(row.command.strip()):
            att_pins.add(pin)

    groups = []
    for pin, roles in pins.items():
        halves = (
            (("user", att_user_delete_command(pin)),) if pin in att_pins else
            (("user", user_delete_command(pin)),
             ("userauthorize", authorize_delete_command(pin)))
        )
        for role, body in halves:
            if role in roles:
                continue
            log_row = (
                db.query(DeviceCommandLog)
                .filter(DeviceCommandLog.device_sn == device_sn,
                        DeviceCommandLog.command == body)
                .order_by(DeviceCommandLog.concluded_at.desc(), DeviceCommandLog.id.desc())
                .first()
            )
            roles[role] = _concluded_role_status(log_row) if log_row else None
        still_open = (
            db.query(DeviceEmployee)
            .filter_by(device_sn=device_sn, user_id=pin)
            .first()
            is not None
        )
        groups.append({
            "device_sn": device_sn,
            "user_id": pin,
            "still_open": still_open,
            "has_door_permission": pin not in att_pins,
            "user": roles.get("user"),
            "userauthorize": roles.get("userauthorize"),
        })
    return groups


# ---------------------------------------------------------------------------
# Taking one fingerprint off an attendance terminal
# ---------------------------------------------------------------------------
#
# Not a revocation of the person, and kept out of everything above that means
# one. The person stays on the terminal and keeps every other finger, so a
# finger delete is not counted, grouped or cancelled as a revocation, does not
# block a push of the person, and its acknowledgement drops no
# `device_employees` link: none of the revocation parsers above match
# `FINGERTMP`. What it does share with a revocation is commands.is_revocation
# (any `DATA DELETE`): until it lands the finger still verifies the person,
# so it is retried on the shorter schedule, and a failure is said at ERROR in
# words about the finger, not the door (commands.conclude).
#
# The `acc` side has no counterpart and refuses one with a 501 (see
# app/routers/devices.py, delete_user_template): the Security PUSH command set
# has no biometric delete. Attendance PUSH has one, §12.1.2.2.


def att_fingerprint_delete_command(user_id, finger_id) -> str:
    """`DATA DELETE FINGERTMP PIN=<s><HT>FID=<n>` — one finger off an `att`
    terminal.

    Attendance PUSH 2.4.1 §12.1.2.2, from the document; not yet observed on
    hardware::

        DATA DELETE FINGERTMP PIN=<s>
        DATA DELETE FINGERTMP PIN=<s><HT>FID=<n>

    ``FID`` is always sent, and that is the point of this function. The
    section says "When only PIN information is transmitted, all fingerprints
    of the user are deleted", so a FID that went missing on the way would
    turn a one-finger delete into every finger the person has. A finger
    outside the document's 0–9 is refused rather than sent, as
    :func:`att_fingerprint_command` refuses one; so is an empty PIN, which
    names nobody.

    ``PIN`` goes out verbatim, as the string it is (`036` and `0036` are two
    people on the SA20).
    """
    pin = _wire_safe(user_id)
    if not pin:
        raise ValueError("no PIN; a fingerprint delete has to name its person")
    if isinstance(finger_id, bool) or finger_id not in ATT_FINGER_IDS:
        raise ValueError(
            f"finger {finger_id} is outside 0-9, the only fingers §12.1.2.2 "
            f"numbers; nothing was queued"
        )
    return f"DATA DELETE FINGERTMP PIN={pin}{HT}FID={int(finger_id)}"


# One finger on the attendance wire, `(PIN, FID)`: the push (§12.1.1.3) and the
# delete (§12.1.2.2) both lead with PIN and then FID. The delete only matches
# with its FID: a PIN-only delete (typed by hand into the command box) takes
# every finger and is not this command, so no single stored finger is
# forgotten on its account.
_FINGER_PUSH = re.compile(
    r"^DATA UPDATE FINGERTMP\s+PIN=([^\t]*)\tFID=(\d+)(?:\t|$)", re.IGNORECASE
)
_FINGER_DELETE = re.compile(
    r"^DATA DELETE FINGERTMP\s+PIN=([^\t]*)\tFID=(\d+)$", re.IGNORECASE
)


def _finger_named_by(pattern, command: str):
    match = pattern.match((command or "").strip())
    if not match or not match.group(1).strip():
        return None
    return match.group(1).strip(), int(match.group(2))


def finger_from_fingerprint_delete(command: str):
    """``(pin, finger_id)`` of a one-finger `DATA DELETE FINGERTMP`, or None."""
    return _finger_named_by(_FINGER_DELETE, command)


def withdraw_fingerprint_push(db: Session, device_sn: str, user_id: str,
                              finger_id: int, reason: str) -> list:
    """Retire a queued `DATA UPDATE FINGERTMP` for this one finger. Returns
    the ids.

    The finger-sized :func:`withdraw_pushes_for`: a queued push and a queued
    delete of the same finger contradict each other, and the outbox is FIFO,
    so the push is concluded ``failed`` with the reason recorded before the
    delete is queued. The person's other fingers and their USERINFO are left
    alone: only this finger was asked about.
    """
    withdrawn = []
    for row in db.query(DeviceCommandOutbox).filter(
        DeviceCommandOutbox.device_sn == device_sn
    ).order_by(DeviceCommandOutbox.id).all():
        if _finger_named_by(_FINGER_PUSH, row.command) != (str(user_id), finger_id):
            continue
        row_id = row.id
        if commands.conclude(db, row, "failed", last_error=reason):
            withdrawn.append(row_id)
            log.warning(
                "withdrew queued fingerprint push %s (finger %s of %s on %s): %s",
                row_id, finger_id, user_id, device_sn, reason,
            )
    return withdrawn


def delete_att_fingerprint(db: Session, device_sn: str, user_id: str,
                           finger_id: int) -> tuple:
    """Queue one finger's removal from one `att` terminal.

    Returns ``(row, withdrawn)``: the outbox row and the ids of any push of
    the same finger retired to make room for it. Raises ValueError, queueing
    nothing, for a finger :func:`att_fingerprint_delete_command` refuses.

    Deletes nothing from `fingerprint_templates`. That happens when the
    terminal confirms (:func:`note_fingerprint_delete_acknowledged`), for the
    reason `device_employees` waits for an acknowledgement: until then the
    finger is still on the terminal, and the stored copy is what would put it
    back if the delete is refused.
    """
    body = att_fingerprint_delete_command(user_id, finger_id)
    withdrawn = withdraw_fingerprint_push(
        db, device_sn, user_id, finger_id,
        reason=f"withdrawn: finger {finger_id} of {user_id} is being deleted "
               f"from {device_sn}",
    )
    row = commands.queue(db, device_sn, body)
    log.info(
        "deleting finger %s of %s from %s: queued command %s%s — not removed "
        "until the terminal acknowledges",
        finger_id, user_id, device_sn, row.id,
        f", withdrew {len(withdrawn)} push(es) of the same finger" if withdrawn else "",
    )
    return row, withdrawn


def note_fingerprint_delete_acknowledged(db: Session, device_sn: str, command: str):
    """The terminal confirmed a one-finger delete: forget the stored finger.

    `fingerprint_templates` is keyed on the person and the finger, not the
    device, so this is the same server-side effect the SDK delete had
    (removed after the device call succeeded): the finger is no longer
    offered to any terminal by a later push. Only on ``Return=0`` — a refused
    or unconfirmed delete leaves the finger on the terminal, and the stored
    copy with it.

    Does not commit — the caller owns the transaction.
    """
    finger = finger_from_fingerprint_delete(command)
    if not finger:
        return False
    user_id, finger_id = finger
    removed = employee_sync.forget_fingerprint(db, user_id, finger_id)
    log.info(
        "device %s acknowledged deleting finger %s of %s%s",
        device_sn, finger_id, user_id,
        "" if removed else " (no stored template for that finger to forget)",
    )
    return removed


# ---------------------------------------------------------------------------
# Enrolling a finger at an attendance terminal, started from here
# ---------------------------------------------------------------------------
#
# The one write in this module that carries no credential. `ENROLL_FP`
# (Attendance PUSH 2.4.1 §12.6.1) tells the terminal to open its own
# enrolment screen for one PIN and one finger; the person has to be standing
# at it when it is collected and press that finger. The reply is a result and
# nothing else (`ID=…&Return=…&CMD=ENROLL_FP`). The template itself comes up
# the way every finger enrolled at that keypad does, as an `FP PIN=…⇥FID=…`
# line on cdata?table=OPERLOG — the handshake's TransFlag=1111000000 has digit
# 4, "Enrolling a new fingerprint", set — which adms._store_operlog files in
# `fingerprint_templates`. So nothing is written on the acknowledgement: the
# upload is the evidence, and it carries the bytes.
#
# Here rather than in devicecontrol.py because it is about a person, not the
# device. It names a PIN the terminal must already hold (Appendix 1's -10,
# "The user specified by PIN does not exist in the equipment"), so it is
# queued behind the person's USERINFO when the terminal has not confirmed
# them, withdrawn behind a refused one (:func:`withdraw_orphaned_templates`),
# and withdrawn with the person's pushes when they are removed
# (:func:`withdraw_pushes_for`) — all rules this module already keeps for a
# FINGERTMP push.
#
# Its replies are judged in commands.verdict_for: Appendix 1 gives
# ENROLL_FP failures that are POSITIVE (2, 4, 5, 6, 7), which no other
# command here has.

# §12.6.1: "RETRY: Number of retries required if enrollment fails". The value
# §12.6.2 prints in its own example (`ENROLL_MF PIN=408\tRETRY=3`): a few
# chances for a person with a hard-to-read finger, bounded so that a terminal
# which collects the command when nobody is at it gives up and goes back to
# taking attendance.
ATT_ENROL_RETRY = 3

# §12.6.1: "0 means the fingerprint of corresponding user exists and will not
# be overwritten and error information is returned. 1 means … will be
# overwritten." Never overwrite. A finger the terminal already holds is
# answered with Appendix 1's 2 and the operator deletes it first (DATA DELETE
# FINGERTMP, which also forgets the stored copy on its ack). Overwriting in
# place would replace the finger as a *change*, not an enrolment — and the
# handshake's TransFlag has digit 8, "Changing a fingerprint", at 0, so the
# new template might never be uploaded, leaving `fingerprint_templates`
# holding the old one to push to every other terminal.
ATT_ENROL_OVERWRITE = 0


def att_fingerprint_enrol_command(user_id, finger_id) -> str:
    """`ENROLL_FP PIN=<s><HT>FID=<n><HT>RETRY=<n><HT>OVERWRITE=<n>` — start
    enrolling one finger at an `att` terminal.

    Attendance PUSH 2.4.1 §12.6.1, from the document; not yet observed on
    hardware::

        ENROLL_FP PIN=<s><HT>FID=<n><HT>RETRY=<n><HT>OVERWRITE=<n>

    ``PIN`` goes out verbatim, as the string it is (`036` and `0036` are two
    people on the SA20); an empty one names nobody and is refused. ``FID`` is
    refused outside 0–9, the fingers §12.1.1.3 and §12.1.2.2 number — §12.6.1
    gives no range of its own, and a finger this application cannot store or
    push again is not one to enrol. ``RETRY`` and ``OVERWRITE`` are
    :data:`ATT_ENROL_RETRY` and :data:`ATT_ENROL_OVERWRITE`.
    """
    pin = _wire_safe(user_id)
    if not pin:
        raise ValueError("no PIN; an enrolment has to name its person")
    if isinstance(finger_id, bool) or finger_id not in ATT_FINGER_IDS:
        raise ValueError(
            f"finger {finger_id} is outside 0-9, the only fingers the "
            f"Attendance PUSH document numbers; nothing was queued"
        )
    return (
        "ENROLL_FP "
        + HT.join([
            f"PIN={pin}",
            f"FID={int(finger_id)}",
            f"RETRY={ATT_ENROL_RETRY}",
            f"OVERWRITE={ATT_ENROL_OVERWRITE}",
        ])
    )


_ENROLMENT_PIN = re.compile(r"^ENROLL_FP\s+PIN=([^\t]*)", re.IGNORECASE)


def pin_from_enrolment_command(command: str):
    """The PIN in an `ENROLL_FP` command, or None if it is not one."""
    match = _ENROLMENT_PIN.match((command or "").strip())
    if not match:
        return None
    return match.group(1).strip() or None


def enrol_att_fingerprint(db: Session, device_sn: str, user_id: str,
                          finger_id: int, employee: Employee = None) -> list:
    """Queue a remote enrolment of one finger at one `att` terminal. Returns
    the outbox rows.

    ``employee`` is passed when the terminal has not confirmed the person
    (:func:`is_on_device`): their USERINFO (:func:`provision_att`) is queued
    first, so the FIFO outbox hands the terminal the person before the
    enrolment, as :func:`push_templates` does for a template. Raises
    ValueError, queueing nothing, for what
    :func:`att_fingerprint_enrol_command` refuses.
    """
    body = att_fingerprint_enrol_command(user_id, finger_id)
    rows = provision_att(db, device_sn, employee) if employee is not None else []
    rows.append(commands.queue(db, device_sn, body))
    log.info(
        "enrolling finger %s of %s at %s: queued command id(s) %s%s — the "
        "person must be at the terminal when it collects it",
        finger_id, user_id, device_sn, [r.id for r in rows],
        " (behind the user record, which the device has not confirmed yet)"
        if employee is not None else "",
    )
    return rows


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


# The `att` side: one query, people and fingerprints together.
#
# Attendance PUSH 2.4.1 §12.1.3 documents only `DATA QUERY USERINFO PIN=<pin>`.
# Sent with no PIN, it returns every user. Field-confirmed on BioPro SA20
# CPV2232560497 (pushver 2.4.1), 2026-10-19: Return=0, then 459 `USER` and
# 479 `FP` lines uploaded on `cdata?table=OPERLOG`, the exact counts the
# terminal reports in its own `INFO=` line. The fingerprints come with the
# users unasked, so there is no second query for templates. Attendance is
# not asked for either: these terminals push every punch as ATTLOG.
QUERY_ATT_USERS = "DATA QUERY USERINFO"

# Every punch an `att` terminal still holds (§12.1.3). The device re-uploads
# them as ordinary `cdata?table=ATTLOG` pushes, which `_store_attlog` already
# stores and de-duplicates on (device, user, timestamp), so asking again is
# harmless. Live pushes alone are not enough: the SA20 reported 62,501 stored
# records but only uploads what is punched after it is pointed here. The range
# is wide on purpose — the times are the device's wall clock, so a range that
# covers every year needs no timezone arithmetic. The separator is a TAB.
QUERY_ATT_ATTENDANCE = (
    "DATA QUERY ATTLOG StartTime=2000-01-01 00:00:00\tEndTime=2099-12-31 23:59:59"
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


def query_att_users(db: Session, device_sn: str) -> tuple:
    """Ask an `att` terminal for its users and fingerprints — one query."""
    return queue_query(db, device_sn, QUERY_ATT_USERS)


def query_att_attendance(db: Session, device_sn: str) -> tuple:
    """Ask an `att` terminal to re-upload every punch it holds."""
    return queue_query(db, device_sn, QUERY_ATT_ATTENDANCE)


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
