"""Delivery of commands to a device, and the record of what became of them.

This is the *only* command delivery mechanism in the app. Anything that wants
a device to do something calls :func:`queue` and, later, reads the outcome —
nothing re-implements dispatch, retry or acknowledgement.

The shape of the problem
------------------------
A ZKTeco terminal on the ADMS/PUSH protocol is never dialled; it dials us. It
polls ``GET /iclock/getrequest`` every few seconds and we answer with the work
we have for it, formatted ``C:<id>:<command>``. Some seconds later it reports
what happened with ``POST /iclock/devicecmd`` carrying
``ID=<id>&Return=<code>&CMD=<name>``. There is no other channel, no way to ask,
and no error at push time — queueing always succeeds, so the *only* signal
that a delivery failed is an acknowledgement that never comes.

Two tables, and why
-------------------
``device_command_outbox`` holds outstanding work and nothing else; a row is
there if and only if the command is still owed to a device. ``getrequest``
scans only this, so the per-poll cost never grows with history.
``device_command_log`` is append-only history of concluded commands.

Concluding a command is a *move*: one transaction writes the log row and
deletes the outbox row, so a command is never both outstanding and concluded,
and never neither. :func:`conclude` is the single place that transition
happens.

The distinction this module exists to keep straight
---------------------------------------------------
**Offline is not failure.** A command sitting ``pending`` because the device
has not polled has attempts=0, no ``next_attempt_at``, and is failing at
nothing — it is the queue working exactly as intended. This is the behaviour
that recovered a weekend of missed punches for the operator, and it must
survive. The attempt counter and the backoff apply *only* to a command that
was actually handed to a device and never acknowledged.

A device that is switched off all weekend must come back to its queue intact,
not to a pile of failures it never had a chance to attempt.

**A ``Return`` code is read three ways, not two.** This module used to say
"``0`` is success, anything else is a refusal". Hardware disproved the second
half — see :func:`verdict_for`. A code we cannot read is now concluded, and
recorded, without being called either a success or a refusal. Only silence is
retried.
"""

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import config
from app.models import DeviceCommandLog, DeviceCommandOutbox

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Callers hand us the command body ("DATA UPDATE user Pin=1<HT>..."); the
# ``C:<id>:`` envelope is ours to add at dispatch, because the id in it is what
# the device quotes back to identify the command. If something passes a command
# that already carries an envelope we strip it rather than nesting a second
# one, which would leave the device reporting an id we have never issued.
_WIRE_ENVELOPE = re.compile(r"^C:\d+:")


def strip_envelope(command: str) -> str:
    """``'C:7:DATA UPDATE user …'`` → ``'DATA UPDATE user …'``; else unchanged."""
    return _WIRE_ENVELOPE.sub("", command.strip(), count=1)


def wire_line(row: DeviceCommandOutbox) -> str:
    """The exact bytes handed to the device for one command (§3.8)."""
    return f"C:{row.id}:{row.command}"


# A command that takes access away rather than granting it (E8). Matched on
# the wire text rather than a column so no schema change is needed and so a
# command queued by hand through POST /devices/{sn}/commands gets the same
# treatment as one this application built.
_REVOCATION = re.compile(r"^DATA DELETE\b", re.IGNORECASE)


def is_revocation(command: str) -> bool:
    """True for `DATA DELETE …` — the commands that take access away.

    Used for two things and nothing else: a shorter retry schedule, and a
    louder log line when one is given up on. Both exist because while a
    revocation is outstanding the person it names can still open the door.
    """
    return bool(_REVOCATION.match((command or "").strip()))


def backoff_for(attempts: int, command: str = None) -> timedelta:
    """How long to wait after ``attempts`` deliveries before offering again.

    The schedule is a list, one entry per attempt, and the final entry repeats
    once attempts outrun it — so the wait is bounded however the two settings
    are combined.

    A revocation gets its own, much shorter schedule
    (config.REVOCATION_BACKOFF_SECONDS): every other command in this system
    can afford to wait, and a delete cannot, because the wait is time during
    which somebody who should have lost access still has it.
    """
    schedule = (
        config.REVOCATION_BACKOFF_SECONDS if is_revocation(command)
        else config.COMMAND_BACKOFF_SECONDS
    )
    index = min(max(attempts, 1), len(schedule)) - 1
    return timedelta(seconds=schedule[index])


# ---------------------------------------------------------------------------
# What a `Return=<code>` actually tells us  (E11)
# ---------------------------------------------------------------------------

SUCCESS = "success"          # the device did the thing
REFUSAL = "refusal"          # the device would not do the thing
UNREADABLE = "unreadable"    # the device said something we cannot interpret


# `DATA QUERY` is the one command type whose acknowledgement we have actually
# watched real hardware produce, and it turned out not to answer with a status
# at all. Matched loosely on purpose: this has to recognise both the device's
# own `CMD=DATA QUERY` field and the full command text we queued
# (`DATA QUERY tablename=user,fielddesc=*,filter=*`).
_DATA_QUERY = re.compile(r"^\s*DATA\s+QUERY\b", re.IGNORECASE)


def is_query(command_name: str) -> bool:
    """True for a ``DATA QUERY``, from either a ``CMD=`` field or a command."""
    return bool(_DATA_QUERY.match(command_name or ""))


def verdict_for(return_code, command_name: str = "") -> str:
    """Read one ``Return=`` code. Returns SUCCESS, REFUSAL or UNREADABLE.

    The single owner of that judgement. It needs ``command_name`` because
    **``Return`` does not mean the same thing for every command**, which is the
    finding this whole function exists to encode.

    `DATA QUERY`: ``Return`` is a RECORD COUNT
    ------------------------------------------
    Field-confirmed on BioFace A1 ``VGU6254600603``, 2026-08-21, four completed
    queries:

        cmdid 1   user      3 records stored   ID=1&Return=3&CMD=DATA QUERY
        cmdid 2   biophoto  3 photos stored    ID=2&Return=3&CMD=DATA QUERY
        cmdid 3   biodata   6 records stored   ID=3&Return=6&CMD=DATA QUERY
        cmdid 4   biodata   6 records stored   ID=4&Return=6&CMD=DATA QUERY

    ``Return`` tracked the number of records the query produced, exactly,
    across three tables and two distinct counts. It was never a status. ``3``
    never meant "success" — it meant "three records", and the reason this
    firmware has never sent ``Return=0`` is simply that no query has yet
    matched nothing.

    So for a query, **any count is a success, including zero**. ``Return=0``
    means the query ran and matched no records — a real, correct, useful
    answer, and the one value the old rule would have got right for entirely
    the wrong reason. A *negative* value cannot be a count at all; there is no
    evidence for what it would be, so it is read as a refusal, which is the
    pessimistic direction.

`DATA UPDATE`: ``Return`` is a status, and ``0`` is success
    -----------------------------------------------------------
    Also field-confirmed, same terminal, 2026-08-21 10:18:55–10:18:56, the
    first provisioning ever acknowledged by this deployment's hardware:

        cmdid 5   DATA UPDATE user Pin=4 …          ID=5&Return=0&CMD=DATA UPDATE
        cmdid 6   DATA UPDATE userauthorize Pin=4   ID=6&Return=0&CMD=DATA UPDATE

    Both succeeded, both answered ``0``, matching the vendor's own example in
    push-protocol.md §3.8 (``ID=295&Return=0&CMD=DATA UPDATE``). So it is now
    observation, not documentation.

    Which settles the shape of the problem: **the same wire field carries a
    record count for one verb and a status for another.** ``Return=0`` means
    "matched nothing, successfully" on a query and "did it" on an update; the
    two readings cannot be reconciled under a single rule, and that is exactly
    why the old single rule had to be wrong about one of them.

    ``0``              SUCCESS.     Observed, and documented.
    negative           REFUSAL.     Observed; see below.
    any other non-zero UNREADABLE.  Never observed on an update. Not claimed.

    No non-zero ``DATA UPDATE`` acknowledgement has been seen, so a positive
    code on one is still genuinely unknown — it could be a status this firmware
    uses for a partial result, or a count after all. It is concluded, recorded
    and surfaced, and it is claimed as neither success nor refusal. That is the
    safe way to be wrong: a missed alarm is worse than a spurious one on a
    door, so an unconfirmed revocation still shouts.

    The negative branch is no longer an inference. It was one until
    2026-08-21 11:06:06, when the operator deliberately queued a command the
    terminal could not satisfy — a query against a table that does not exist —
    to find out what a refusal actually looks like:

        cmdid 9   DATA QUERY tablename=nosuchtable,fielddesc=*,filter=*
                  ID=9&Return=-629&CMD=DATA QUERY

    So vendor error codes on this firmware *are* negative, and ``-629`` is a
    real one. The rule was already pointing the right way; it is now pointing
    that way for a reason rather than out of caution, and the behaviour E4, E8
    and E10 build on refusals rests on evidence.

    ``DATA DELETE``: status, and ``0`` is success — also confirmed
    --------------------------------------------------------------
    Same terminal, 2026-08-21 10:23:25–10:23:26, a real revocation of a real
    person from a real door:

        cmdid 7   DATA DELETE user Pin=4          ID=7&Return=0&CMD=DATA DELETE
        cmdid 8   DATA DELETE userauthorize Pin=4 ID=8&Return=0&CMD=DATA DELETE

    Both succeeded, both answered ``0``, and E8's link-drop and
    "revoked and confirmed at the door" both fired correctly. This was an
    inference from the verb family until that capture; it is now observation.

    Which means **every command family this codebase actually emits is now
    evidenced**: query, update, delete. The UNREADABLE branch is no longer a
    standing fallback for anything we routinely send — it is reserved for what
    remains genuinely unobserved: a non-zero code on an update or a delete
    (never seen), and any other verb (``DATA COUNT``, or whatever an operator
    types by hand into the command box).

    That reservation still matters, and it points at the door. If a terminal
    ever answers a ``DATA DELETE`` with a count-like number, this rule reads it
    as UNREADABLE, the revocation is concluded unconfirmed, and ACCESS NOT
    REVOKED fires. Spurious, and the right way round.
    """
    if return_code is None:
        return UNREADABLE

    if is_query(command_name):
        return SUCCESS if return_code >= 0 else REFUSAL

    if return_code == 0:
        return SUCCESS
    if return_code < 0:
        return REFUSAL
    return UNREADABLE


def record_count(return_code, command_name: str = ""):
    """The number of records a ``DATA QUERY`` reported, or ``None``.

    Only meaningful for a query, where ``Return`` *is* the count (see
    :func:`verdict_for`). For anything else the number is a status of some
    kind and calling it a count would be an invention.
    """
    if return_code is None or not is_query(command_name) or return_code < 0:
        return None
    return return_code


# How a concluded command should be *described* — one owner for the wording the
# API and the UI both use, so a history row cannot be labelled a refusal in one
# place and something else in the other.
def history_verdict(outcome: str, return_code=None, last_error: str = None,
                    command: str = "") -> str:
    """``acknowledged`` | ``refused`` | ``unconfirmed`` | ``cancelled`` | ``abandoned``."""
    if outcome == "acknowledged":
        return "acknowledged"
    if return_code is not None:
        verdict = verdict_for(return_code, command)
        if verdict == REFUSAL:
            return "refused"
        # A SUCCESS code on a row concluded `failed` cannot happen through
        # acknowledge(), but history is long-lived and the honest label for a
        # code we are not calling a refusal is "unconfirmed", never "refused".
        return "unconfirmed"
    if (last_error or "").startswith("cancelled by"):
        return "cancelled"
    return "abandoned"


def history_detail(outcome: str, return_code=None, command: str = ""):
    """The extra clause a history label carries, or ``None``.

    Exists so an operator reading E10's history sees what the device actually
    told us. For a query that is a record count — and "no records matched" is
    a real operational answer worth showing, not an absence.
    """
    if outcome != "acknowledged":
        return None
    count = record_count(return_code, command)
    if count is None:
        return None
    return "no records matched" if count == 0 else (
        f"{count} record{'s' if count != 1 else ''}"
    )


# ---------------------------------------------------------------------------
# Queueing
# ---------------------------------------------------------------------------

def queue(db: Session, device_sn: str, command: str,
          ttl_seconds: int = None) -> DeviceCommandOutbox:
    """Put one command in the outbox for a device. Delivered on its next poll.

    Deliberately does not care whether the device is reachable, approved or
    even switched on: queueing is not delivery, and a device that is offline
    right now is the ordinary case, not an error.

    ``ttl_seconds`` sets a hard deadline after which the command must never be
    delivered. It is None for everything except door control (E15), and None
    keeps the queue's original patience: wait as long as the device takes.
    Pass it only where arriving late is worse than not arriving — see
    ``config.DOOR_COMMAND_TTL_SECONDS``.
    """
    created = _now()
    row = DeviceCommandOutbox(
        device_sn=device_sn,
        command=strip_envelope(command),
        status="pending",
        attempts=0,
        created_at=created,
        expires_at=(created + timedelta(seconds=ttl_seconds)
                    if ttl_seconds else None),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log.info("command %s queued for %s: %s", row.id, device_sn, row.command[:120])
    return row


# ---------------------------------------------------------------------------
# The atomic move: outbox row -> log row
# ---------------------------------------------------------------------------

def conclude(
    db: Session,
    row: DeviceCommandOutbox,
    outcome: str,
    return_code=None,
    last_error=None,
) -> bool:
    """Move one command out of the outbox and into history, in one transaction.

    Returns True if this call is the one that concluded it, False if something
    else got there first.

    The DELETE is the arbiter, not the preceding read: its row count decides
    whether the log row is written at all. Two acknowledgements racing for the
    same command therefore produce exactly one log row, and a command can never
    be left both outstanding and concluded — the two statements commit
    together or not at all.
    """
    # Snapshot first. Once the DELETE has run, the row is gone from the
    # database, and any attribute the ORM has to reload from it raises
    # ObjectDeletedError — including on a perfectly ordinary path, because
    # SQLAlchemy expires loaded attributes on every commit.
    snapshot = dict(
        device_sn=row.device_sn,
        command=row.command,
        attempts=row.attempts,
        created_at=row.created_at,
        sent_at=row.sent_at,
    )
    row_id = row.id
    # The outbox id travels into history with the row (E11). Without it a
    # later acknowledgement quoting that id is indistinguishable from an id we
    # never issued, and the only honest thing to say about either is a
    # WARNING — which is how a device's perfectly normal second ack for a
    # DATA QUERY came to log one on every successful command.
    snapshot["outbox_id"] = row_id

    deleted = (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.id == row_id)
        .delete(synchronize_session=False)
    )
    if deleted != 1:
        db.rollback()
        log.warning("command %s was already concluded elsewhere — no second log row", row_id)
        return False

    db.add(DeviceCommandLog(
        outcome=outcome,
        return_code=return_code,
        last_error=(str(last_error)[:255] if last_error else None),
        concluded_at=_now(),
        **snapshot,
    ))
    db.commit()

    # A revocation that did not land is not an ordinary failed command: the
    # operator asked for somebody's access to be taken away and it was not.
    # Said at ERROR, naming the door and the person's Pin, because this is the
    # line somebody reads at 2am asking "can they still get in".
    if outcome == "failed" and is_revocation(snapshot["command"]):
        # Deliberately fires for an UNREADABLE code too, and says so precisely.
        # "The device answered with something we cannot read" is not evidence
        # the door was closed, and an unconfirmed revocation is exactly what
        # this line exists to shout about.
        if return_code is None:
            reason = last_error or "no acknowledgement"
        elif verdict_for(return_code, snapshot["command"]) == REFUSAL:
            reason = f"refused it with Return={return_code}"
        else:
            reason = (
                f"answered Return={return_code}, which this system cannot read "
                "as either success or refusal"
            )
        log.error(
            "ACCESS NOT REVOKED: %s never confirmed %r (%s). That person may "
            "still be able to open this door — check the terminal directly.",
            snapshot["device_sn"], snapshot["command"][:120], reason,
        )
    return True


# ---------------------------------------------------------------------------
# Operator control — cancel and retry (E10)
# ---------------------------------------------------------------------------

def cancel(db: Session, row: DeviceCommandOutbox, by: str) -> bool:
    """Withdraw one outstanding command from the outbox, by operator request.

    Concluded ``failed`` rather than deleted outright — same move as an
    unacknowledged command running out of attempts — so the log row is where
    an operator later finds out this happened, when and why.

    What "cancel" actually means depends on ``row.status``, and the two cases
    are not the same claim:

    * ``pending`` — never handed to the device. Cancelling here is the whole
      truth: nothing was sent, there is nothing at the device end to undo.
    * ``sent`` — handed to the device at least once already. The device may
      already have collected and acted on it before this call landed;
      cancelling only removes *our record* of owing it. For a
      ``DATA DELETE`` this is the difference between access still being
      revoked at the door and access quietly being restored — the caller
      (the router, then the UI) must say so and never imply the delivery
      itself was recalled, which is the false-reassurance mistake E8's
      browser gate caught in a different shape.
    """
    was_sent = row.status == "sent"
    last_error = (
        f"cancelled by {by} — already delivered to the device at least once "
        "before this cancellation; the device may already have acted on it, "
        "only our record of owing it was removed"
        if was_sent else
        f"cancelled by {by} before delivery — never sent to the device"
    )
    return conclude(db, row, "failed", last_error=last_error)


def retry(db: Session, log_row: DeviceCommandLog) -> DeviceCommandOutbox:
    """Requeue a concluded command as a brand-new outbox row.

    Decision: **copy, don't resurrect.** ``log_row`` is left exactly as it
    was concluded — the record of what happened the first time is never
    edited — and a fresh ``device_command_outbox`` row starts its own
    lifecycle at ``attempts=0``. Two independent rows means two independent
    outcomes stay visible: a retry that also fails does not overwrite what
    the first attempt showed, and a retry that succeeds sits next to the
    refusal it followed rather than erasing it.

    Does not judge whether retrying is wise. A device refusal
    (``return_code`` not null) will very likely earn the identical refusal
    again, since nothing about the device changed — the warning is the
    caller's job (the retry endpoint's response, and the UI), not this
    function's. It only ever does what it is asked.
    """
    return queue(db, log_row.device_sn, log_row.command)


# ---------------------------------------------------------------------------
# Dispatch — the /iclock/getrequest hot path
# ---------------------------------------------------------------------------

def _eligible(db: Session, device_sn: str, now: datetime):
    """Outstanding commands this device may be given right now, oldest first.

    Either never delivered, or delivered and past its retry time. A command
    that was sent and is still inside its backoff window is deliberately
    invisible here — that is the whole point of the backoff.

    A command past its ``expires_at`` is invisible here too, and that is the
    stronger rule: it is not offered to the device however long the device has
    been away. Only door commands carry a deadline (E15), and for those,
    delivering late is the failure being prevented. The expired row is left
    for the sweep to conclude — this function is on the getrequest hot path
    and does not write.
    """
    return (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.device_sn == device_sn)
        .filter(
            or_(
                DeviceCommandOutbox.expires_at.is_(None),
                DeviceCommandOutbox.expires_at > now,
            )
        )
        .filter(
            or_(
                DeviceCommandOutbox.status == "pending",
                DeviceCommandOutbox.next_attempt_at <= now,
            )
        )
        .order_by(DeviceCommandOutbox.created_at, DeviceCommandOutbox.id)
        .all()
    )


def next_commands(db: Session, device_sn: str, limit: int = None, now: datetime = None) -> list:
    """Hand this device its next commands, marking each as delivered.

    Returns the wire lines to send, oldest first. Empty list means there is
    nothing owed — which the caller answers with "OK", the idle heartbeat.

    A candidate that has already used its attempts is concluded ``failed``
    here rather than handed out again: the device came back, we had nothing
    left to try, and pretending otherwise would loop forever.
    """
    now = now or _now()
    limit = config.COMMAND_BATCH_SIZE if limit is None else limit

    # Two passes on purpose. conclude() owns its own transaction, so retiring
    # the exhausted rows must finish before any attempt counter is touched —
    # otherwise a rollback inside conclude() could discard a half-applied
    # dispatch from the same loop.
    live = []
    for row in _eligible(db, device_sn, now):
        if row.attempts < config.COMMAND_MAX_ATTEMPTS:
            live.append(row)
            continue
        # Read before concluding: the move deletes the row, after which the
        # ORM cannot refresh these attributes.
        row_id, attempts = row.id, row.attempts
        conclude(
            db, row, "failed",
            last_error=(
                f"no acknowledgement after {attempts} "
                f"attempt{'s' if attempts != 1 else ''}"
            ),
        )
        log.warning(
            "command %s for %s failed: %s deliveries, never acknowledged",
            row_id, device_sn, attempts,
        )

    lines = []
    for row in live[:limit]:
        row.attempts += 1
        row.status = "sent"
        row.sent_at = now
        row.next_attempt_at = now + backoff_for(row.attempts, row.command)
        lines.append(wire_line(row))

    db.commit()
    if lines:
        log.info("handed %s command(s) to %s: %s", len(lines), device_sn, lines)
    return lines


# ---------------------------------------------------------------------------
# Acknowledgement — the /iclock/devicecmd path
# ---------------------------------------------------------------------------

def acknowledge(
    db: Session,
    device_sn: str,
    command_id: int,
    return_code: int,
    command_name: str = "",
    source: str = "devicecmd",
    known_verdict: str = None,
) -> str:
    """Record what the device reported about one specific command.

    The verdict on ``return_code`` belongs to :func:`verdict_for`, which is
    three-way — success, refusal, or *unreadable* — and carries the evidence
    for each branch. Read it before changing anything here.

    Returns one word, which is both the caller's log line and the caller's
    permission to act:

    ``acknowledged``  the device confirmed it. Act on success.
    ``rejected``      the device refused it. Act on failure.
    ``unconfirmed``   the device answered with a code we cannot read. Concluded
                      — the device has replied, so there is nothing to wait for
                      — but act on **neither** outcome. This is the branch that
                      exists so a successful command is never called a refusal
                      and a refused one is never called a success.
    ``informational`` an acknowledgement for a command already concluded. The
                      outcome was decided by better evidence; nothing changes.
    ``unknown``       an id never issued to this serial. Nothing touched.
    ``duplicate``     lost the race to conclude; another ack got there first.

    Never raises and never refuses the request — a device that cannot deliver
    its ack will keep retrying the whole command, which is worse than a lost
    outcome.

    ``source`` names the endpoint the report arrived on, for the log only.
    There are two, and a ``DATA QUERY`` uses **both** (E11, field-confirmed):
    ``/iclock/querydata`` carries the payload and arrives first, then
    ``/iclock/devicecmd`` follows about half a second later with a code. E9
    read §3.13 as saying querydata was the only ack for a query; hardware says
    it is the first of two. The second one lands here on an already-concluded
    command, which is ordinary and expected, and is reported as such.
    """
    row = (
        db.query(DeviceCommandOutbox)
        .filter(
            DeviceCommandOutbox.id == command_id,
            DeviceCommandOutbox.device_sn == device_sn,
        )
        .first()
    )

    if row is None:
        # Nothing outstanding under that id. Two very different situations,
        # and telling them apart is the whole point of this branch — see
        # _report_on_concluded. Neither one touches another command:
        # acknowledging whatever happened to be nearby is the bug this
        # function exists to fix.
        return _report_on_concluded(
            db, device_sn, command_id, return_code, command_name, source,
        )

    # `known_verdict` is for a caller holding better evidence than any code.
    # /iclock/querydata is the only one: the device answers a DATA QUERY by
    # uploading the data, and the arrival of the payload is the proof — there
    # is no `Return=` field on that request to read. It passes SUCCESS and a
    # null code rather than a synthetic zero, because now that `Return` on a
    # query is known to be a record count, storing 0 there would claim the
    # query matched nothing, which for a payload we just parsed is false.
    verdict = known_verdict or verdict_for(return_code, command_name)

    if verdict == SUCCESS:
        moved = conclude(db, row, "acknowledged", return_code=return_code)
        if moved:
            log.info("command %s acknowledged by %s", command_id, device_sn)
        return "acknowledged" if moved else "duplicate"

    if verdict == REFUSAL:
        moved = conclude(
            db, row, "failed",
            return_code=return_code,
            last_error=f"device refused the command with Return={return_code}",
        )
        if moved:
            log.warning(
                "command %s refused by %s with Return=%s (%r) — not retried, a "
                "refusal is permanent",
                command_id, device_sn, return_code, command_name,
            )
        return "rejected" if moved else "duplicate"

    # UNREADABLE. The device answered, so the command is over — re-sending it
    # has no reason to earn a different answer, and leaving it outstanding
    # would eventually record "no acknowledgement", which is simply false.
    # It is concluded `failed` because `failed` is this ledger's word for "not
    # confirmed done", and because that is the direction that keeps a
    # revocation shouting. What it is NOT is a refusal, and nothing downstream
    # is told it was one.
    moved = conclude(
        db, row, "failed",
        return_code=return_code,
        last_error=(
            f"device answered Return={return_code}, which this system cannot "
            f"read as success or refusal — treated as unconfirmed, not refused"
        ),
    )
    if moved:
        log.warning(
            "command %s: %s answered Return=%s (%r), a code this system cannot "
            "interpret. NOT recorded as a refusal and NOT recorded as a "
            "success — the command is concluded unconfirmed. If you can see at "
            "the terminal whether this actually worked, that observation is "
            "what settles what Return=%s means.",
            command_id, device_sn, return_code, command_name, return_code,
        )
    return "unconfirmed" if moved else "duplicate"


def _report_on_concluded(
    db: Session,
    device_sn: str,
    command_id: int,
    return_code,
    command_name: str,
    source: str,
) -> str:
    """An acknowledgement arrived for a command that is not outstanding.

    Two cases, and they deserve very different volumes:

    * **We concluded it already.** The ordinary case for a ``DATA QUERY``,
      whose second acknowledgement always lands here (E11), and for a device
      re-sending an ack it thinks we missed. The outcome was decided by better
      evidence — the payload itself, for a query — so this changes nothing and
      is said at INFO. A WARNING here fires on every single successful query,
      and a warning that fires on the normal path teaches an operator to stop
      reading warnings, which is expensive in a codebase that uses WARNING for
      things that genuinely matter.

    * **We never issued that id to this serial.** Still a WARNING: it means a
      device is quoting an id we have no record of, and that is worth a look.

    Told apart by ``device_command_log.outbox_id``. A history row written
    before that column existed has none, so an ack for one of those falls
    through to the WARNING — rare, self-correcting, and better than guessing.
    """
    prior = (
        db.query(DeviceCommandLog)
        .filter(
            DeviceCommandLog.outbox_id == command_id,
            DeviceCommandLog.device_sn == device_sn,
        )
        .order_by(DeviceCommandLog.id.desc())
        .first()
    )

    if prior is None:
        log.warning(
            "%s from %s reported ID=%s Return=%s CMD=%r, which is not "
            "outstanding for that serial and matches no command we concluded "
            "— no other command was touched",
            source, device_sn, command_id, return_code, command_name,
        )
        return "unknown"

    # One exception to the quiet: the device is reporting a refusal for
    # something we already wrote down as done. Both cannot be true, and the
    # optimistic half is the one already recorded, so say so — without
    # rewriting history, which conclude() owns and which is settled.
    if (prior.outcome == "acknowledged"
            and verdict_for(return_code, command_name) == REFUSAL):
        log.warning(
            "%s from %s reported ID=%s Return=%s CMD=%r, but that command was "
            "already concluded ACKNOWLEDGED at %s. The device is contradicting "
            "the evidence we concluded on — history is left as it stands, but "
            "this one is worth checking at the terminal.",
            source, device_sn, command_id, return_code, command_name,
            prior.concluded_at,
        )
        return "informational"

    log.info(
        "%s from %s reported ID=%s Return=%s CMD=%r for a command already "
        "concluded %s at %s — recorded, nothing re-decided",
        source, device_sn, command_id, return_code, command_name,
        prior.outcome, prior.concluded_at,
    )
    return "informational"


# ---------------------------------------------------------------------------
# The scheduled sweep
# ---------------------------------------------------------------------------

def sweep(db: Session, now: datetime = None) -> dict:
    """Periodic maintenance: give up on the hopeless, prune old history.

    Runs on the app's existing APScheduler (see app/main.py), infrequently —
    none of this is on a request path.

    Four jobs, in the order they matter:

    1. **Exhausted deliveries.** A command handed to a device the maximum
       number of times, whose last retry window has passed, is concluded
       failed. ``getrequest`` does this too, on the next poll; this covers the
       device that stopped polling part-way through its retries, so the
       failure surfaces on a timer instead of waiting for a device that may
       never return.

    1b. **Door deadlines (E15).** A door command past its ``expires_at`` is
       concluded failed and never offered again. `_eligible` already refuses
       to hand it out; this is what turns that silence into a visible outcome
       saying the door did not open.

    2. **Absolute expiry.** An outstanding command older than
       COMMAND_PENDING_EXPIRY_DAYS is abandoned regardless of status. This is
       the answer to "queued weeks ago for a terminal that was decommissioned",
       and it is deliberately a *separate, much longer* clock from the retry
       count: a month of being offline expires a command, a weekend does not.

    3. **History retention.** Prune device_command_log past its retention.
       Only concluded rows are ever pruned — the outbox is never touched by
       cleanup, because everything in it is live work.

    Note what is *not* here: nothing ages out a pending command for merely
    being undelivered. That is the queue working.
    """
    now = now or _now()
    result = {"exhausted": 0, "door_expired": 0, "expired": 0, "pruned": 0}

    # 1. Delivered the maximum number of times, retry window elapsed, silent.
    exhausted = (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.status == "sent")
        .filter(DeviceCommandOutbox.attempts >= config.COMMAND_MAX_ATTEMPTS)
        .filter(DeviceCommandOutbox.next_attempt_at <= now)
        .all()
    )
    for row in exhausted:
        if conclude(
            db, row, "failed",
            last_error=(
                f"no acknowledgement after {row.attempts} "
                f"attempt{'s' if row.attempts != 1 else ''}"
            ),
        ):
            result["exhausted"] += 1

    # 1b. Door commands past their short deadline (E15). Concluded failed with
    # a reason that says the door did NOT open, which is the only thing the
    # operator actually needs to know. Kept separate from the absolute expiry
    # below because the two answer different questions on wildly different
    # clocks — a minute versus a month — and because collapsing them would let
    # a future change to the long one silently lengthen the short one.
    for row in (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.expires_at.isnot(None))
        .filter(DeviceCommandOutbox.expires_at <= now)
        .all()
    ):
        row_id, sn, attempts = row.id, row.device_sn, row.attempts
        if conclude(
            db, row, "failed",
            last_error=(
                "expired before the device collected it — the door was not "
                "opened"
                if attempts == 0 else
                f"expired after {attempts} delivery"
                f"{'' if attempts == 1 else 'ies'} without an acknowledgement "
                "— it is not known whether the door opened"
            ),
        ):
            result["door_expired"] += 1
            log.warning(
                "door command %s for %s expired after %s delivery attempt(s) "
                "— not retried and not delivered again",
                row_id, sn, attempts,
            )

    # 2. Outstanding too long in absolute terms, whatever its status.
    if config.COMMAND_PENDING_EXPIRY_DAYS > 0:
        cutoff = now - timedelta(days=config.COMMAND_PENDING_EXPIRY_DAYS)
        for row in (
            db.query(DeviceCommandOutbox)
            .filter(DeviceCommandOutbox.created_at < cutoff)
            .all()
        ):
            never_tried = row.attempts == 0
            if conclude(
                db, row, "failed",
                last_error=(
                    f"abandoned after {config.COMMAND_PENDING_EXPIRY_DAYS} days "
                    + ("without the device ever polling" if never_tried
                       else "still outstanding")
                ),
            ):
                result["expired"] += 1

    # 3. History past its retention. Concluded rows only, by construction.
    if config.COMMAND_LOG_RETENTION_DAYS > 0:
        cutoff = now - timedelta(days=config.COMMAND_LOG_RETENTION_DAYS)
        result["pruned"] = (
            db.query(DeviceCommandLog)
            .filter(DeviceCommandLog.concluded_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.commit()

    if any(result.values()):
        log.info(
            "command sweep: %s exhausted, %s expired, %s history row(s) pruned",
            result["exhausted"], result["expired"], result["pruned"],
        )
    return result
