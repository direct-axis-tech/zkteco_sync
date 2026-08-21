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

**A non-zero ``Return`` is a refusal, not a hiccup.** The device received the
command, understood it, and declined it. Re-sending it earns the same answer
while occupying the queue, so it is concluded ``failed`` immediately with the
code recorded. Only silence is retried.
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
# Queueing
# ---------------------------------------------------------------------------

def queue(db: Session, device_sn: str, command: str) -> DeviceCommandOutbox:
    """Put one command in the outbox for a device. Delivered on its next poll.

    Deliberately does not care whether the device is reachable, approved or
    even switched on: queueing is not delivery, and a device that is offline
    right now is the ordinary case, not an error.
    """
    row = DeviceCommandOutbox(
        device_sn=device_sn,
        command=strip_envelope(command),
        status="pending",
        attempts=0,
        created_at=_now(),
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
        log.error(
            "ACCESS NOT REVOKED: %s never confirmed %r (%s). That person may "
            "still be able to open this door — check the terminal directly.",
            snapshot["device_sn"], snapshot["command"][:120],
            f"Return={return_code}" if return_code is not None else (last_error or "no acknowledgement"),
        )
    return True


# ---------------------------------------------------------------------------
# Dispatch — the /iclock/getrequest hot path
# ---------------------------------------------------------------------------

def _eligible(db: Session, device_sn: str, now: datetime):
    """Outstanding commands this device may be given right now, oldest first.

    Either never delivered, or delivered and past its retry time. A command
    that was sent and is still inside its backoff window is deliberately
    invisible here — that is the whole point of the backoff.
    """
    return (
        db.query(DeviceCommandOutbox)
        .filter(DeviceCommandOutbox.device_sn == device_sn)
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
) -> str:
    """Record what the device reported about one specific command.

    ``Return=0`` concludes it acknowledged. Any other code is the device
    *refusing* the command — concluded failed immediately, with the code kept,
    because retrying a refusal only earns the same refusal more slowly.

    Returns a short word describing what happened, for the caller's log:
    ``acknowledged``, ``rejected``, ``unknown`` or ``duplicate``. Never raises
    and never refuses the request — a device that cannot deliver its ack will
    keep retrying the whole command, which is worse than a lost outcome.

    ``source`` names the endpoint the report arrived on, for the log only.
    There are two: ``/iclock/devicecmd`` for an ordinary command, and
    ``/iclock/querydata`` for a ``DATA QUERY``, which a device answers by
    uploading the data and quoting ``cmdid`` instead of ever calling devicecmd
    (E9). Both conclude a command the same way and must keep doing so — one
    definition of "concluded", one atomic move — but "devicecmd reported ID=1"
    in a log line about a querydata upload would send the next person reading
    it to the wrong endpoint.
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
        # Either already concluded (the device re-sent an ack, or acked after
        # we gave up) or an id we never issued to this serial. Both are worth
        # saying out loud, and neither is worth touching another command over
        # — acknowledging whatever happened to be nearby is the bug this
        # function exists to fix.
        log.warning(
            "%s from %s reported ID=%s Return=%s CMD=%r, which is not "
            "outstanding for that serial — no other command was touched",
            source, device_sn, command_id, return_code, command_name,
        )
        return "unknown"

    if return_code == 0:
        moved = conclude(db, row, "acknowledged", return_code=0)
        if moved:
            log.info("command %s acknowledged by %s", command_id, device_sn)
        return "acknowledged" if moved else "duplicate"

    moved = conclude(
        db, row, "failed",
        return_code=return_code,
        last_error=f"device rejected the command with Return={return_code}",
    )
    if moved:
        log.warning(
            "command %s rejected by %s with Return=%s (%r) — not retried, a "
            "refusal is permanent",
            command_id, device_sn, return_code, command_name,
        )
    return "rejected" if moved else "duplicate"


# ---------------------------------------------------------------------------
# The scheduled sweep
# ---------------------------------------------------------------------------

def sweep(db: Session, now: datetime = None) -> dict:
    """Periodic maintenance: give up on the hopeless, prune old history.

    Runs on the app's existing APScheduler (see app/main.py), infrequently —
    none of this is on a request path.

    Three jobs, in the order they matter:

    1. **Exhausted deliveries.** A command handed to a device the maximum
       number of times, whose last retry window has passed, is concluded
       failed. ``getrequest`` does this too, on the next poll; this covers the
       device that stopped polling part-way through its retries, so the
       failure surfaces on a timer instead of waiting for a device that may
       never return.

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
    result = {"exhausted": 0, "expired": 0, "pruned": 0}

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
