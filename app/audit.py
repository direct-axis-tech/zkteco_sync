"""The accountability trail: one function that writes one row.

This module exists so every privileged or physical action in the app leaves
a record of who did it and from where. It is deliberately the last thing a
request handler does, after its own commit, so a failure here can never turn
a successful door-unlock (or any other action) into a failed request — it is
swallowed and logged at ERROR instead. See ``record``.

``detail`` is free text for human context and must never carry a secret
value — a password, an HRM secret, a device comm key. Call sites may say
*that* one of these changed, never what it changed to.
"""

import logging

from sqlalchemy.orm import Session

from app.models import AuditLog

log = logging.getLogger(__name__)


def record(db: Session, actor: str, action: str, target: str = None,
           ip: str = None, detail: str = None) -> None:
    """Append one audit row. Never raises into the caller.

    ``actor`` is a username, or the literal ``"system"`` / ``"device"`` for
    actions with no signed-in operator behind them. Call this after the
    primary change has already been committed, so an audit-write failure
    cannot roll back or block the action it is merely recording.
    """
    try:
        db.add(AuditLog(
            actor=actor or "system",
            action=action,
            target=target,
            ip=ip,
            detail=detail,
        ))
        db.commit()
    except Exception:
        db.rollback()
        log.error(
            "audit: failed to record action=%s actor=%s target=%s",
            action, actor, target, exc_info=True,
        )
