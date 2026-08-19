"""The ADMS pairing window.

Onboarding is the one moment the server has to accept a serial number it has
never seen. Rather than leaving that door open for ever — which is what
auto-registration did — an admin opens it for a few minutes, installs the
device, and it closes itself. A serial seen inside the window is only *filed*
for approval; it still pushes nothing until an admin approves it.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app import config
from app.models import AdmsPairing

log = logging.getLogger(__name__)

# An onboarding window is meant to be minutes, not a standing invitation.
MAX_MINUTES = 120


def get_window(db: Session) -> AdmsPairing:
    """The single pairing row, created closed on first use."""
    row = db.query(AdmsPairing).filter_by(id=1).first()
    if not row:
        row = AdmsPairing(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def seconds_remaining(row: AdmsPairing) -> int:
    if not row or not row.open_until:
        return 0
    left = (row.open_until - datetime.now(timezone.utc)).total_seconds()
    return int(left) if left > 0 else 0


def is_open(db: Session) -> bool:
    return seconds_remaining(get_window(db)) > 0


def open_window(db: Session, minutes: int, username: str) -> AdmsPairing:
    minutes = max(1, min(int(minutes or config.ADMS_PAIRING_MINUTES), MAX_MINUTES))
    now = datetime.now(timezone.utc)
    row = get_window(db)
    row.open_until = now + timedelta(minutes=minutes)
    row.opened_at = now
    row.opened_by = username
    db.commit()
    db.refresh(row)
    log.warning("ADMS pairing window opened for %s minutes by %s", minutes, username)
    return row


def close_window(db: Session, username: str) -> AdmsPairing:
    row = get_window(db)
    row.open_until = None
    db.commit()
    db.refresh(row)
    log.info("ADMS pairing window closed by %s", username)
    return row
