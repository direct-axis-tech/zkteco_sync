"""First-boot seeding of the initial administrator.

API_USERNAME / API_PASSWORD in .env used to *be* the login. They are now a
one-time bootstrap only: they seed the first account on an empty users table
and are never consulted again. In particular this never resurrects a deleted
account and never overwrites a password an operator has since changed.
"""

import logging
import os

from app.database import SessionLocal
from app.models import User
from app.security import hash_password

log = logging.getLogger(__name__)


def seed_first_admin() -> None:
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return  # someone already administers this install — hands off

        username = (os.getenv("API_USERNAME") or "").strip()
        password = os.getenv("API_PASSWORD") or ""
        if not username or not password:
            log.error(
                "No operator accounts exist and API_USERNAME/API_PASSWORD are not set in .env, "
                "so no administrator could be created. Set both, restart, and change the "
                "password at first sign-in."
            )
            return

        user = User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            must_change_password=True,
            failed_attempts=0,
        )
        db.add(user)
        db.commit()

        log.warning(
            "Created the first administrator '%s' from API_USERNAME/API_PASSWORD. "
            "That .env password is now a SPENT one-time bootstrap credential: it must be "
            "changed at first sign-in (the UI will force it), after which API_PASSWORD "
            "should be removed from .env.",
            username,
        )
    finally:
        db.close()
