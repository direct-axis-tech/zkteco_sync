"""Password hashing, opaque session tokens and constant-time comparison.

Passwords are hashed with Argon2id. Session tokens are random and opaque —
only their SHA-256 digest is stored, so a database dump cannot be replayed
as a live session.
"""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError

# Deliberately above the argon2-cffi defaults for memory cost: an admin login
# is not a hot path, and the cost is paid once per sign-in.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    """Argon2id hash, encoded with its own parameters so it can be rehashed later."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """True only on a match. Never raises — a malformed or empty hash is a
    failed verification, not a 500."""
    if not password or not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (Argon2Error, InvalidHashError, TypeError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash predates the current cost parameters."""
    if not password_hash:
        return False
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (Argon2Error, InvalidHashError, TypeError, ValueError):
        return False


def generate_token() -> str:
    """Opaque, URL-safe token for session cookies and CSRF tokens."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """SHA-256 hex digest — what actually goes in the sessions table.

    A plain digest is right here (unlike for passwords): the token already
    carries full entropy, so there is nothing to brute-force."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    """Comparison that does not leak the position of the first difference."""
    if not left or not right:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
