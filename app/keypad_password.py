"""Keeping a person's device keypad password secret while it is stored.

A keypad password is not like an operator's login password, which is hashed
because it only ever has to be *checked*. This one has to be *given back*: a
push to another terminal carries it in the `Passwd=` (att) or `Password=`
(acc) field, so it is stored reversibly — sealed with Fernet (AES-128-CBC plus
an HMAC) under a key derived from SECRET_KEY, never as the digits themselves.

What that buys, and what it does not: a copy of the database alone does not
reveal anybody's password. A copy of the database *and* `.env` does, because
the server itself must be able to read them to push them.

Rotating SECRET_KEY makes every stored password unreadable. :func:`unseal`
then answers None, which every caller treats as "no password stored" — the
person is pushed without one, exactly as before this column existed, and the
next device report or operator edit seals it again under the new key.
"""

import base64
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import config

log = logging.getLogger(__name__)

# Bound into the derived key, so this key is never the one anything else
# derives from SECRET_KEY, and cannot be confused with it.
_KEY_PURPOSE = b"zkteco-sync keypad password v1"


def _fernet() -> Fernet:
    secret = config.SECRET_KEY
    if not secret:
        # Production refuses to start without one (config.validate); this is
        # a development run with nothing to derive a key from.
        raise RuntimeError("SECRET_KEY is not set; a keypad password cannot be sealed")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_KEY_PURPOSE).derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def seal(password: str) -> str:
    """The stored form of ``password``. Different every call (Fernet uses a
    fresh IV), so two people with the same digits do not share a token."""
    return _fernet().encrypt(password.encode("utf-8")).decode("ascii")


def unseal(token):
    """The password ``token`` was sealed from, or None — for no token, and for
    one this key cannot open (SECRET_KEY rotated, or the value tampered
    with)."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, RuntimeError, ValueError):
        log.warning("a stored keypad password could not be unsealed with the "
                    "current SECRET_KEY; treating it as not set")
        return None
