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

In a queued command
-------------------
A push has to put the digits on the wire, but a queued command is a row in
`device_command_outbox`, then in `device_command_log`, and it is listed in
the Commands drawer and written to the log. So the command is queued with
:func:`in_command` — the sealed value in a ``{sealed:…}`` placeholder — and
:func:`revealed` swaps the digits in only for the line handed to the device.
Everything that shows a command shows :func:`masked`, ``<set>``. A retry
re-queues the placeholder, not the digits, so it works the same way.
"""

import base64
import logging
import re

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


# Fernet tokens are URL-safe base64: no TAB, no newline, no brace, so the
# placeholder can never swallow the field separator that follows it.
_IN_COMMAND = re.compile(r"\{sealed:([A-Za-z0-9_=-]+)\}")


def in_command(token: str) -> str:
    """The field value a queued command carries for a stored password."""
    return f"{{sealed:{token}}}"


def revealed(command: str) -> str:
    """``command`` as the device must receive it: each placeholder replaced by
    the password it seals. One this key cannot open (SECRET_KEY rotated after
    it was queued) becomes an empty field — the person is still delivered,
    with no password, rather than not at all."""
    return _IN_COMMAND.sub(lambda m: unseal(m.group(1)) or "", command)


def masked(command: str) -> str:
    """``command`` as anyone but the device may see it."""
    return _IN_COMMAND.sub("<set>", command or "")
