"""Validated application settings, read once from the environment.

Every setting the app needs is resolved here so that a misconfigured
deployment fails at boot with an actionable message instead of failing
half-way through a request. Later hardening units add keys to this module.
"""

import logging
import os
import zoneinfo
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

_PLACEHOLDER_SECRET = "change-me-in-production"
_MIN_SECRET_LENGTH = 32


def _get(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def _get_bool(name: str, default: bool) -> bool:
    raw = _get(name).lower()
    if raw == "":
        return default
    return raw in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    raw = _get(name)
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("%s='%s' is not a number — falling back to %s", name, raw, default)
        return default


def _get_list(name: str, default: str = "") -> list:
    """Comma-separated env value → list of non-empty trimmed strings."""
    return [item.strip() for item in _get(name, default).split(",") if item.strip()]


APP_ENV = _get("APP_ENV", "production").lower()
IS_PRODUCTION = APP_ENV == "production"

SECRET_KEY = _get("SECRET_KEY")
ALLOWED_HOSTS = _get_list("ALLOWED_HOSTS")
TRUSTED_PROXIES = _get_list("TRUSTED_PROXIES", "127.0.0.1,::1")

# Cookies may only carry the Secure flag where TLS actually terminates in
# front of the app. Apache does that in production; a plain-HTTP dev run
# would otherwise never receive the session cookie back.
COOKIE_SECURE = _get_bool("COOKIE_SECURE", IS_PRODUCTION)
SESSION_COOKIE_NAME = _get("SESSION_COOKIE_NAME", "zk_session")
SESSION_IDLE_MINUTES = _get_int("SESSION_IDLE_MINUTES", 60)
SESSION_ABSOLUTE_HOURS = _get_int("SESSION_ABSOLUTE_HOURS", 12)

LOGIN_MAX_ATTEMPTS = _get_int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_LOCKOUT_MINUTES = _get_int("LOGIN_LOCKOUT_MINUTES", 15)

ENABLE_DOCS = _get_bool("ENABLE_DOCS", False)
MAX_REQUEST_BYTES = _get_int("MAX_REQUEST_BYTES", 2 * 1024 * 1024)
ADMS_PAIRING_MINUTES = _get_int("ADMS_PAIRING_MINUTES", 15)


# ---------------------------------------------------------------------------
# Timezone provenance
# ---------------------------------------------------------------------------
# A ZKTeco device sends a bare wall-clock string with no offset and no zone
# name ("time=2026-08-20 14:48:22"). The digits are correct; what is missing
# is what they *mean*. This is the zone a newly registered device is assumed
# to be set to, and it is stamped onto the device row, which in turn is
# snapshotted onto every attendance record. Nothing here ever converts a
# time — it only labels one.

@lru_cache(maxsize=1)
def _known_timezones() -> frozenset:
    """The IANA zone names this machine's tz database knows about."""
    return frozenset(zoneinfo.available_timezones())


def valid_timezone(name) -> bool:
    """True for an IANA zone name this machine can resolve, e.g. 'Asia/Dubai'."""
    return bool(name) and name in _known_timezones()


DEFAULT_DEVICE_TIMEZONE = _get("DEFAULT_DEVICE_TIMEZONE", "Asia/Dubai")

# Unlike the checks in _problems() below, this one raises in *every*
# environment. Those are deployment-posture questions where a development
# machine legitimately differs; an unresolvable zone name is simply a typo,
# and letting it through would silently stamp a meaningless label onto every
# device and every attendance record the install goes on to collect — a data
# error that is invisible until someone tries to interpret a punch time.
if not valid_timezone(DEFAULT_DEVICE_TIMEZONE):
    raise RuntimeError(
        f"DEFAULT_DEVICE_TIMEZONE='{DEFAULT_DEVICE_TIMEZONE}' is not an IANA "
        "timezone name this system recognises.\n"
        "Use a name from the tz database, e.g.\n"
        "    DEFAULT_DEVICE_TIMEZONE=Asia/Dubai\n"
        "List the valid names with:\n"
        "    python -c \"import zoneinfo; print('\\n'.join(sorted(zoneinfo.available_timezones())))\"\n"
        "If that list comes back empty, this machine has no tz database — "
        "install the 'tzdata' package."
    )


def _problems() -> list:
    """Settings that make a public deployment unsafe, with the fix for each."""
    found = []

    if not SECRET_KEY:
        found.append(
            "SECRET_KEY is not set. Add a random value to .env, e.g.\n"
            "    SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")"
        )
    elif SECRET_KEY == _PLACEHOLDER_SECRET:
        found.append(
            f"SECRET_KEY is still the placeholder '{_PLACEHOLDER_SECRET}'. Replace it in .env with\n"
            "    SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")"
        )
    elif len(SECRET_KEY) < _MIN_SECRET_LENGTH:
        found.append(
            f"SECRET_KEY is only {len(SECRET_KEY)} characters; at least {_MIN_SECRET_LENGTH} are required. Replace it in .env with\n"
            "    SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")"
        )

    if not ALLOWED_HOSTS:
        found.append(
            "ALLOWED_HOSTS is not set. List the hostnames this server answers on, e.g.\n"
            "    ALLOWED_HOSTS=zk.example.com"
        )
    elif "*" in ALLOWED_HOSTS:
        found.append(
            "ALLOWED_HOSTS contains '*', which accepts any Host header. Replace it with the real hostnames, e.g.\n"
            "    ALLOWED_HOSTS=zk.example.com"
        )

    return found


def _validate() -> None:
    """Refuse to boot on an unsafe production config; warn in development."""
    problems = _problems()
    if not problems:
        return

    listing = "\n\n".join(f"  * {p}" for p in problems)
    if IS_PRODUCTION:
        raise RuntimeError(
            "Refusing to start: unsafe configuration for APP_ENV=production.\n\n"
            f"{listing}\n\n"
            "Fix the values above in .env and restart. To run without these checks "
            "on a development machine set APP_ENV=development."
        )

    log.warning(
        "Configuration would be rejected under APP_ENV=production:\n%s", listing
    )


_validate()
