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
# Device command delivery (E7)
# ---------------------------------------------------------------------------
# A command is queued into device_command_outbox and handed to the device on
# its next /iclock/getrequest poll. The device acknowledges it with
# ID=<id>&Return=<code>&CMD=<name>. Everything below governs what happens when
# that acknowledgement does not arrive.
#
# The distinction that matters: a command sitting `pending` because the device
# has not polled is NOT a failure — it is the queue doing its job, and it is
# what let the operator recover a weekend of missed punches. Only the
# sent-but-never-acknowledged case consumes an attempt.

# How many times one command may be handed to a device without ever being
# acknowledged before it is given up on. Deliveries, not seconds: a device
# that never polls never consumes one.
COMMAND_MAX_ATTEMPTS = max(1, _get_int("COMMAND_MAX_ATTEMPTS", 5))

# Delay before a delivered-but-unacknowledged command is offered again, one
# entry per attempt. The last entry repeats if attempts outlive the list, so
# the schedule is bounded no matter how the two values are set.
# Default: 1m, 5m, 15m, 1h, 1h — a device that is merely slow gets several
# quick chances; one that is ignoring us is retried lazily.
COMMAND_BACKOFF_SECONDS = [
    max(1, int(v))
    for v in _get_list("COMMAND_BACKOFF_SECONDS", "60,300,900,3600")
    if v.lstrip("-").isdigit()
] or [60, 300, 900, 3600]

# Absolute age at which an outstanding command is abandoned, counted from when
# it was queued. Deliberately long and deliberately separate from
# COMMAND_MAX_ATTEMPTS: this is the answer to "a command queued for a device
# that never came back", not to "the device refused us". Set to 0 to disable.
COMMAND_PENDING_EXPIRY_DAYS = _get_int("COMMAND_PENDING_EXPIRY_DAYS", 30)

# How long concluded commands stay in device_command_log before the sweep
# prunes them. Set to 0 to keep history forever.
COMMAND_LOG_RETENTION_DAYS = _get_int("COMMAND_LOG_RETENTION_DAYS", 90)

# How often the retry/expiry/prune sweep runs on the existing scheduler.
COMMAND_SWEEP_MINUTES = max(1, _get_int("COMMAND_SWEEP_MINUTES", 15))

# How many commands one getrequest poll may carry. The protocol allows several
# LF-separated commands in one reply (§3.8), but no device in this install has
# ever been sent a command at all, so the ack behaviour for a batch is
# unobserved — and mis-acknowledging is precisely the bug this unit fixes.
# Default 1 is provably correct; raise it once a real terminal has been seen
# acknowledging a multi-command reply.
COMMAND_BATCH_SIZE = max(1, _get_int("COMMAND_BATCH_SIZE", 1))

# The same schedule, for a command that REVOKES access (`DATA DELETE …`, E8).
#
# Everywhere else in this application the queue's patience with an unreachable
# device is the feature — it is what recovered a weekend of missed punches.
# Revocation is the one place where it is a hazard: while a delete sits in a
# backoff window the person it names can still open that door. So a delivered
# but unacknowledged revocation is offered again much sooner than an ordinary
# command.
#
# Safe to make aggressive because a delete is idempotent in exactly the way
# E7 relies on for DATA UPDATE: deleting a user the terminal has already
# removed does nothing the second time.
#
# The shorter schedule also means a revocation that is never acknowledged
# exhausts its attempts in minutes rather than an hour. That is deliberate: a
# failed revocation is something the operator has to *act* on — walk to the
# door, pull the person some other way — and finding out quickly is worth more
# than a few extra silent retries. Nothing is ever concluded on this clock
# while the device is merely offline; that path consumes no attempts at all.
REVOCATION_BACKOFF_SECONDS = [
    max(1, int(v))
    for v in _get_list("REVOCATION_BACKOFF_SECONDS", "30,60,120,300")
    if v.lstrip("-").isdigit()
] or [30, 60, 120, 300]


# ---------------------------------------------------------------------------
# Central provisioning of people onto access-control terminals (E3)
# ---------------------------------------------------------------------------
# Creating a user on an `acc` terminal does NOT let that person through a
# door. The user record and the door permission are two different tables, and
# the permission one is `userauthorize` (§3.8):
#
#     DATA UPDATE userauthorize Pin=<n><HT>AuthorizeTimezoneId=<n>
#
# AuthorizeTimezoneId names one of the device's own stored access time zones —
# a weekly schedule of intervals during which the holder may open the door.
# The two values that matter:
#
#   0  is the ZKTeco convention for "no access time zone" — the person is
#      known to the terminal, can enrol a face, verifies successfully, and is
#      then refused at the door. That is the confusing half-success this
#      setting exists to avoid, so it is NOT the default.
#   1  is the factory-default time zone on ZKTeco access panels, defined as
#      the whole week, 00:00-23:59 — i.e. "allowed at any time". It is what
#      BioTime assigns a newly created person unless a schedule is chosen.
#
# So the default is 1: a person provisioned from here can open the door as
# soon as they have enrolled a biometric, which is the workflow being built.
# A site that runs real access schedules sets this to the id of the time zone
# it has configured on the terminal. CAVEAT, stated plainly: no acknowledgement
# from real hardware has ever been observed by this application, so "1 = 24/7"
# is taken from the vendor's documented default and is not yet confirmed
# against the operator's BioFace A1.
PROVISION_AUTHORIZE_TIMEZONE_ID = _get_int("PROVISION_AUTHORIZE_TIMEZONE_ID", 1)

# The `Group=` field of the user record. 0 is what ZKTeco's own SDK command
# constants use in their worked example (§3.8), and access-group membership is
# not how this application grants access — `userauthorize` above is. Exposed
# because it is a device-semantics number, not a constant of nature: a site
# that uses device access groups will need its own value here.
PROVISION_USER_GROUP = _get_int("PROVISION_USER_GROUP", 0)


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
