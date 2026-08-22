"""Device-control commands for `acc` terminals, and the honest gaps.

E15. The nine device-control endpoints in `app/routers/devices.py` all opened
an SDK connection with no `acc` path, so every one of them 503'd on a terminal
behind NAT. Door unlock is the one that mattered: the operator's BioFace A1
could not be opened from this server at all.

WHERE THESE SHAPES COME FROM, AND WHY THAT IS DIFFERENT THIS TIME
=================================================================

Every string in this module is quoted from ZKTeco's *Security PUSH
Communication Protocol*, PUSH Protocol Version 3.1.2, Doc Version 2.3,
January 2021 — the 178-page vendor document, read in full.

That document is the reason this unit could be implemented rather than
refused. push-protocol.md §3.8 had to reconstruct command shapes out of SDK
constants because the copies of the spec available at the time were
*truncated at page 74*, and every command chapter lives on pages 100-150. The
complete PDF is committed in the `ciphercall/zkteco-adms-api` repository. Its
extracted text is kept alongside the protocol notes as `push.txt`.

Three independent things say this document describes *this* firmware, not
merely a related family:

1. Its Appendix 1 defines **-629 as "Incorrect table name"**. That is exactly
   the code the operator's terminal returned on 2026-08-21 when it was probed
   with `DATA QUERY tablename=nosuchtable` — a well-formed query against a
   table that does not exist. A field-observed error code matching the
   document's appendix is about as direct a confirmation as is available
   short of running the command.
2. It is version-matched: the device announces `pushver=3.1.2` and this is the
   3.1.2 document.
3. Appendix 1 also carries error codes that only exist if these very commands
   are implemented in firmware: -28 "Door opening command is executed during
   the open time period", -614 "Failed to remotely cancel the alarm", -615
   "Remote restart failed", -616 "Remotely enabling or canceling normal open
   failed".

The spec defines exactly eight server-to-device verbs: `DATA UPDATE`,
`DATA DELETE`, `DATA COUNT`, `DATA QUERY`, `CONTROL DEVICE`, `SET OPTIONS`,
`GET OPTIONS` and `UPGRADE`. Anything outside that set does not exist on an
`acc` terminal, however many open-source servers send it.

TWO SHAPES THAT WOULD HAVE BEEN PLAUSIBLE GUESSES, AND ARE WRONG
----------------------------------------------------------------

* **`AC_UNLOCK`** is real, vendor-documented, and belongs to the *Attendance*
  PUSH protocol. It appears nowhere in the 178 pages of the Security one. On a
  `DeviceType=acc` device it is not a command.
* **`CONTROL DEVICE 1 1 1 15`** — space-separated decimal — is used by at
  least two open-source ADMS servers. The spec's parameters are a single
  concatenated hex string with no separators at all. The space-separated form
  is third-party convention and is not sent from here.

Had this module been written from analogy or from the most popular open-source
implementation, it would have shipped one of those two.
"""

import logging
from datetime import datetime

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CONTROL DEVICE — spec §12.4, pp.137-139
# ---------------------------------------------------------------------------
#
# Format, verbatim from the spec:
#
#     C:$(CmdID):CONTROL$(SP)DEVICE$(SP)AABBCCDDEE
#
# and, verbatim: "AA, BB, CC, and DD are four groups of two-byte strings. Each
# group of strings is the converted result of a one-byte integer after %02X
# conversion."
#
# So the parameters are POSITIONAL HEX WITH NO SEPARATORS — not key=value, not
# comma-separated, not space-separated. `SET OPTIONS` in the same document
# uses comma-separated key=value and `DATA UPDATE` uses TAB-separated fields;
# all three are different and none of them generalises to the others.
#
# The spec prints EE as a fifth group labelled "Operator", but the prose says
# four groups and every door, alarm and restart example prints eight hex
# digits. Eight is what is sent here, byte-for-byte as the spec's own example.
#
# AA (the control command) is written in the spec's table as a DECIMAL label
# and encoded as hex — proven by the spec's own examples, where the row
# labelled 13 renders as `0D` and the row labelled 11 renders as `0B`. The
# rows used here are 01 and 03, which are identical in both readings, so
# nothing in this module depends on resolving that.

_AA_CONTROL_OUTPUT = 0x01      # "01: Control the output"
_AA_RESTART_DEVICE = 0x03      # "03: Restart the device."

_CC_LOCK = 0x01                # "01: Control the lock."
# "02: Control the auxiliary output." is documented in the same column but is
# NOT offered here: §12.4's BB column only ever documents door IDs, and the
# spec numbers auxiliary outputs differently elsewhere ("auxiliary output
# ranges from 1 to 4"), so the numbering for an aux command is genuinely
# ambiguous in the vendor's own text. Not guessed at.

# DD is the opening duration in seconds — with two reserved values that make
# the range narrower than a byte:
#
#     "00: Off. FF: Normal open. 01-FF: The opening duration."
#
# **FF does not mean 255 seconds. It means latch the door normally-open.**
# A caller asking to "unlock for 255 seconds" and getting a door that stays
# open until somebody notices is the single worst bug this file could contain,
# so 255 is refused rather than clamped — silently turning a request into a
# different request is how that bug would reach a door.
#
# 00 is likewise not an unlock; it is "off", the immediate-close command.
DOOR_LATCH_NORMAL_OPEN = 0xFF
MAX_UNLOCK_SECONDS = 0xFE      # 254 — the largest duration that is a duration
MIN_UNLOCK_SECONDS = 0x01

# "00: Open all the doors. 01-10: The door ID". Door 0 is ALL DOORS and is
# never the default here: defaulting a single-door face terminal to 0 would be
# harmless, and defaulting a multi-door controller to 0 would open every door
# in the building. The default is door 1, which is what the spec's own unlock
# example uses.
DEFAULT_DOOR = 1
MIN_DOOR = 1
MAX_DOOR = 10


class UnsafeDoorCommand(ValueError):
    """A door command was asked for that this module will not construct."""


def unlock_command(door: int = DEFAULT_DOOR, seconds: int = 3) -> str:
    """`CONTROL DEVICE 01<door>01<secs>` — open a door for N seconds.

    The spec's own example, §12.4 example (1), is reproduced exactly by
    ``unlock_command(door=1, seconds=5)``:

        C:221:CONTROL DEVICE 01010105
        "The server delivers the command of opening Door 1 for 5s"

    Raises :class:`UnsafeDoorCommand` rather than clamping. See the notes on
    ``DOOR_LATCH_NORMAL_OPEN`` above for why a silent clamp is the dangerous
    option: 255 is not a long unlock, it is a permanent one.
    """
    if not isinstance(door, int) or isinstance(door, bool):
        raise UnsafeDoorCommand("door must be an integer")
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        raise UnsafeDoorCommand("seconds must be an integer")
    if not MIN_DOOR <= door <= MAX_DOOR:
        raise UnsafeDoorCommand(
            f"door must be between {MIN_DOOR} and {MAX_DOOR}; door 0 means "
            "EVERY door on the controller and is never sent from here"
        )
    if seconds == DOOR_LATCH_NORMAL_OPEN:
        raise UnsafeDoorCommand(
            "255 is not a 255-second unlock — in this protocol 0xFF means "
            "latch the door normally-open, i.e. leave it open indefinitely. "
            f"Use {MAX_UNLOCK_SECONDS} or fewer seconds."
        )
    if not MIN_UNLOCK_SECONDS <= seconds <= MAX_UNLOCK_SECONDS:
        raise UnsafeDoorCommand(
            f"seconds must be between {MIN_UNLOCK_SECONDS} and "
            f"{MAX_UNLOCK_SECONDS}; 0 is the immediate-close command, not an "
            "unlock"
        )
    return (
        "CONTROL DEVICE "
        f"{_AA_CONTROL_OUTPUT:02X}{door:02X}{_CC_LOCK:02X}{seconds:02X}"
    )


def restart_command() -> str:
    """`CONTROL DEVICE 03000000` — restart this device.

    §12.4 example (3), verbatim: "The server delivers the command of
    restarting the current device: C:223:CONTROL DEVICE 03000000". BB=00 is
    "Restart the current device" as opposed to a slave device ID.
    """
    return f"CONTROL DEVICE {_AA_RESTART_DEVICE:02X}000000"


# ---------------------------------------------------------------------------
# SET OPTIONS DateTime — spec §12.5.1 p.144, and Appendix 5 p.164
# ---------------------------------------------------------------------------

def encode_time(dt: datetime) -> int:
    """ZKTeco's seconds encoding. **Not** a Unix timestamp.

    Appendix 5 gives the algorithm as C, reproduced here as written:

        tt = ((year - 2000) * 12 * 31 + ((mon - 1) * 31) + day - 1)
             * (24 * 60 * 60) + (hour * 60 + min) * 60 + sec;

    Note the deliberately wrong calendar: every month is 31 days long and
    every year is 12 * 31 days. It is not a duration since an epoch and
    arithmetic on it is meaningless — it is a packed field. Implemented
    exactly, including the parts that look like bugs, because the device
    decodes it with the matching Appendix 6 routine.

    Checked against the spec's own worked value: the example command carries
    DateTime=583080894, which this function returns for 2018-02-22 14:54:54.
    """
    return (
        ((dt.year - 2000) * 12 * 31 + (dt.month - 1) * 31 + dt.day - 1)
        * (24 * 60 * 60)
        + (dt.hour * 60 + dt.minute) * 60
        + dt.second
    )


def set_time_command(dt: datetime) -> str:
    """`SET OPTIONS DateTime=<encoded>` — set the terminal's clock.

    §12.5.1, verbatim: "Synchronize the time to the client: C:401:SET OPTIONS
    DateTime=583080894".

    ``dt`` must already be wall-clock time in the zone the terminal is
    supposed to display. The caller owns that conversion, because this server
    knows each device's timezone (``Device.timezone``) and the device does not
    tell us its own.

    One documented compatibility note, quoted so nobody has to rediscover it:
    "Some devices stop time synchronization after receiving this command,
    while some devices immediately trigger the following request after
    executing this command" — the follow-up being
    `GET /iclock/rtdata?SN=...&type=time`. Our server does not implement
    `/iclock/rtdata`; a device that asks will get the catch-all's 404 and log
    a line naming the endpoint, which is exactly how `/iclock/querydata` was
    discovered. If that appears in the log, that is what it means.
    """
    return f"SET OPTIONS DateTime={encode_time(dt)}"


# ---------------------------------------------------------------------------
# GET OPTIONS — spec §12.5.2 pp.146-147
# ---------------------------------------------------------------------------
#
# The device does NOT answer inline. It POSTs the parameters to
# /iclock/querydata with type=options&tablename=options, then acknowledges
# separately on /iclock/devicecmd. Both halves already work here: E9's
# querydata handler concludes the command by its cmdid, and `_store_bulk_table`
# routes a table named `options` to the same `_store_capabilities` that stores
# the parameter line the device pushes on its own.
#
# The key list is the spec's own example from §12.5.2, minus the two keys that
# would be actively unhelpful to request:
#   * ComPwd — the device's communication password. There is no reason to pull
#     a shared secret into `device.capabilities`, which is rendered in the UI.
#   * EventTypes / VerifyStyles — long opaque bitfields nothing here reads.
# Everything kept is something the Device Info drawer displays or something
# that answers a question the operator has actually had (LockCount is "how
# many doors does this thing have", which is the input to a door command).

GET_OPTIONS_KEYS = (
    "~SerialNumber",
    "FirmVer",
    "~DeviceName",
    "MachineType",
    "LockCount",
    "ReaderCount",
    "AuxInCount",
    "AuxOutCount",
    "~MaxUserCount",
    "~MaxAttLogCount",
    "~MaxUserFingerCount",
    "IPAddress",
    "NetMask",
    "GATEIPAddress",
    "~ZKFPVersion",
)

# "Multiple parameters are separated by commas, but the last parameter is not
# followed by a comma." (§12.5.2) — hence join, not a trailing separator.
QUERY_OPTIONS = "GET OPTIONS " + ",".join(GET_OPTIONS_KEYS)


def parse_options(text: str) -> dict:
    """Split a device parameter line into a dict. Values are left as strings.

    The line is the one shape the device sends its parameters in, on all three
    occasions it sends them: at registration, unprompted on
    `cdata?table=options`, and in answer to `GET OPTIONS`. Comma-separated
    `key=value`, with `~`-prefixed keys meaning read-only capabilities.

    Deliberately forgiving and deliberately non-interpreting. Values are not
    coerced to ints, booleans or anything else: this feeds a
    last-known-parameters display, and a field this code does not understand
    should reach the operator unchanged rather than be dropped by a parser
    with opinions. An empty or malformed line yields ``{}`` rather than
    raising — the caller's fallback for "nothing recorded" is the same as its
    fallback for "unparseable", namely to say so.
    """
    out = {}
    for chunk in (text or "").replace("\r", "\n").replace("\n", ",").split(","):
        key, sep, value = chunk.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        out[key] = value.strip()
    return out


# The subset of parsed keys the Device Info drawer knows how to show, mapped
# onto the field names the `att` branch has always returned so one drawer can
# render either transport. A key the device did not send is simply absent, and
# the drawer already renders a missing value as an em dash.
def options_as_info(options: dict) -> dict:
    """Map a parsed parameter dict onto the Device Info shape."""
    def pick(*names):
        for name in names:
            if options.get(name):
                return options[name]
        return None

    return {
        "serial_number": pick("~SerialNumber", "SerialNumber"),
        "device_name": pick("~DeviceName", "DeviceName"),
        "firmware_version": pick("FirmVer", "FirmwareVersion"),
        "platform": pick("MachineType", "~Platform", "Platform"),
        "mac": pick("MAC", "~MAC"),
        "face_version": pick("ZKFaceVersion", "~ZKFaceVersion", "FaceFunOn"),
        "fp_version": pick("~ZKFPVersion", "ZKFPVersion"),
        "pin_width": pick("~PIN2Width", "PIN2Width"),
        "network": {
            "ip": pick("IPAddress"),
            "mask": pick("NetMask"),
            "gateway": pick("GATEIPAddress"),
        },
        "doors": pick("LockCount"),
        "readers": pick("ReaderCount"),
        "aux_outputs": pick("AuxOutCount"),
        "sizes": {
            "users_cap": pick("~MaxUserCount"),
            "rec_cap": pick("~MaxAttLogCount"),
            "fingers_cap": pick("~MaxUserFingerCount"),
        },
    }


# ---------------------------------------------------------------------------
# DATA DELETE transaction * — spec §12.1.2.5 pp.103-104
# ---------------------------------------------------------------------------
#
# Verbatim: "Delete all the access control records: C:123:DATA DELETE
# transaction *", where "$(Cond): * means deleting all the records."
#
# This is the `acc` equivalent of the SDK's clear_attendance, and the same
# caveat applies as on the SDK path: it wipes the DEVICE's stored events and
# does not touch anything already ingested here.
#
# Note what this is NOT. E12 refused to invent `DATA QUERY tablename=transaction`
# and that refusal still stands, for its original reason: no server-issued
# query for the transaction table has ever been observed answering, and these
# terminals push their punches up unasked, so nothing needs to ask. The DELETE
# is a different command with a different justification — it is printed in the
# vendor spec with a worked example, and it is the only way to reclaim space on
# a terminal whose event buffer is full. Reading E12's refusal as "the
# transaction table is off limits" would be over-reading it.
CLEAR_RECORDS = "DATA DELETE transaction *"


# ---------------------------------------------------------------------------
# The gaps — what an `acc` terminal genuinely cannot be asked
# ---------------------------------------------------------------------------
#
# Each of these was searched for in the full document, not assumed absent
# because it was hard to find. They are quoted at the endpoints that refuse,
# so an operator reading a 501 gets the reason and not just the refusal.

NO_DEVICE_TIME_READ = (
    "There is no command for asking an access-control terminal what time it "
    "thinks it is. The traffic runs the other way: the spec's clock section "
    "documents the DEVICE fetching the time from the SERVER, by requesting "
    "/iclock/rtdata?type=time and being told the answer. So the supported "
    "operation is to set this terminal's clock, not to read it — and setting "
    "it does not require knowing what it was."
)

NO_LOCK_STATE_READ = (
    "There is no command for asking an access-control terminal whether its "
    "door is locked. The device reports door, relay and alarm state on its "
    "own schedule by pushing an `rtstate` record, and the protocol defines no "
    "way for the server to request one. The state is also not decoded here: "
    "an rtstate body carries `sensor`, `relay` and `alarm` as raw hex bytes "
    "whose meaning the specification never defines, so reporting a lock state "
    "from them would mean guessing about a door. Nothing was queued and "
    "nothing was guessed at."
)

NO_LCD_COMMAND = (
    "There is no command for writing to an access-control terminal's screen. "
    "The vendor protocol defines exactly eight server-to-device commands — "
    "DATA UPDATE, DATA DELETE, DATA COUNT, DATA QUERY, CONTROL DEVICE, SET "
    "OPTIONS, GET OPTIONS and UPGRADE — and none of them addresses the "
    "display. The specification does advertise a capability bit for "
    "'delivering the resource files, such as voice files, boot screen, "
    "welcome page, and screensaver page', but it never defines the command "
    "that delivers them, and UPGRADE is explicitly firmware-only. Nothing was "
    "queued and nothing was guessed at."
)


# ---------------------------------------------------------------------------
# Why a door command is one-shot — the async caveat, made structural
# ---------------------------------------------------------------------------
#
# An SDK unlock is synchronous: the call returns when the door has opened.
# An ADMS unlock is queued and collected on the device's next poll, and the
# outbox that carries it was designed for provisioning, where every command is
# idempotent and worth retrying. Three of its properties are wrong for a door:
#
#   1. Delivery is strict FIFO at COMMAND_BATCH_SIZE=1, so an unlock queued
#      behind a bulk enrolment is not ~10 seconds away, it is minutes away.
#   2. Nothing expires a pending command for hours, so an unlock that missed
#      its moment still opens the door later, at a door nobody is standing at.
#   3. An unacknowledged command is re-delivered on backoff up to
#      COMMAND_MAX_ATTEMPTS times, so a lost acknowledgement re-opens the door
#      repeatedly over the following hour.
#
# (2) and (3) are both closed by giving door commands a short absolute expiry:
# past it the command is never offered again and is concluded honestly as
# undelivered. Because the shortest retry backoff is 60s, a TTL of 60s also
# means a door command can never reach a second delivery. (1) is not fixed —
# it is reported: an unlock that expires in a queue says so, which is the
# correct outcome, because opening the door late is worse than not opening it.
#
# The value lives in app/config.py as DOOR_COMMAND_TTL_SECONDS.

DOOR_COMMAND_EXPIRED = (
    "This door command expired before the terminal collected it, so the door "
    "was NOT opened. An access-control terminal only receives commands when "
    "it polls, and a door command is deliberately given a short life: opening "
    "a door minutes after somebody asked — when they have gone — is worse "
    "than not opening it. Check the terminal is online and try again."
)
