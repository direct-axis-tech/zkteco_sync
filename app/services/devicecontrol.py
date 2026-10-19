"""Device-control commands for `acc` and `att` terminals, and the honest gaps.

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
  `DeviceType=acc` device it is not a command. (It is what an `att` terminal
  is sent, as UNLOCK_ATT_DOOR below, and only ever an `att` one.)
* **`CONTROL DEVICE 1 1 1 15`** — space-separated decimal — is used by at
  least two open-source ADMS servers. The spec's parameters are a single
  concatenated hex string with no separators at all. The space-separated form
  is third-party convention and is not sent from here.

Had this module been written from analogy or from the most popular open-source
implementation, it would have shipped one of those two.

ATTENDANCE-MODE COMMANDS
------------------------

Since 2026-10-19 the module also holds the device-control commands for `att`
terminals, which an `acc` one does not understand and the reverse. Those are
quoted from a different document — ZKTeco's *Attendance PUSH Communication
Protocol*, software version 2.4.1, doc v3.7, March 2020 — and each one says so
where it is defined, with its section and whether it has been seen working on
hardware. Everything not so marked is from the Security PUSH document above.
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
# onto the field names the SDK read used to return so one drawer renders
# either protocol. A key the device did not send is simply absent, and the
# drawer already renders a missing value as an em dash. The `acc` names come
# first in each list; the names after them are the ones an `att` terminal's
# report is filed under (UPDATE_INFORMATION_KEYS below), and are only reached
# when the `acc` name is missing.
#
# `sizes` carries the enrolment counts an `att` terminal reports on every poll
# (§9) beside the capacities. The drawer does not show counts on a last-known
# reading today — it shows capacities only — but they are what an attendance
# terminal actually tells us, so they are returned for when it does.
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
        "firmware_version": pick("FirmVer", "FirmwareVersion", "FWVersion"),
        "platform": pick("MachineType", "~Platform", "Platform"),
        "mac": pick("MAC", "~MAC"),
        "face_version": pick("ZKFaceVersion", "~ZKFaceVersion", "FaceVersion",
                             "FaceFunOn"),
        "fp_version": pick("~ZKFPVersion", "ZKFPVersion", "FPVersion"),
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
            "users": pick("UserCount"),
            "fingers": pick("FPCount"),
            "records": pick("TransactionCount"),
            "faces": pick("FaceCount"),
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
# This is the `acc` equivalent of the SDK's clear_attendance (CLEAR_ATT_RECORDS
# below is the `att` one), and the same caveat applies: it wipes the DEVICE's
# stored events and does not touch anything already ingested here.
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
# CLEAR LOG — Attendance PUSH 2.4.1 §12.2.1, p.88 (`att` terminals)
# ---------------------------------------------------------------------------
#
# The attendance-mode counterpart of CLEAR_RECORDS above, and the one string
# in this module that is NOT from the Security PUSH document. Verbatim from
# ZKTeco's Attendance PUSH Communication Protocol, software 2.4.1, doc v3.7:
# "Clearing Attendance Record. To clear the client attendance record, the
# command format is: C:${CmdID}:CLEAR${SP}LOG", answered with
# `ID=${XXX}&Return=${XXX}&CMD=CLEAR_LOG`. From the document; not yet observed
# on hardware. The reply needs no reading of its own: CLEAR_LOG is neither a
# query nor an enrolment, so commands.verdict_for takes Return=0 as done and a
# negative code as a refusal, as it does for any other status.
#
# Same caveat as CLEAR_RECORDS: it empties the TERMINAL's punch buffer and
# nothing already ingested here — `attendance_logs` is the server's history and
# no acknowledgement of this command touches it.
#
# Two neighbours in the same §12.2 are one word away and must never be sent in
# its place. §12.2.2 `CLEAR PHOTO` clears attendance photos, which is not what
# "clear attendance" means to an operator. §12.2.3 is "Clearing All Data. To
# clear all client data" — CLEAR followed by DATA — which wipes every user,
# fingerprint and record on the terminal: a factory reset of its contents, with
# no undo. Nothing in this application builds that string, and the AST guard
# in tests/test_adms.py (UnverifiedControlCommandsAreNotInventedTests) keeps
# it out of every module, this one included.
#
# Not on an `acc` terminal either: it has no ATTLOG, and its stored events are
# the `transaction` table above.
CLEAR_ATT_RECORDS = "CLEAR LOG"


# ---------------------------------------------------------------------------
# AC_UNLOCK — Attendance PUSH 2.4.1 §12.7.2, p.97 (`att` terminals)
# ---------------------------------------------------------------------------
#
# The attendance-mode counterpart of unlock_command above. Verbatim from the
# Attendance PUSH document: "Outputting the Door Unlocking Signal. The access
# equipment outputs the door unlocking signal. The command format is:
# C:${CmdID}:AC_UNLOCK", answered with `ID=${XXX}&Return=${XXX}&CMD=AC_UNLOCK`.
# From the document; not yet observed on hardware. The BioPro SA20 has a lock
# relay, door sensor and exit-button interface, so it is the hardware this
# section describes, but nobody has yet watched its relay fire on this command.
#
# IT TAKES NO PARAMETERS — no door, no duration. That is the whole of §12.7.2,
# and nothing else in the document qualifies it. So the two things an `acc`
# unlock is built from cannot be expressed here, and are not invented:
#
#   * duration — the terminal holds the lock open for its OWN configured lock
#     time, set on the terminal, whatever the operator asked for. The endpoint
#     says so in its reply rather than echoing a number it never sent.
#   * door — an attendance terminal drives one lock and the command names
#     none. The endpoint refuses a request for any door but the first rather
#     than open the one door it can while claiming to have opened another.
#
# The reply is a plain status, read by commands.verdict_for's general rule:
# Return=0 the signal was output, negative refused (Appendix 1 has no codes of
# its own for it). Like the `acc` unlock it is queued with
# DOOR_COMMAND_TTL_SECONDS, so it is one-shot and never delivered late — see
# "Why a door command is one-shot" below; the deadline lives on the outbox row,
# so the sweep and the dispatcher treat it exactly as they treat the `acc` one.
#
# §12.7.3 `AC_UNALARM` sits beside it and is a different action (cancel an
# alarm output). It is not sent from here.
UNLOCK_ATT_DOOR = "AC_UNLOCK"


# ---------------------------------------------------------------------------
# REBOOT — Attendance PUSH 2.4.1 §12.7.1, p.96 (`att` terminals)
# ---------------------------------------------------------------------------
#
# The attendance-mode counterpart of restart_command above. Verbatim from the
# Attendance PUSH document: "Rebooting the Client. To reboot the client, the
# command format is: C:${CmdID}:REBOOT", answered with
# `ID=${XXX}&Return=${XXX}&CMD=REBOOT`. From the document; not yet observed on
# hardware. No parameters.
#
# THE REPLY MAY NEVER COME. The section says the terminal answers, and says
# nothing about whether it answers before it goes down. A terminal that
# reboots first has no command left to reply about when it comes back, and
# the queue's ordinary rule for silence — offer it again after the backoff,
# up to COMMAND_MAX_ATTEMPTS times — would turn one lost reply into a terminal
# restarting itself every few minutes for an hour, mid-shift. So this command
# is handed over once and never again (commands.delivery_limit): no reply
# within the first backoff and it is concluded unacknowledged, not re-sent.
# Whether the SA20 replies first is the thing to watch on hardware.
#
# A reply that does come is a plain status, read by commands.verdict_for's
# general rule: Return=0 accepted, negative refused.
#
# No deadline, like the `acc` restart: queued with the queue's usual patience,
# so a terminal that is offline when asked restarts when it next polls.
RESTART_ATT_DEVICE = "REBOOT"


# ---------------------------------------------------------------------------
# What an `att` terminal reports about itself — three doors, one record
# ---------------------------------------------------------------------------
#
# The attendance-mode counterpart of GET OPTIONS above. An `att` terminal
# behind NAT cannot be dialled for its Device Info any more than an `acc` one
# can, so its Device Info is the last thing it reported, from whichever of
# three doors the report came through. All three are Attendance PUSH 2.4.1:
#
#   1. §8 "Pushing Configuration Information": `POST cdata?table=options`, a
#      comma-separated `key=value` line, the same shape parse_options reads.
#      The terminal sends it unasked after it connects.
#   2. §9 "Uploading Update Information": an `INFO=` parameter on
#      `GET /iclock/getrequest`, ten POSITIONAL comma-separated values with no
#      keys (UPDATE_INFORMATION_KEYS below). Seen on the BioPro SA20
#      CPV2232560497 as `INFO=Ver 8.0.4.6-20211123,459,479,62501,10.39.1.200,
#      10,-1,0,0,101,4,14,0` — thirteen values, of which the document names the
#      first ten.
#   3. §12.4.3 `INFO`, the command below, answered on /iclock/devicecmd with
#      `key=value` lines after the ID/Return/CMD line.
#
# Each door carries a different part of the picture, and a later report on one
# door must not erase what another one said — the options push arrives after
# every connection and may carry only `FingerFunOn=1,FaceFunOn=1` (the §8
# example). So for an `att` terminal the three are folded into one parameter
# line, newest value per key (merge_parameters), kept where an `acc`
# terminal's line is kept, `Device.capabilities`. An `acc` terminal's line is
# still replaced whole, as it always was: GET OPTIONS answers with every key
# asked for, so replacing it loses nothing.


# INFO — Attendance PUSH 2.4.1 §12.4.3, p.91. Verbatim: "Sending Client
# Information to the Server. The server gets information such as client
# configuration. The command format is: C:${CmdID}:INFO", answered with
# `ID=${XXX}&Return=${XXX}&CMD=INFO${LF}${Key}=${Value}${LF}${Key}=${Value}…`,
# "specific customer configuration information, in the form of key-value".
# From the document; not yet observed on hardware. No parameters.
#
# The document names none of the keys, so none is assumed: parse_info_reply
# keeps every line as the terminal wrote it, and options_as_info shows the
# ones whose names it knows. Which keys the SA20 actually sends is the thing
# to read in its stored line (or the first 500 characters the devicecmd log
# line keeps) the first time it answers — and, if they
# include `~MaxUserCount` or `~MaxAttLogCount`, whether those are plain
# capacities: options_as_info shows them as Max Users / Max Records verbatim,
# and attendance firmware is said, unverified, to report them in hundreds and
# ten-thousands.
#
# The reply's Return is a plain status, read by commands.verdict_for's general
# rule: 0 answered, negative refused. Its key=value lines are stored only from
# a reply that is acknowledged (adms_devicecmd). Repeating it is harmless — it
# changes nothing on the terminal — so it keeps the queue's ordinary retries
# and patience, and an identical one already outstanding is reused, as GET
# OPTIONS is.
QUERY_ATT_INFO = "INFO"


# §9's ten positional values, in order, under the key names this server
# files them as. THE NAMES ARE THIS SERVER'S, NOT THE DOCUMENT'S: §9 numbers
# the values and describes them ("Firmware version number", "Number of
# enrolled users", …) without naming them. The ones chosen are the names
# ZKTeco attendance firmware is commonly seen to use for the same facts in an
# INFO reply, so that a reply carrying them (once one is observed) updates the
# same entries rather than sitting beside them under a second name. `None`
# marks a value not kept: Value8 ("Number of faces required for face
# enrollment") is an enrolment setting, not something Device Info shows, and
# Value10 is a string of function-support bits whose fourth and fifth digits
# depend on terminal parameters. Anything past the tenth (the SA20 sends three
# more) has no meaning in the document and is not kept either.
UPDATE_INFORMATION_PARAMETER = "INFO"   # the getrequest parameter's name, §9

UPDATE_INFORMATION_KEYS = (
    "FWVersion",          # Value1  "Firmware version number"
    "UserCount",          # Value2  "Number of enrolled users"
    "FPCount",            # Value3  "Number of enrolled fingerprints"
    "TransactionCount",   # Value4  "Number of attendance records"
    "IPAddress",          # Value5  "IP address of Equipment"
    "FPVersion",          # Value6  "Version of fingerprint algorithm"
    "FaceVersion",        # Value7  "Version of face algorithm"
    None,                 # Value8  "Number of faces required for face enrollment"
    "FaceCount",          # Value9  "Number of enrolled faces"
    None,                 # Value10 "Identifier of functions supported"
)


def parse_update_information(value: str) -> dict:
    """§9's positional ``INFO=`` value, as a dict under UPDATE_INFORMATION_KEYS.

    Values are kept as strings, exactly as sent (the SA20's face algorithm
    version is ``-1``, which is what it says, not an error to correct). An
    empty position says nothing and is left out, so it never blanks a value
    another report supplied. Never raises.
    """
    out = {}
    for key, raw in zip(UPDATE_INFORMATION_KEYS, (value or "").split(",")):
        raw = raw.strip()
        if key and raw:
            out[key] = raw
    return out


def parse_info_reply(lines) -> dict:
    """The ``${Key}=${Value}`` lines of an ``INFO`` reply (§12.4.3), as a dict.

    One pair per line. Split on the first ``=`` only, so a value containing
    one survives; a line with no ``=`` is not a pair and is skipped. Values are
    kept as sent, like parse_options. Never raises.
    """
    out = {}
    for line in lines or ():
        key, sep, value = (line or "").partition("=")
        key = key.strip()
        if sep and key:
            out[key] = value.strip()
    return out


def merge_parameters(line: str, fields: dict) -> str:
    """``line`` with ``fields`` folded in, newest value per key.

    The stored form stays the comma-separated parameter line parse_options
    reads, so one reader serves both protocols. That form cannot carry a comma
    inside a value: parse_options would cut such a value at the comma, as it
    always has for an `acc` line. Device Info is display-only, and no value a
    terminal is known to report contains one.
    """
    merged = parse_options(line)
    merged.update(fields)
    return ",".join(f"{key}={value}" for key, value in merged.items())


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
    "was NOT opened. A terminal on the push queue only receives commands "
    "when it polls, and a door command is deliberately given a short life: opening "
    "a door minutes after somebody asked — when they have gone — is worse "
    "than not opening it. Check the terminal is online and try again."
)
