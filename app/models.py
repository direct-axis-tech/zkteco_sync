from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Boolean, Index, UniqueConstraint, Enum, Text
from app import config
from app.database import Base, UTCDateTime as DateTime

_now = lambda: datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(50), unique=True, nullable=False, index=True)
    ip_address = Column(String(50), nullable=False)
    port = Column(Integer, default=4370)
    name = Column(String(100), nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_online = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)

    # Device trust. /iclock/* is reachable from the public internet, so a
    # serial only pushes once an admin has approved it — a newly seen serial
    # lands in "pending" and does nothing until then.
    status = Column(
        Enum("pending", "approved", "rejected", name="device_status"),
        nullable=False,
        default="pending",
    )
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(String(150), nullable=True)   # username, for accountability
    # Optional second factor for sites with a static IP: when enabled the push
    # must also arrive from inside allowed_cidrs. Off by default because some
    # sites are on dynamic addresses (locked decision D4).
    ip_check_enabled = Column(Boolean, nullable=False, default=False)
    allowed_cidrs = Column(Text, nullable=True)        # comma-separated CIDRs or bare IPs
    last_ip = Column(String(64), nullable=True)        # resolved source of the last push

    # SDK comm key (pyzk's `password`) — the only authentication on TCP 4370.
    # A secret: write-only from the API's point of view. 0 means "no key set",
    # matching pyzk's own default, so a device that never had a key keeps
    # connecting exactly as before this column existed.
    comm_key = Column(Integer, nullable=False, default=0)

    # Which of ZKTeco's two PUSH protocol families this serial speaks. They
    # share the /iclock/* URL space but disagree on the handshake reply, so
    # the server has to know which one it is talking to. "att" is the default
    # precisely so that every row which existed before this column keeps
    # receiving the byte-for-byte legacy handshake it has always had — a
    # serial only becomes "acc" once it has said so itself, either by sending
    # DeviceType=acc or by calling an endpoint that exists only in the
    # Security protocol.
    protocol = Column(
        Enum("att", "acc", name="device_protocol"),
        nullable=False,
        default="att",
    )
    # Set by PATCH /devices/{sn}/protocol (E6) — an operator correcting the
    # protocol directly, for a terminal switched between cloud and local
    # server modes. True from the moment of that call until the device itself
    # produces evidence that contradicts it (DeviceType=acc on a handshake, an
    # ATTLOG push, or a call to /iclock/registry or /iclock/push — the same
    # signals `_set_protocol` has always acted on). While pinned, that
    # automatic reclassification is not silently applied: it still happens,
    # because a genuinely reconfigured device must self-heal exactly as D9
    # intended, but `_set_protocol` clears the pin and audits the moment
    # distinctly (`adms_protocol_change` with "overriding manual pin" in
    # `detail`) so an operator can see the value did not just drift back on
    # its own. Not pinned == the column is fully automatic, as it always was.
    protocol_pinned = Column(Boolean, nullable=False, default=False)
    # Opaque values the Security protocol asks the server to mint and the
    # device folds into its own session token. Neither is validated here —
    # the device derives a token from them and presents it back, but our
    # trust decision is the approved-serial + CIDR allowlist, which is
    # strictly stronger than a token computed from values we handed out in
    # cleartext. They are persisted only so the same values survive a
    # restart, since the device keeps using the ones it was first given.
    registry_code = Column(String(64), nullable=True)
    session_id = Column(String(64), nullable=True)
    # The raw comma-separated parameter line the device pushes at registration
    # (and again on table=options). It is a complete capability inventory in
    # one column — FaceFunOn, MultiBioDataSupport, MachineType and the rest —
    # and is stored verbatim rather than parsed, because nothing here needs
    # to understand it yet and a parser would be a guess.
    capabilities = Column(Text, nullable=True)

    # What the digits on this device's clock mean. The device sends a bare
    # wall-clock string with no offset, so without this column the server is
    # guessing — and it guessed UTC, which is how a 14:48 punch came to be
    # displayed as 18:48. Seeded from DEFAULT_DEVICE_TIMEZONE at registration
    # and changed only through the dedicated timezone endpoint, because
    # changing it relabels every historical record for the device.
    # A scalar default (not a callable) on purpose: app/migrations.py compiles
    # it into the ALTER TABLE as a server DEFAULT, so existing rows on an
    # upgraded install get a value from the database itself.
    timezone = Column(String(64), nullable=False, default=config.DEFAULT_DEVICE_TIMEZONE)

    @property
    def comm_key_set(self) -> bool:
        """The only externally-visible fact about the comm key: whether one
        is configured. Never expose ``comm_key`` itself outside this model."""
        return bool(self.comm_key)


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(24), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    privilege = Column(Integer, default=0)
    card = Column(String(20), default="0")
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)


class DeviceEmployee(Base):
    __tablename__ = "device_employees"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    user_id = Column(String(24), nullable=False, index=True)
    uid = Column(Integer, nullable=False)  # device-local sequence number, varies per device
    synced_at = Column(DateTime, default=_now, onupdate=_now)

    __table_args__ = (
        UniqueConstraint("device_sn", "user_id", name="uq_device_employee"),
    )


class AttendanceLog(Base):
    __tablename__ = "attendance_logs"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    user_id = Column(String(24), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    status = Column(Integer, nullable=False)   # 0=check-in 1=check-out 4=OT-in 5=OT-out
    punch = Column(Integer, default=0)          # verify mode: 1=finger 3=password 4=card 15=face
    source = Column(Enum("adms_push", "sdk_pull", name="attendance_source"), nullable=False)
    created_at = Column(DateTime, default=_now)

    # Provenance for rows that arrived as Security-protocol `rtlog` records.
    # All three are deliberately opaque. Which `event` codes represent a
    # successful verification on this firmware is not established (the
    # protocol document's appendix is unreadable), so the value is *recorded*
    # rather than filtered on: an abnormal event briefly counted as a punch is
    # a visible, correctable data error, whereas a real punch dropped by a
    # wrong guess is silent and unrecoverable. Null on every legacy ATTLOG and
    # SDK-pull row.
    event_code = Column(String(16), nullable=True)
    # A string, not an int: 3.1.2 may report verification mode either as a
    # small decimal or as a 16-character bitmask (`0000000000000010` = face),
    # and int() would quietly turn the latter into the unrelated value 10.
    verify_type = Column(String(32), nullable=True)
    # The device-unique record ID from `rtlog`. Indexed because it is the
    # dedup key for pushes from an `acc` device.
    record_index = Column(String(32), nullable=True, index=True)

    # What `timestamp`'s digits mean: a snapshot of the device's timezone
    # taken at insert. Snapshotted rather than joined so a record keeps its
    # own meaning even if the device row is later edited or deleted, and so
    # two devices in different zones can be read side by side without every
    # consumer having to resolve the device first.
    #
    # Nullable on purpose. Rows that predate this column are backfilled by
    # app/migrations.py from their device, but a null must never be fatal:
    # every reader falls back to the device's zone and then to
    # DEFAULT_DEVICE_TIMEZONE. `timestamp` itself is never rewritten by
    # anything — not on ingest, not on relabel, not on push.
    timezone = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("device_sn", "user_id", "timestamp", name="uq_attendance"),
    )


class DeviceCommand(Base):
    """DEAD TABLE — superseded by DeviceCommandOutbox / DeviceCommandLog (E7).

    Nothing reads or writes this any more: /iclock/getrequest and
    POST /devices/{sn}/commands both moved to the outbox. It is left mapped
    only because app/migrations.py is additive-only by design and dropping
    tables is not something it does — the one production row is a D3 test
    artefact. Do not wire anything back to it; queue through
    app/services/commands.py instead.
    """

    __tablename__ = "device_commands"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    command = Column(String(500), nullable=False)
    status = Column(Enum("pending", "sent", "acknowledged", name="device_command_status"), default="pending")
    created_at = Column(DateTime, default=_now)


class DeviceCommandOutbox(Base):
    """Outstanding work only — a row exists here IFF the command is unresolved.

    This is the table /iclock/getrequest scans on every poll (every ~10s per
    device, forever), so it is kept to exactly the commands still owed to a
    device. The moment one is acknowledged or given up on it is *moved* to
    device_command_log in a single transaction, so this table drains itself
    and the hot path stays small no matter how much history accumulates.
    """

    __tablename__ = "device_command_outbox"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)

    # Text, not String(500): E3/E4 will push biophoto/facev7 commands whose
    # Content= field is base64 image or template data, which does not fit in
    # the 500 characters the dead table allowed.
    command = Column(Text, nullable=False)

    # Only two states can be outstanding. `acknowledged` and `failed` are not
    # values here — they are outcomes in device_command_log, which is what
    # avoids ever having to widen an enum in a live database.
    status = Column(
        Enum("pending", "sent", name="device_command_outbox_status"),
        nullable=False,
        default="pending",
    )

    # Deliveries attempted, not seconds elapsed. A command that is still
    # `pending` because the device has not polled has attempts=0 and is not
    # failing at anything.
    attempts = Column(Integer, nullable=False, default=0)

    # When a delivered-but-unacknowledged command may be offered again. Null
    # while pending — there is nothing to wait for until it has been sent once.
    next_attempt_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=_now)
    sent_at = Column(DateTime, nullable=True)   # most recent delivery

    __table_args__ = (
        Index("ix_outbox_dispatch", "device_sn", "status"),
    )


class DeviceCommandLog(Base):
    """Append-only history of concluded commands.

    Written only by the atomic move out of the outbox, so every row here is a
    command that is definitively over: the device either acknowledged it or it
    was given up on, with the reason recorded. Pruned on a schedule by
    retention age; never read by the delivery hot path.
    """

    __tablename__ = "device_command_log"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    command = Column(Text, nullable=False)

    outcome = Column(
        Enum("acknowledged", "failed", name="device_command_outcome"),
        nullable=False,
    )

    attempts = Column(Integer, nullable=False, default=0)

    # As reported by the device: 0 = success, non-zero = the device refusing
    # the command. Null when the command was never answered at all.
    return_code = Column(Integer, nullable=True)
    last_error = Column(String(255), nullable=True)

    created_at = Column(DateTime, nullable=False, default=_now)   # queued
    sent_at = Column(DateTime, nullable=True)                     # last delivery
    concluded_at = Column(DateTime, nullable=False, default=_now, index=True)


class FingerprintTemplate(Base):
    __tablename__ = "fingerprint_templates"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(24), nullable=False, index=True)
    finger_id = Column(Integer, nullable=False)          # 0-9, which finger
    valid = Column(Integer, nullable=False, default=1)
    template = Column(Text, nullable=False)              # hex-encoded binary from pyzk
    source_device_sn = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)

    __table_args__ = (
        UniqueConstraint("user_id", "finger_id", name="uq_fingerprint"),
    )


class BiometricTemplate(Base):
    """Biometric templates from Security PUSH's `tabledata&tablename=biodata`
    bulk upload — ZKTeco's own "unified/hybrid" table, holding fingerprint
    (`type=1`) and face (`type=9`) templates side by side, and possibly other
    modalities `type` has not been observed to carry yet. That interpretation
    of `type` is evidence, not a rule this table enforces: it is stored as
    plain data, never branched on here.

    Deliberately NOT `fingerprint_templates`. That table is SDK-sourced
    (pyzk `get_templates()` over TCP 4370), keyed on `finger_id`, and stores a
    hex-packed pyzk-specific blob — a different provenance and a different
    field set. Folding `biodata` into it would corrupt both.

    Every field the device sent is kept verbatim, including ones with no use
    today (`duress`, `record_index`, `majorver`, `minorver`, `format`): E4
    (template push-down) must reconstruct

        DATA UPDATE BIODATA Pin=..\tNo=..\tIndex=..\tValid=..\tDuress=..\t
        Type=..\tMajorVer=..\tMinorVer=..\tFormat=..\tTmp=..

    from exactly these columns, and anything normalised away here is data it
    cannot send. The command's field names are CamelCase (`Index`, `Type`,
    `Format`...) while the upload's are lowercase (`index`, `type`,
    `format`...) — a documented asymmetry between §3.7 and §3.8 of the
    protocol spec, not a mismatch to "fix" by renaming.

    `index` itself is a reserved word in the SQL dialects this project must
    stay portable across (MariaDB/MySQL, PostgreSQL, MSSQL), so the column
    that holds the wire's `index=` value is named `record_index` — the same
    rename `AttendanceLog.record_index` already uses for the analogous field
    on `rtlog`. The value round-trips unchanged; only the column identifier
    differs from the wire.

    `tmp` is base64 text of a few KB, stored as-is and never decoded — the
    server has no need to understand the template, only to hold and later
    replay it.

    Keyed on `(user_id, type, no)`, confirmed unique against the operator's
    real capture (VGU6254600603, 2026-08-20): pin=1 carries a fingerprint
    record (`type=1, no=5`) and a face record (`type=9, no=0`) — two rows,
    two distinct keys, one person.
    """
    __tablename__ = "biometric_templates"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(24), nullable=False, index=True)   # the device's `pin`
    no = Column(Integer, nullable=False, default=0)
    record_index = Column(Integer, nullable=False, default=0)  # wire field `index`
    valid = Column(Integer, nullable=False, default=1)
    duress = Column(Integer, nullable=False, default=0)
    type = Column(Integer, nullable=False)                     # modality: data, not a branch taken here
    majorver = Column(Integer, nullable=False, default=0)
    minorver = Column(Integer, nullable=False, default=0)
    format = Column(Integer, nullable=False, default=0)
    tmp = Column(Text, nullable=False)                          # base64, verbatim, never decoded
    source_device_sn = Column(String(50), nullable=False)       # so E4 can avoid pushing a template back to its own source
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)

    __table_args__ = (
        UniqueConstraint("user_id", "type", "no", name="uq_biometric_template"),
    )


class HrmIntegration(Base):
    """Single-row table — config and sync state for the HRM push integration."""
    __tablename__ = "hrm_integration"

    id = Column(Integer, primary_key=True, default=1)
    # Config (editable from UI)
    endpoint = Column(String(500), nullable=True)
    secret = Column(String(200), nullable=True)
    location_id = Column(String(20), default="1")
    interval_seconds = Column(Integer, default=300)
    timezone = Column(String(50), default="UTC")
    enabled = Column(Boolean, default=True)
    # State (updated after each push; last_synced_id also editable from UI)
    last_synced_id = Column(Integer, default=0)
    last_run_at = Column(DateTime, nullable=True)
    records_last_push = Column(Integer, default=0)
    total_pushed = Column(Integer, default=0)
    last_error = Column(String(1000), nullable=True)


class AdmsPairing(Base):
    """Single-row table — the time-boxed window during which an unrecognised
    serial is filed for approval instead of being refused outright.

    Onboarding a device is the one moment the server must accept a serial it
    has never seen, so that moment is made deliberate, short and attributable
    rather than permanent."""
    __tablename__ = "adms_pairing"

    id = Column(Integer, primary_key=True, default=1)
    open_until = Column(DateTime, nullable=True)   # window is open while this is in the future
    opened_at = Column(DateTime, nullable=True)
    opened_by = Column(String(150), nullable=True)


class User(Base):
    """An operator account. Replaces the single credential pair in .env."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=True)
    password_hash = Column(String(255), nullable=False)   # Argon2id, never a plaintext password
    role = Column(Enum("admin", "viewer", name="user_role"), nullable=False, default="viewer")
    is_active = Column(Boolean, nullable=False, default=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)         # set once failed_attempts hits the limit
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)


class AuditLog(Base):
    """An append-only accountability trail for privileged and physical
    actions — the app is public-internet-facing now, so every action that
    touches trust, credentials or a physical door must be attributable to
    an actor and a source IP after the fact."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor = Column(String(150), nullable=False, index=True)   # username, or "system"/"device"
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(200), nullable=True)                # the object acted on, e.g. a serial or username
    ip = Column(String(64), nullable=True)
    detail = Column(Text, nullable=True)   # human-readable context — NEVER a secret value
    created_at = Column(DateTime, default=_now, index=True)    # the date-range filter needs this indexed


class UserSession(Base):
    """A live sign-in. The cookie carries an opaque token; only its SHA-256
    digest is stored here, so the table cannot be replayed if it leaks."""
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    csrf_token = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)   # absolute cap, independent of activity
    last_seen_at = Column(DateTime, nullable=False, default=_now)  # slides, drives the idle timeout
    revoked = Column(Boolean, nullable=False, default=False)
    ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=_now)
