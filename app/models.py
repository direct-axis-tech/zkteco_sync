from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Boolean, UniqueConstraint, Enum, Text
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

    __table_args__ = (
        UniqueConstraint("device_sn", "user_id", "timestamp", name="uq_attendance"),
    )


class DeviceCommand(Base):
    __tablename__ = "device_commands"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    command = Column(String(500), nullable=False)
    status = Column(Enum("pending", "sent", "acknowledged", name="device_command_status"), default="pending")
    created_at = Column(DateTime, default=_now)


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
