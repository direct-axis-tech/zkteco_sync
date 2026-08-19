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
