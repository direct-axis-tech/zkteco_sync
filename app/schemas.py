from pydantic import BaseModel, Field, field_serializer
from datetime import datetime
from typing import Literal, Optional, List


class DeviceCreate(BaseModel):
    serial_number: str
    ip_address: str
    port: int = 4370
    name: Optional[str] = None
    # SDK comm key (D7) — write-only, see DeviceOut.comm_key_set. 0/omitted
    # means no key, matching pyzk's own default.
    comm_key: int = Field(default=0, ge=0)


class DeviceOut(BaseModel):
    id: int
    serial_number: str
    ip_address: str
    port: int
    name: Optional[str]
    last_seen: Optional[datetime]
    is_online: bool
    created_at: datetime
    # Device trust (D3)
    status: str
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    ip_check_enabled: bool = False
    allowed_cidrs: Optional[str] = None
    last_ip: Optional[str] = None
    # Which PUSH protocol family the device speaks (D9): "att" (Attendance,
    # the default and what every pre-existing device is) or "acc" (Security /
    # access control). Read-only on this shape — normally set automatically
    # from what the device announces about itself, but an operator can correct
    # it directly via PATCH /devices/{sn}/protocol (E6) when a terminal is
    # reconfigured between cloud and local server modes. `registry_code`,
    # `session_id` and `capabilities` are deliberately absent: the first two
    # are inputs to the device's session token and the third is a long
    # diagnostic blob, and neither belongs in a device listing.
    protocol: str = "att"
    # True when the current `protocol` value came from that manual PATCH
    # rather than from device traffic — the UI's answer to "why is this the
    # value it is". Cleared automatically, and audited, the moment the device
    # itself produces contradicting evidence (see Device.protocol_pinned).
    protocol_pinned: bool = False
    # What this device's clock digits mean (D10). Read-only on this shape and
    # on DeviceUpdate: changing it relabels every historical record for the
    # device, so it has its own endpoint (PATCH /devices/{sn}/timezone) rather
    # than riding along with a name or IP edit.
    timezone: Optional[str] = None
    # SDK comm key (D7) — deliberately no `comm_key` field here. The key is a
    # secret and this is the only shape a device is allowed to leave the
    # server in; only whether one is set is observable.
    comm_key_set: bool = False
    # How many people have been revoked from this device in the system and NOT
    # yet confirmed removed by the device itself (E8). Non-zero means somebody
    # can still open this door who is not supposed to be able to. It is on the
    # *device* shape as well as the person's page deliberately: an operator
    # scanning the device list for "is anything wrong" should not have to open
    # each employee in turn to find an outstanding revocation.
    pending_revocations: int = 0

    class Config:
        from_attributes = True


class EmployeeOut(BaseModel):
    id: int
    user_id: str
    name: str
    privilege: int
    card: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EmployeeCreate(BaseModel):
    """A person an operator is adding centrally, before any device knows them.

    ``user_id`` is the device PIN and the key every other table joins on, so
    it is required and immutable once set — renaming it would orphan the
    person's attendance history and their enrolled biometrics.
    """
    user_id: str = Field(min_length=1, max_length=24)
    name: str = Field(default="", max_length=100)
    # 0 = ordinary user, 14 = device administrator. Defaulted to 0 rather than
    # inherited from anything: 14 hands somebody the terminal's own menus.
    privilege: int = 0
    card: str = Field(default="", max_length=20)


class EmployeeUpdate(BaseModel):
    """A deliberate edit. Absent fields are left alone; empty ones are cleared.

    That distinction is the whole point of this shape and it is carried by
    ``exclude_unset`` at the router: a device may never empty a field it said
    nothing about, but an operator deleting a name means it.

    ``user_id`` is deliberately absent — see EmployeeCreate.
    """
    name: Optional[str] = Field(default=None, max_length=100)
    privilege: Optional[int] = None
    card: Optional[str] = Field(default=None, max_length=20)


class DeviceEmployeeOut(BaseModel):
    device_sn: str
    user_id: str
    uid: int
    synced_at: datetime

    class Config:
        from_attributes = True


class AttendanceOut(BaseModel):
    id: int
    device_sn: str
    user_id: str
    timestamp: datetime
    status: int
    punch: int
    source: str
    created_at: Optional[datetime] = None
    # The zone those digits are in — snapshotted from the device when the
    # record was stored. Null only for a row that predates the column and
    # whose device is gone; the UI shows the label it is given and never
    # invents one.
    timezone: Optional[str] = None

    class Config:
        from_attributes = True

    @field_serializer("timestamp")
    def _wall_clock(self, value: datetime) -> str:
        """Emit the punch time as the bare wall-clock the device sent.

        ``UTCDateTime`` stamps ``tzinfo=utc`` when it reads any DateTime
        column, which is right for ``created_at``, ``last_seen`` and session
        expiry — those really are UTC — and wrong for this one, which is the
        device's local clock. Serialising it with an offset is what let the
        browser "helpfully" re-convert a 14:48 punch into 18:48. So the offset
        is dropped here, at the boundary, rather than by changing UTCDateTime
        and disturbing every genuinely-UTC column in the app. The digits are
        untouched; ``timezone`` above says what they mean.
        """
        return value.strftime("%Y-%m-%d %H:%M:%S")


class CommandCreate(BaseModel):
    command: str


class CommandOut(BaseModel):
    """One outstanding command — a row of device_command_outbox.

    ``attempts=0`` with ``status='pending'`` is a command waiting for a device
    that has not polled yet. Nothing is wrong with it; do not present it as an
    error.
    """

    id: int
    device_sn: str
    command: str
    status: str
    attempts: int
    next_attempt_at: Optional[datetime] = None
    created_at: datetime
    sent_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CommandLogOut(BaseModel):
    """One concluded command — a row of device_command_log.

    ``outcome='failed'`` with a ``return_code`` means the device refused it;
    with no code, it means we gave up (``last_error`` says why).
    """

    id: int
    device_sn: str
    command: str
    outcome: str
    attempts: int
    return_code: Optional[int] = None
    last_error: Optional[str] = None
    created_at: datetime
    sent_at: Optional[datetime] = None
    concluded_at: datetime

    class Config:
        from_attributes = True


# --- Device info ---

class DeviceSizesOut(BaseModel):
    users: int
    fingers: int
    records: int
    cards: int
    faces: int
    users_cap: int
    fingers_cap: int
    rec_cap: int
    faces_cap: int


class DeviceNetworkOut(BaseModel):
    ip: str
    mask: str
    gateway: str


class DeviceInfoOut(BaseModel):
    serial_number: str
    firmware_version: str
    platform: str
    device_name: str
    mac: Optional[str]
    face_version: Optional[int]
    fp_version: Optional[int]
    pin_width: Optional[int]
    network: DeviceNetworkOut
    sizes: DeviceSizesOut


# --- Device control ---

class UnlockRequest(BaseModel):
    seconds: int = 3


class LcdRequest(BaseModel):
    line: int = 1
    text: str


class SetTimeRequest(BaseModel):
    sync: bool = False
    dt: Optional[str] = None  # ISO 8601, e.g. "2024-01-15T09:00:00" — used when sync=False


# --- Fingerprints ---

class FingerprintTemplateOut(BaseModel):
    id: int
    user_id: str
    finger_id: int
    valid: int
    template: str
    source_device_sn: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BiometricTemplateOut(BaseModel):
    """One captured biometric, described but not handed over.

    `tmp` — the template itself — is deliberately **not** in this schema. It
    is a biometric credential a few KB long; the server needs it to replay a
    `DATA UPDATE BIODATA` command to another terminal, and a browser needs
    only to know the template exists, where it came from and how big it is.
    Its size is reported instead, which is enough for an operator to see that
    something real is stored.

    `type` is passed through as the number the device sent. The protocol
    documents an enumeration (1 fingerprint, 9 visible-light face, and others)
    but nothing in this application branches on it and this schema does not
    start: it is data from the device, presented as data.
    """

    id: int
    user_id: str
    type: int
    no: int
    record_index: int
    valid: int
    duress: int
    majorver: int
    minorver: int
    format: int
    tmp_bytes: int
    source_device_sn: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EnrollRequest(BaseModel):
    finger_id: int = 0  # 0-9, which finger to enroll


# --- Auth ---

class LoginRequest(BaseModel):
    username: str
    password: str


class SessionOut(BaseModel):
    """Returned by /auth/login and /auth/me. The session token itself never
    appears here — it only ever travels in the HttpOnly cookie."""
    username: str
    role: str
    must_change_password: bool
    csrf_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordVerify(BaseModel):
    password: str


# --- Device update ---

class DeviceUpdate(BaseModel):
    ip_address: Optional[str] = None
    port: Optional[int] = None
    name: Optional[str] = None
    # Source-address pinning. `status` is deliberately absent: approval is not
    # an editable field, it happens through /approve and /reject.
    ip_check_enabled: Optional[bool] = None
    allowed_cidrs: Optional[str] = None   # comma-separated; "" or null clears it
    # SDK comm key (D7) — write-only. Omit to leave unchanged; send 0 to clear
    # it back to "no key".
    comm_key: Optional[int] = Field(default=None, ge=0)
    # `timezone` is deliberately absent, for the same reason `status` is.
    # Changing a device's zone relabels every attendance record it ever
    # pushed; that is a deliberate act with its own endpoint
    # (PATCH /devices/{sn}/timezone), not a field that can be nudged while
    # someone is editing an IP address.
    # `protocol` is deliberately absent, for the same reason. Correcting it is
    # a decision with real consequences elsewhere (which PUSH handshake reply
    # a device receives, which outbound transport E7 picks) and must go
    # through PATCH /devices/{sn}/protocol, which pins the value against
    # automatic drift and audits the change — not this generic PATCH.


class DeviceTimezoneUpdate(BaseModel):
    timezone: str   # IANA name, e.g. "Asia/Dubai"; validated against zoneinfo


class DeviceProtocolUpdate(BaseModel):
    # Literal, not str: the wire value is exactly "att" or "acc" (D9), so a
    # bad value is a 422 from FastAPI's own validation before the handler
    # ever runs, matching the model's own Enum.
    protocol: Literal["att", "acc"]


# --- ADMS pairing window ---

class PairingWindowOut(BaseModel):
    is_open: bool
    open_until: Optional[datetime] = None
    seconds_remaining: int = 0
    opened_at: Optional[datetime] = None
    opened_by: Optional[str] = None


class PairingOpenRequest(BaseModel):
    minutes: Optional[int] = None   # defaults to ADMS_PAIRING_MINUTES, capped at 120


class BulkPushRequest(BaseModel):
    user_ids: List[str]


# --- Operator accounts (admin-only) ---

class UserOut(BaseModel):
    """Never carries password_hash — this is the only shape a user record
    is allowed to leave the server in."""
    id: int
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    must_change_password: bool
    last_login_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str
    full_name: Optional[str] = None
    # A setup password chosen by the admin. must_change_password is always
    # forced True on create, so the admin never learns the operator's real one.
    password: str
    role: Literal["admin", "viewer"] = "viewer"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[Literal["admin", "viewer"]] = None
    is_active: Optional[bool] = None


class UserResetPassword(BaseModel):
    new_password: str


# --- Audit trail (admin-only) ---

class AuditLogOut(BaseModel):
    id: int
    actor: str
    action: str
    target: Optional[str]
    ip: Optional[str]
    detail: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
