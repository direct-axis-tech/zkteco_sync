from pydantic import BaseModel, Field
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
    # SDK comm key (D7) — deliberately no `comm_key` field here. The key is a
    # secret and this is the only shape a device is allowed to leave the
    # server in; only whether one is set is observable.
    comm_key_set: bool = False

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

    class Config:
        from_attributes = True


class CommandCreate(BaseModel):
    command: str


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
