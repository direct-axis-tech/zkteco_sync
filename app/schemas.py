from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class DeviceCreate(BaseModel):
    serial_number: str
    ip_address: str
    port: int = 4370
    name: Optional[str] = None


class DeviceOut(BaseModel):
    id: int
    serial_number: str
    ip_address: str
    port: int
    name: Optional[str]
    last_seen: Optional[datetime]
    is_online: bool
    created_at: datetime

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
    mac: str
    face_version: Optional[int]
    fp_version: int
    pin_width: int
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


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PasswordVerify(BaseModel):
    password: str


# --- Device update ---

class DeviceUpdate(BaseModel):
    ip_address: Optional[str] = None
    port: Optional[int] = None
    name: Optional[str] = None


class BulkPushRequest(BaseModel):
    user_ids: List[str]
