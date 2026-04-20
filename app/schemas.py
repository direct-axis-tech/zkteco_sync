from pydantic import BaseModel
from datetime import datetime
from typing import Optional


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
    created_at: datetime

    class Config:
        from_attributes = True


class CommandCreate(BaseModel):
    command: str
