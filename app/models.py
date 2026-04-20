from sqlalchemy import Column, Integer, String, DateTime, Boolean, UniqueConstraint, Enum, Text
from sqlalchemy.sql import func
from app.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    serial_number = Column(String(50), unique=True, nullable=False, index=True)
    ip_address = Column(String(50), nullable=False)
    port = Column(Integer, default=4370)
    name = Column(String(100), nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_online = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(24), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    privilege = Column(Integer, default=0)
    card = Column(String(20), default="0")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class DeviceEmployee(Base):
    __tablename__ = "device_employees"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    user_id = Column(String(24), nullable=False, index=True)
    uid = Column(Integer, nullable=False)  # device-local sequence number, varies per device
    synced_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

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
    source = Column(Enum("adms_push", "sdk_pull"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("device_sn", "user_id", "timestamp", name="uq_attendance"),
    )


class DeviceCommand(Base):
    __tablename__ = "device_commands"

    id = Column(Integer, primary_key=True)
    device_sn = Column(String(50), nullable=False, index=True)
    command = Column(String(500), nullable=False)
    status = Column(Enum("pending", "sent", "acknowledged"), default="pending")
    created_at = Column(DateTime, server_default=func.now())


class FingerprintTemplate(Base):
    __tablename__ = "fingerprint_templates"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(24), nullable=False, index=True)
    finger_id = Column(Integer, nullable=False)          # 0-9, which finger
    valid = Column(Integer, nullable=False, default=1)
    template = Column(Text, nullable=False)              # hex-encoded binary from pyzk
    source_device_sn = Column(String(50), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("user_id", "finger_id", name="uq_fingerprint"),
    )
