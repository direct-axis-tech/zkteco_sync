from fastapi import FastAPI

from app.database import Base, engine
from app.routers import adms, attendance, devices, employees

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ZKTeco Sync", version="1.0.0")

app.include_router(adms.router)
app.include_router(devices.router)
app.include_router(employees.router)
app.include_router(attendance.router)
