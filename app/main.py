from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import adms, attendance, auth, devices, employees

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ZKTeco Sync", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(adms.router)
app.include_router(devices.router)
app.include_router(employees.router)
app.include_router(attendance.router)
