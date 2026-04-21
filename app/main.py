import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app.routers import adms, attendance, auth, devices, employees, hrm_sync
from app.services.hrm_sync import is_configured, run_sync

log = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

_scheduler = None


def _start_scheduler():
    global _scheduler
    interval = int(os.getenv("HRM_SYNC_INTERVAL", "300"))
    from apscheduler.schedulers.background import BackgroundScheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(run_sync, "interval", seconds=interval, id="hrm_sync")
    _scheduler.start()
    log.info("HRM sync scheduler started (every %ds)", interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if is_configured():
        _start_scheduler()
    yield
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


app = FastAPI(title="ZKTeco Sync", version="1.0.0", lifespan=lifespan)

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
app.include_router(hrm_sync.router)

# Serve the React build — must come last so API routes take priority.
_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(_dist):
    app.mount("/", StaticFiles(directory=_dist, html=True), name="spa")
