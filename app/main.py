import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app.routers import adms, attendance, auth, devices, employees
from app.routers import hrm_sync
from app.database import SessionLocal
from app.models import HrmIntegration
from app.services.hrm_sync import run_sync

log = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

_scheduler = None


def _hrm_tick():
    """Called every 60s. Checks DB interval before actually running."""
    db = SessionLocal()
    try:
        row = db.query(HrmIntegration).filter_by(id=1).first()
        if not row or not row.enabled or not row.endpoint or not row.secret:
            return
        from datetime import datetime, timedelta
        interval = row.interval_seconds or 300
        if row.last_run_at and (datetime.utcnow() - row.last_run_at) < timedelta(seconds=interval):
            return
    finally:
        db.close()
    run_sync()


def _start_scheduler():
    global _scheduler
    from apscheduler.schedulers.background import BackgroundScheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_hrm_tick, "interval", seconds=60, id="hrm_tick")
    _scheduler.start()
    log.info("HRM sync scheduler started (60s tick)")


@asynccontextmanager
async def lifespan(app: FastAPI):
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
