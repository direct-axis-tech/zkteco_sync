import logging
import mimetypes
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Some Linux distros ship a system mime.types (mime-support package) that
# files .js/.mjs under text/plain, predating ES modules. That overrides
# Python's own guess and makes browsers reject the frontend bundle under
# strict MIME checking for <script type="module">. Force the correct types
# regardless of what the OS provides.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")

from app import config
from app.database import Base, engine
from app.middleware import MaxBodySizeMiddleware, SecurityHeadersMiddleware
from app.migrations import run_migrations
from app.routers import adms, attendance, audit, auth, devices, employees, users
from app.routers import hrm_sync
from app.database import SessionLocal
from app.models import HrmIntegration
from app.services.bootstrap import seed_first_admin
from app.services.hrm_sync import run_sync

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

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
        from datetime import datetime, timedelta, timezone
        interval = row.interval_seconds or 300
        if row.last_run_at and (datetime.now(timezone.utc) - row.last_run_at) < timedelta(seconds=interval):
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
    # create_all above only builds missing tables; run_migrations brings
    # existing ones up to date before anything queries them.
    run_migrations(engine)
    seed_first_admin()
    _start_scheduler()
    yield
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


app = FastAPI(
    title="ZKTeco Sync",
    version="1.0.0",
    lifespan=lifespan,
    # Publicly reachable on the internet now, so the interactive API
    # explorer is off unless an operator deliberately opts in.
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url="/redoc" if config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)

# No CORSMiddleware: the SPA is always same-origin. In production FastAPI
# serves frontend/dist itself; in development the browser only ever talks to
# the Vite dev server, which proxies /api to this app server-to-server, so
# the browser never makes a cross-origin request in the first place. The
# session cookie is also SameSite=Strict, so even a browser that did send a
# cross-origin request wouldn't carry it. Wiring up CORS here would only add
# a path for some other origin to be allowed in by mistake, for no benefit.

# Middleware runs in the reverse of the order added below, so TrustedHost
# (the cheapest, most important gate — reject an unrecognised Host before
# doing anything else) ends up outermost, checked first on every request.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MaxBodySizeMiddleware, max_bytes=config.MAX_REQUEST_BYTES)
app.add_middleware(
    TrustedHostMiddleware,
    # ALLOWED_HOSTS is required in production (app/config.py refuses to
    # boot without it there). In development it is commonly left unset, so
    # fall back to the addresses a local dev/test instance is actually
    # reached on instead of rejecting every request.
    allowed_hosts=config.ALLOWED_HOSTS or ["localhost", "127.0.0.1", "::1"],
)

app.include_router(auth.router)
app.include_router(adms.router)
app.include_router(devices.router)
app.include_router(employees.router)
app.include_router(attendance.router)
app.include_router(hrm_sync.router)
app.include_router(users.router)
app.include_router(audit.router)

# Serve the React build — must come last so API routes take priority.
_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(_dist):
    _index_html = os.path.join(_dist, "index.html")

    async def _spa_shell(request: Request):
        return FileResponse(_index_html)

    # StaticFiles(html=True) below only serves index.html for "/" itself and
    # for on-disk directories — it has no SPA history-fallback, so a hard
    # GET/reload of a client-side route 404s unless we hand it index.html
    # explicitly. Only routes no API router owns are safe to add here:
    # /devices, /employees, /attendance, /users, /auth, /hrm-sync and
    # /iclock are all claimed by routers above and must not be shadowed.
    for _path in ("/login", "/change-password", "/settings"):
        app.add_api_route(_path, _spa_shell, methods=["GET"], include_in_schema=False)

    app.mount("/", StaticFiles(directory=_dist, html=True), name="spa")
