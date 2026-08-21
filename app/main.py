import logging
import mimetypes
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
from app.middleware import (
    MaxBodySizeMiddleware,
    SecurityHeadersMiddleware,
    SpaNavigationMiddleware,
)
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

# Schema creation happens in the lifespan handler, NOT at import time.
# Importing this module must not open a database connection: the test
# suite imports it, and at import time `.env` names the operator's real
# database, so a module-level create_all() made `import app.main` touch
# production from a unit test.

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


def _command_sweep_tick():
    """Retry/expiry/prune for the device command outbox and log (E7).

    Deliberately low-frequency and deliberately on the *existing* scheduler:
    none of this is time-critical and a second scheduler would be a second
    thing to leak. The retry itself does not happen here — a command is only
    ever re-offered when the device polls — so this job exists to conclude the
    commands no poll will ever resolve, and to keep history from growing
    without bound.

    Two jobs share this tick because they are two halves of one question:
    what has this queue given up on? `commands.sweep` retires the commands no
    poll will resolve; `withdraw_orphaned_templates` then retires the
    biometric templates that were queued behind one of them (E4). A user
    record that is refused is caught immediately, on the acknowledgement — but
    a user record that is *never acknowledged at all* only fails on a timer,
    and its templates must not outlive it and be delivered to a terminal that
    never took the person.
    """
    from app.services import commands, provisioning

    db = SessionLocal()
    try:
        commands.sweep(db)
        provisioning.withdraw_orphaned_templates(db)
    except Exception:
        # A failed sweep must never take the scheduler thread down with it;
        # the next tick will try again.
        log.exception("command sweep failed")
    finally:
        db.close()


def _start_scheduler():
    global _scheduler
    from apscheduler.schedulers.background import BackgroundScheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_hrm_tick, "interval", seconds=60, id="hrm_tick")
    _scheduler.add_job(
        _command_sweep_tick,
        "interval",
        minutes=config.COMMAND_SWEEP_MINUTES,
        id="command_sweep",
    )
    _scheduler.start()
    log.info(
        "Scheduler started: HRM sync (60s tick), command sweep (%sm tick)",
        config.COMMAND_SWEEP_MINUTES,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # create_all builds missing tables; run_migrations then brings existing
    # ones up to date before anything queries them. Both are deferred to
    # startup so that importing this module stays side-effect free.
    Base.metadata.create_all(bind=engine)
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

_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
_index_html = os.path.join(_dist, "index.html")

# Middleware runs in the reverse of the order added below, so TrustedHost
# (the cheapest, most important gate — reject an unrecognised Host before
# doing anything else) ends up outermost, checked first on every request.
#
# SpaNavigation is added first and therefore runs innermost, immediately
# before routing. That placement is deliberate: a bad Host is still rejected
# by TrustedHost before the shell is ever considered, MaxBodySize is
# untouched (it only guards request bodies, and this only claims GET/HEAD),
# and because SecurityHeaders wraps it, the shell it returns carries exactly
# the same CSP and friends as every other document response.
app.add_middleware(SpaNavigationMiddleware, index_html=_index_html)
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
#
# StaticFiles keeps serving the real files out of dist (bundles, favicon).
# Client-side routes never reach it: SpaNavigationMiddleware above answers a
# browser navigation with the shell before routing happens at all, which is
# what makes a hard reload of /devices work even though an API router owns
# that exact path.
if os.path.isdir(_dist):
    app.mount("/", StaticFiles(directory=_dist, html=True), name="spa")
