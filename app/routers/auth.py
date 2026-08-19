"""Sign-in, sign-out and password management.

Failure messages here are deliberately identical for an unknown username and
a wrong password — a login form must not become a user-enumeration oracle.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.deps import current_user, require_auth
from app.models import User, UserSession
from app.net import client_ip
from app.schemas import ChangePasswordRequest, LoginRequest, PasswordVerify, SessionOut
from app.security import generate_token, hash_password, hash_token, needs_rehash, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

log = logging.getLogger(__name__)

_GENERIC_FAILURE = "Invalid username or password"
_MIN_PASSWORD_LENGTH = 8


def _now():
    return datetime.now(timezone.utc)


def _session_payload(user: User, session: UserSession) -> SessionOut:
    return SessionOut(
        username=user.username,
        role=user.role,
        must_change_password=bool(user.must_change_password),
        csrf_token=session.csrf_token,
    )


def _set_session_cookie(response: Response, token: str) -> None:
    """SameSite=Strict means the cookie never rides along with a cross-site
    request, which is the first half of the CSRF defence; the X-CSRF-Token
    header is the second."""
    response.set_cookie(
        key=config.SESSION_COOKIE_NAME,
        value=token,
        max_age=config.SESSION_ABSOLUTE_HOURS * 3600,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _register_failure(user: User, db: Session) -> None:
    """Count a bad password and lock the account once it hits the limit."""
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= config.LOGIN_MAX_ATTEMPTS:
        user.locked_until = _now() + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)
        log.warning(
            "Account '%s' locked for %s minutes after %s failed sign-in attempts",
            user.username,
            config.LOGIN_LOCKOUT_MINUTES,
            user.failed_attempts,
        )
    db.commit()


@router.post("/login", response_model=SessionOut)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=payload.username).first()

    # No user, or a disabled one: same answer as a wrong password.
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail=_GENERIC_FAILURE)

    if user.locked_until and user.locked_until > _now():
        remaining = int((user.locked_until - _now()).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=423,
            detail=f"Account locked after too many failed attempts. Try again in {remaining} minute(s).",
        )

    if not verify_password(payload.password, user.password_hash):
        _register_failure(user, db)
        raise HTTPException(status_code=401, detail=_GENERIC_FAILURE)

    # Success — the lockout counter starts again from zero.
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = _now()
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    token = generate_token()
    session = UserSession(
        token_hash=hash_token(token),
        user_id=user.id,
        csrf_token=generate_token(),
        expires_at=_now() + timedelta(hours=config.SESSION_ABSOLUTE_HOURS),
        last_seen_at=_now(),
        revoked=False,
        ip=client_ip(request),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
    )
    db.add(session)
    db.commit()

    _set_session_cookie(response, token)
    log.info("User '%s' signed in", user.username)
    return _session_payload(user, session)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           user: User = Depends(current_user)):
    """Revoke server-side first — clearing the cookie alone would leave a
    stolen token usable."""
    session = getattr(request.state, "session", None)
    if session is not None:
        session.revoked = True
        db.commit()
    response.delete_cookie(
        key=config.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
    )
    log.info("User '%s' signed out", user.username)


@router.get("/me", response_model=SessionOut)
def me(request: Request, user: User = Depends(current_user)):
    """Also re-seeds the CSRF token after a page reload, since the frontend
    keeps it in memory only."""
    return _session_payload(user, request.state.session)


@router.post("/change-password", status_code=204)
def change_password(payload: ChangePasswordRequest, request: Request,
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if len(payload.new_password) < _MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"New password must be at least {_MIN_PASSWORD_LENGTH} characters",
        )
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")

    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False

    # Anything signed in with the old password loses its session; the browser
    # doing the change keeps its own.
    current = getattr(request.state, "session", None)
    keep_id = current.id if current is not None else None
    sessions = db.query(UserSession).filter_by(user_id=user.id, revoked=False).all()
    for session in sessions:
        if session.id != keep_id:
            session.revoked = True

    db.commit()
    log.info("User '%s' changed their password", user.username)


@router.post("/verify", status_code=204)
def verify(payload: PasswordVerify, user: User = Depends(require_auth)):
    """Re-authentication for destructive actions in the UI. Path and request
    shape are unchanged — PasswordConfirmModal.jsx posts {"password": "..."}."""
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
