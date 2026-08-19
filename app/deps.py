"""Request authentication: opaque cookie sessions with CSRF double-submit.

There is no bearer token and no JWT. The browser holds an opaque session
token in a HttpOnly cookie; the server holds its digest and can revoke it at
any moment. Unsafe methods must additionally echo the session's CSRF token in
the X-CSRF-Token header, which script from another origin cannot read.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import User, UserSession
from app.security import constant_time_equals, hash_token

# Methods that change state and therefore need a CSRF token.
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# last_seen_at drives the idle timeout, but writing it on every single request
# is pointless churn — a coarse slide is enough.
_SLIDE_AFTER_SECONDS = 30


def _unauthorised(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Resolve the session cookie to a live user, or raise 401.

    Also enforces CSRF on unsafe methods and stores the session on
    ``request.state.session`` so the auth router can revoke it."""
    token = request.cookies.get(config.SESSION_COOKIE_NAME)
    if not token:
        raise _unauthorised()

    session = db.query(UserSession).filter_by(token_hash=hash_token(token)).first()
    if not session or session.revoked:
        raise _unauthorised("Session expired")

    now = datetime.now(timezone.utc)

    # Absolute cap first, then the idle window. Either one ends the session
    # for good rather than merely rejecting this request.
    if session.expires_at <= now:
        session.revoked = True
        db.commit()
        raise _unauthorised("Session expired")

    idle_deadline = session.last_seen_at + timedelta(minutes=config.SESSION_IDLE_MINUTES)
    if idle_deadline <= now:
        session.revoked = True
        db.commit()
        raise _unauthorised("Session expired")

    user = db.query(User).filter_by(id=session.user_id).first()
    if not user or not user.is_active:
        session.revoked = True
        db.commit()
        raise _unauthorised("Session expired")

    if request.method in _UNSAFE_METHODS:
        header = request.headers.get("X-CSRF-Token", "")
        if not constant_time_equals(header, session.csrf_token or ""):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid")

    if (now - session.last_seen_at).total_seconds() >= _SLIDE_AFTER_SECONDS:
        session.last_seen_at = now
        db.commit()

    request.state.session = session
    return user


def require_auth(user: User = Depends(current_user)) -> User:
    """Standard guard for every authenticated route.

    Name and signature are unchanged from the bearer-token version, so routers
    that declare ``dependencies=[Depends(require_auth)]`` keep working.

    An account still carrying a forced password change may only reach the
    handful of /auth routes that let it change that password."""
    if user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required",
        )
    return user


def require_admin(user: User = Depends(require_auth)) -> User:
    """Guard for routes a viewer must not reach."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return user
