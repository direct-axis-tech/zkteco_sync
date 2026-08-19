"""Operator account management — admin-only CRUD over the users table.

Two guard rails run on every mutation here, because either one breaking
would let an admin lock the whole team out of the app: an admin may not
demote, deactivate or delete their own account, and the last remaining
active admin may not be demoted, deactivated or deleted by anyone. Both are
enforced in Python, not the DB, so the error can name the rule that was hit.

There is no FK on user_sessions.user_id (see app/models.py), so anything
that should end a user's access immediately — delete, deactivate, role
change, password reset — must revoke their live sessions explicitly here.
Waiting for the session to expire on its own is not good enough.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import User, UserSession
from app.schemas import UserCreate, UserOut, UserResetPassword, UserUpdate
from app.security import hash_password

router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(require_admin)])

log = logging.getLogger(__name__)

_MIN_PASSWORD_LENGTH = 8


def _get_user_or_404(user_id: int, db: Session) -> User:
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _validate_password(password: str) -> None:
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {_MIN_PASSWORD_LENGTH} characters",
        )


def _revoke_live_sessions(db: Session, user_id: int) -> None:
    """No FK on user_sessions.user_id — revocation has to be explicit so a
    deactivated/deleted/reset user loses access immediately, not at next
    idle/absolute expiry."""
    db.query(UserSession).filter_by(user_id=user_id, revoked=False).update({"revoked": True})


def _active_admin_count(db: Session, exclude_id: Optional[int] = None) -> int:
    q = db.query(User).filter_by(role="admin", is_active=True)
    if exclude_id is not None:
        q = q.filter(User.id != exclude_id)
    return q.count()


@router.get("", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter_by(username=payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    _validate_password(payload.password)

    user = User(
        username=payload.username,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info("User '%s' created with role '%s'", user.username, user.role)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    user = _get_user_or_404(user_id, db)
    changes = payload.model_dump(exclude_unset=True)

    demoting = "role" in changes and changes["role"] != user.role
    deactivating = "is_active" in changes and user.is_active and changes["is_active"] is False

    if user.id == current.id and (demoting or deactivating):
        raise HTTPException(
            status_code=400,
            detail="You cannot demote or deactivate your own account.",
        )

    if user.role == "admin" and user.is_active and (demoting or deactivating):
        if _active_admin_count(db, exclude_id=user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail="This is the last active admin — demoting or deactivating it "
                       "would lock everyone out. Promote another user to admin first.",
            )

    for field, value in changes.items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)

    if demoting or deactivating:
        _revoke_live_sessions(db, user.id)
        db.commit()
        log.info("Revoked live sessions for '%s' after role/status change", user.username)

    return user


@router.post("/{user_id}/reset-password", status_code=204)
def reset_password(user_id: int, payload: UserResetPassword, db: Session = Depends(get_db)):
    """Sets a new setup password chosen by the admin and forces a change at
    next sign-in — the admin still never learns the operator's real password."""
    user = _get_user_or_404(user_id, db)
    _validate_password(payload.new_password)

    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = True
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    _revoke_live_sessions(db, user.id)
    db.commit()
    log.info("Password reset for user '%s'", user.username)


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    user = _get_user_or_404(user_id, db)

    if user.id == current.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    if user.role == "admin" and user.is_active:
        if _active_admin_count(db, exclude_id=user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail="This is the last active admin — deleting it would lock "
                       "everyone out. Promote another user to admin first.",
            )

    _revoke_live_sessions(db, user.id)
    db.delete(user)
    db.commit()
    log.info("User '%s' deleted", user.username)
