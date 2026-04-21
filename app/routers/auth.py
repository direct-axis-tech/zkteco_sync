from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from jose import jwt
import os

from app.deps import require_auth
from app.schemas import LoginRequest, PasswordVerify, TokenOut

router = APIRouter(prefix="/auth", tags=["auth"])

_SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
_ALGORITHM = "HS256"
_TOKEN_EXPIRE_HOURS = 12


@router.post("/login", response_model=TokenOut)
def login(payload: LoginRequest):
    expected_user = os.getenv("API_USERNAME", "admin")
    expected_pass = os.getenv("API_PASSWORD", "admin")

    if payload.username != expected_user or payload.password != expected_pass:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {
            "sub": payload.username,
            "exp": datetime.utcnow() + timedelta(hours=_TOKEN_EXPIRE_HOURS),
        },
        _SECRET_KEY,
        algorithm=_ALGORITHM,
    )
    return TokenOut(access_token=token)


@router.post("/verify", status_code=204, dependencies=[Depends(require_auth)])
def verify_password(payload: PasswordVerify):
    expected_pass = os.getenv("API_PASSWORD", "admin")
    if payload.password != expected_pass:
        raise HTTPException(status_code=401, detail="Invalid password")
