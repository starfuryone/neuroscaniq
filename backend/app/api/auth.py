"""Authentication endpoints.

Implements:
  * POST /auth/register     - create account + send verification email
  * POST /auth/login        - exchange password for JWT pair
  * POST /auth/refresh      - exchange refresh token for new access token
  * POST /auth/verify-email - confirm email via signed token
  * POST /auth/password-reset/request - email reset link
  * POST /auth/password-reset/confirm - submit new password with token

The refresh-token rotation strategy stores the JTI of issued refresh tokens
in Redis with TTL == token lifetime; rotation invalidates the prior JTI.
This gives us replay protection while keeping the DB free of session rows.
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.errors import Conflict, NotFound, Unauthorized
from app.core.security import (
    REFRESH_AUDIENCE,
    create_access_token,
    create_email_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.schemas import (
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
    VerifyEmailRequest,
)
from app.services.email import email_service
from app.services.redis import get_redis

log = structlog.get_logger(__name__)
router = APIRouter()


REFRESH_JTI_PREFIX = "refresh:jti:"


async def _store_refresh_jti(jti: str, user_id: str, ttl_seconds: int) -> None:
    redis = await get_redis()
    await redis.set(f"{REFRESH_JTI_PREFIX}{jti}", user_id, ex=ttl_seconds)


async def _consume_refresh_jti(jti: str) -> str | None:
    redis = await get_redis()
    key = f"{REFRESH_JTI_PREFIX}{jti}"
    user_id = await redis.get(key)
    if user_id is None:
        return None
    await redis.delete(key)
    return user_id if isinstance(user_id, str) else user_id.decode()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/register", response_model=UserOut, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    """Create a new user account. Idempotent on duplicate email -> 409."""
    settings = get_settings()
    email_norm = payload.email.lower().strip()

    existing = await session.scalar(select(User).where(User.email == email_norm))
    if existing is not None:
        raise Conflict("An account with this email already exists.")

    user = User(
        email=email_norm,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name.strip(),
        role=UserRole.user,
        is_active=True,
        is_email_verified=False,
    )
    session.add(user)
    await session.flush()
    await session.commit()

    verify_token = create_email_token(user_id=str(user.id), purpose="verify")
    verify_url = f"{settings.app_url}/auth/verify-email?token={verify_token}"
    await email_service.send(
        to=user.email,
        template="verify_email",
        context={"full_name": user.full_name, "verify_url": verify_url},
    )

    log.info(
        "auth.register",
        user_id=str(user.id),
        email=user.email,
        ip=_client_ip(request),
    )
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Verify password and return an access/refresh JWT pair."""
    settings = get_settings()
    email_norm = payload.email.lower().strip()

    user = await session.scalar(select(User).where(User.email == email_norm))
    # Always run the hasher even on miss to avoid timing oracle.
    if user is None:
        verify_password(payload.password, "$argon2id$v=19$m=65536,t=3,p=2$abcdefgh$invalidhash")
        log.info("auth.login_failed", email=email_norm, ip=_client_ip(request), reason="no_user")
        raise Unauthorized("Invalid email or password.")

    if not verify_password(payload.password, user.password_hash):
        log.info("auth.login_failed", user_id=str(user.id), ip=_client_ip(request), reason="bad_password")
        raise Unauthorized("Invalid email or password.")

    if not user.is_active:
        raise Unauthorized("This account has been deactivated.")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    access, _ = create_access_token(user_id=str(user.id), role=user.role.value)
    refresh, jti = create_refresh_token(user_id=str(user.id))
    await _store_refresh_jti(jti, str(user.id), settings.jwt_refresh_ttl_days * 86400)

    user.last_login_at = datetime.now(timezone.utc)
    await session.commit()

    log.info("auth.login", user_id=str(user.id), ip=_client_ip(request))
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        expires_in=settings.jwt_access_ttl_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Rotate a refresh token. The prior JTI is invalidated."""
    settings = get_settings()
    try:
        claims = decode_token(payload.refresh_token, aud=REFRESH_AUDIENCE)
    except Exception:  # noqa: BLE001
        raise Unauthorized("Invalid or expired refresh token.") from None

    jti = claims.get("jti")
    sub = claims.get("sub")
    if not jti or not sub:
        raise Unauthorized("Malformed refresh token.")

    persisted_user_id = await _consume_refresh_jti(jti)
    if persisted_user_id != sub:
        raise Unauthorized("Refresh token has been used or revoked.")

    user = await session.get(User, sub)
    if user is None or not user.is_active:
        raise Unauthorized("Account not available.")

    access, _ = create_access_token(user_id=str(user.id), role=user.role.value)
    new_refresh, new_jti = create_refresh_token(user_id=str(user.id))
    await _store_refresh_jti(new_jti, str(user.id), settings.jwt_refresh_ttl_days * 86400)

    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        token_type="bearer",
        expires_in=settings.jwt_access_ttl_minutes * 60,
    )


@router.post("/verify-email", response_model=UserOut)
async def verify_email(
    payload: VerifyEmailRequest,
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    """Mark a user's email as verified after validating the signed token."""
    try:
        claims = decode_token(payload.token, aud="neuroscaniq:email")
    except Exception:  # noqa: BLE001
        raise Unauthorized("Verification link is invalid or has expired.") from None

    if claims.get("purpose") != "verify":
        raise Unauthorized("Wrong token purpose.")

    user = await session.get(User, claims["sub"])
    if user is None:
        raise NotFound("User not found.")

    if not user.is_email_verified:
        user.is_email_verified = True
        await session.commit()
    return UserOut.model_validate(user)


@router.post("/password-reset/request", status_code=202)
async def password_reset_request(
    payload: PasswordResetRequest,
    session: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Send a password-reset email. Always returns 202 to prevent enumeration."""
    settings = get_settings()
    user = await session.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if user is not None and user.is_active:
        token = create_email_token(user_id=str(user.id), purpose="reset")
        reset_url = f"{settings.app_url}/auth/reset?token={token}"
        await email_service.send(
            to=user.email,
            template="password_reset",
            context={"full_name": user.full_name, "reset_url": reset_url},
        )
    return {"status": "accepted"}


@router.post("/password-reset/confirm", response_model=UserOut)
async def password_reset_confirm(
    payload: PasswordResetConfirm,
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    """Set a new password from a valid reset token."""
    try:
        claims = decode_token(payload.token, aud="neuroscaniq:email")
    except Exception:  # noqa: BLE001
        raise Unauthorized("Reset link is invalid or has expired.") from None

    if claims.get("purpose") != "reset":
        raise Unauthorized("Wrong token purpose.")

    user = await session.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise Unauthorized("Account not available.")

    user.password_hash = hash_password(payload.new_password)
    await session.commit()
    log.info("auth.password_reset_complete", user_id=str(user.id))
    return UserOut.model_validate(user)
