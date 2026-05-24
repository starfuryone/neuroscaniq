"""Reusable FastAPI dependencies.

These dependencies resolve the current user (via JWT or API key),
fetch their organization, and enforce role/plan requirements.
"""

from __future__ import annotations

from typing import Annotated

import jwt
import structlog
from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Forbidden, Unauthorized
from app.core.security import ACCESS_AUDIENCE, decode_token, extract_prefix, verify_api_key
from app.db.session import get_db
from app.models.api_key import APIKey
from app.models.billing import PlanTier, Subscription
from app.models.user import User, UserRole

log = structlog.get_logger(__name__)


# ---------- Token / API key resolution ----------
async def _user_from_bearer(token: str, db: AsyncSession) -> User:
    try:
        claims = decode_token(token, aud=ACCESS_AUDIENCE)
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Access token expired", code="token_expired")
    except jwt.InvalidTokenError as e:
        raise Unauthorized(f"Invalid token: {e}", code="invalid_token")

    user_id = claims.get("sub")
    if not user_id:
        raise Unauthorized("Token missing subject", code="invalid_token")

    user = await db.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise Unauthorized("User inactive", code="user_inactive")
    return user


async def _user_from_api_key(presented: str, db: AsyncSession) -> User:
    prefix = extract_prefix(presented)
    if not prefix:
        raise Unauthorized("Malformed API key", code="invalid_api_key")

    api_key = await db.scalar(select(APIKey).where(APIKey.prefix == prefix, APIKey.is_active.is_(True)))
    if not api_key:
        raise Unauthorized("Unknown API key", code="invalid_api_key")

    if not verify_api_key(presented, api_key.secret_hash):
        raise Unauthorized("API key verification failed", code="invalid_api_key")

    user = await db.scalar(select(User).where(User.id == api_key.user_id, User.is_active.is_(True)))
    if not user:
        raise Unauthorized("Owner of API key is inactive", code="user_inactive")

    return user


# ---------- Public deps ----------
async def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the requesting principal from either Bearer JWT or API key."""

    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise Unauthorized("Expected Bearer token", code="invalid_authorization")
        user = await _user_from_bearer(value, db)
    elif x_api_key:
        user = await _user_from_api_key(x_api_key, db)
    else:
        raise Unauthorized("Authentication required", code="missing_authorization")

    # Stash on request for audit middleware
    request.state.user_id = str(user.id)
    request.state.role = user.role.value
    return user


def require_role(*roles: UserRole):
    """Dependency factory enforcing an allowed-roles list."""
    role_values = {r.value for r in roles}

    async def _enforcer(user: User = Depends(get_current_user)) -> User:
        if user.role.value not in role_values:
            raise Forbidden("Insufficient role")
        return user

    return _enforcer


async def get_subscription(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Subscription:
    sub = await db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if sub is None:
        # Implicit free tier — return an in-memory default. Callers shouldn't mutate.
        return Subscription(user_id=user.id, plan=PlanTier.free)
    return sub
