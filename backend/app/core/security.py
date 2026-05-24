"""Authentication primitives.

* `hash_password` / `verify_password` use Argon2id.
* `create_access_token` / `create_refresh_token` issue JWTs with separate
  audiences so a refresh token can never be replayed as an access token.
* `generate_api_key` returns a (display, secret_hash) tuple. The plaintext
  is only shown to the user once at creation time.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

from app.config import settings

_hasher = PasswordHasher(
    time_cost=settings.password_hash_rounds,
    memory_cost=64 * 1024,
    parallelism=2,
)

ACCESS_AUDIENCE = "neuroscaniq:access"
REFRESH_AUDIENCE = "neuroscaniq:refresh"
EMAIL_AUDIENCE = "neuroscaniq:email"


# ---------- Passwords ----------
def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        _hasher.verify(hashed, plaintext)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHash:
        return True


# ---------- JWTs ----------
def _encode(
    payload: dict[str, Any],
    *,
    aud: str,
    ttl_seconds: int,
) -> str:
    now = datetime.now(timezone.utc)
    body = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "aud": aud,
        "iss": settings.app_name,
    }
    return jwt.encode(body, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(*, user_id: str, role: str) -> tuple[str, str]:
    jti = secrets.token_urlsafe(16)
    token = _encode(
        {"sub": user_id, "role": role, "typ": "access", "jti": jti},
        aud=ACCESS_AUDIENCE,
        ttl_seconds=settings.jwt_access_ttl_minutes * 60,
    )
    return token, jti


def create_refresh_token(*, user_id: str, jti: str | None = None) -> tuple[str, str]:
    jti = jti or secrets.token_urlsafe(16)
    token = _encode(
        {"sub": user_id, "typ": "refresh", "jti": jti},
        aud=REFRESH_AUDIENCE,
        ttl_seconds=settings.jwt_refresh_ttl_days * 86400,
    )
    return token, jti


def create_email_token(*, user_id: str, purpose: Literal["verify", "reset"]) -> str:
    return _encode(
        {"sub": user_id, "typ": purpose, "purpose": purpose},
        aud=EMAIL_AUDIENCE,
        ttl_seconds=60 * 60 * 24,  # 24h
    )


def decode_token(token: str, *, aud: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        audience=aud,
        issuer=settings.app_name,
        options={"require": ["exp", "iat", "aud", "iss", "sub"]},
    )


# ---------- API keys ----------
API_KEY_PREFIX = "nsiq"


def generate_api_key() -> tuple[str, str, str]:
    """Returns (display_key, prefix, secret_hash).

    `display_key` is what the user sees once: e.g. `nsiq_ab12cd34_<random>`.
    Store only `prefix` and `secret_hash` in DB.
    """
    prefix = secrets.token_hex(4)               # 8 chars
    secret = secrets.token_urlsafe(32)          # 43 chars
    display = f"{API_KEY_PREFIX}_{prefix}_{secret}"
    return display, f"{API_KEY_PREFIX}_{prefix}", _hasher.hash(secret)


def verify_api_key(presented: str, secret_hash: str) -> bool:
    """Verify a presented `nsiq_<prefix>_<secret>` against a stored hash."""
    try:
        _, _prefix, secret = presented.split("_", 2)
    except ValueError:
        return False
    try:
        _hasher.verify(secret_hash, secret)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def extract_prefix(presented: str) -> str | None:
    try:
        scheme, prefix, _ = presented.split("_", 2)
        if scheme != API_KEY_PREFIX:
            return None
        return f"{API_KEY_PREFIX}_{prefix}"
    except ValueError:
        return None
