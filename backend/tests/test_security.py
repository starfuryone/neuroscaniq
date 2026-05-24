"""Tests for the security primitives: password hashing, JWT, API keys."""

from __future__ import annotations

import time

import pytest

from app.core.security import (
    ACCESS_AUDIENCE,
    REFRESH_AUDIENCE,
    create_access_token,
    create_email_token,
    create_refresh_token,
    decode_token,
    extract_prefix,
    generate_api_key,
    hash_password,
    needs_rehash,
    verify_api_key,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_is_argon2(self) -> None:
        h = hash_password("CorrectHorseBattery5!")
        assert h.startswith("$argon2")

    def test_round_trip(self) -> None:
        h = hash_password("CorrectHorseBattery5!")
        assert verify_password("CorrectHorseBattery5!", h)

    def test_wrong_password_rejected(self) -> None:
        h = hash_password("CorrectHorseBattery5!")
        assert not verify_password("wrong", h)

    def test_distinct_salts(self) -> None:
        a = hash_password("CorrectHorseBattery5!")
        b = hash_password("CorrectHorseBattery5!")
        assert a != b


class TestJWT:
    def test_access_token_round_trip(self) -> None:
        token, jti = create_access_token(user_id="user-123", role="user")
        claims = decode_token(token, aud=ACCESS_AUDIENCE)
        assert claims["sub"] == "user-123"
        assert claims["role"] == "user"
        assert claims["jti"] == jti

    def test_refresh_token_round_trip(self) -> None:
        token, jti = create_refresh_token(user_id="user-123")
        claims = decode_token(token, aud=REFRESH_AUDIENCE)
        assert claims["sub"] == "user-123"
        assert claims["jti"] == jti

    def test_access_token_rejects_refresh_audience(self) -> None:
        # Cross-audience attack -- a refresh token must not work as an access token.
        refresh, _ = create_refresh_token(user_id="user-123")
        with pytest.raises(Exception):  # noqa: PT011
            decode_token(refresh, aud=ACCESS_AUDIENCE)

    def test_email_token_with_purpose(self) -> None:
        token = create_email_token(user_id="user-123", purpose="verify")
        claims = decode_token(token, aud="neuroscaniq:email")
        assert claims["sub"] == "user-123"
        assert claims["purpose"] == "verify"


class TestAPIKeys:
    def test_generated_key_format(self) -> None:
        display, prefix, secret_hash = generate_api_key()
        assert display.startswith("nsiq_")
        assert "_" in display[5:]
        assert prefix.startswith("nsiq_")
        assert secret_hash.startswith("$argon2")

    def test_verify_round_trip(self) -> None:
        display, prefix, secret_hash = generate_api_key()
        assert verify_api_key(display, secret_hash)
        assert extract_prefix(display) == prefix

    def test_verify_rejects_wrong_secret(self) -> None:
        display1, _, hash1 = generate_api_key()
        display2, _, _ = generate_api_key()
        # display2's secret must NOT verify against display1's hash.
        assert not verify_api_key(display2, hash1)

    def test_extract_prefix_handles_malformed(self) -> None:
        assert extract_prefix("garbage") is None
        assert extract_prefix("") is None
        assert extract_prefix("nsiq_abc") is None  # missing secret part
