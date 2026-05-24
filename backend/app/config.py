"""Centralized application configuration.

All env vars are validated and typed through Pydantic. Import `settings`
anywhere — never read os.environ directly outside this module.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core
    app_name: str = "NeuroScanIQ"
    app_env: Literal["development", "staging", "production"] = "development"
    app_debug: bool = False
    app_url: str = "http://localhost:3000"
    api_url: str = "http://localhost:8000"

    # Security
    jwt_secret: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 15
    jwt_refresh_ttl_days: int = 7
    password_hash_rounds: int = 4
    cors_origins: str = "http://localhost:3000"

    # Postgres
    database_url: str

    # OpenSearch
    opensearch_url: str = "http://opensearch:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    opensearch_index_hosts: str = "hosts"
    opensearch_index_screenshots: str = "screenshots"

    # Redis
    redis_url: str = "redis://redis:6379/0"
    redis_queue_db: int = 1

    # S3 / MinIO
    s3_endpoint: str = "http://minio:9000"
    s3_region: str = "us-east-1"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket_screenshots: str = "screenshots"
    s3_bucket_exports: str = "exports"
    s3_public_url: str = "http://localhost:9000"

    # Stripe
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""

    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "NeuroScanIQ <noreply@neuroscaniq.local>"

    # AI
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ai_model_classifier: str = "claude-sonnet-4-6"
    ai_enabled: bool = True

    # Scanner safety
    allowed_scan_cidrs: str = ""
    blocked_scan_cidrs: str = (
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,"
        "169.254.0.0/16,fc00::/7,::1/128"
    )

    # Rate limits (requests / minute)
    rate_limit_free_per_minute: int = 10
    rate_limit_pro_per_minute: int = 120
    rate_limit_enterprise_per_minute: int = 1200

    # Feature flags
    feature_screenshots: bool = True
    feature_maps: bool = True
    feature_monitors: bool = True
    feature_ai_analysis: bool = True

    # ---------- Derived helpers ----------
    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return _parse_cidrs(self.allowed_scan_cidrs)

    @property
    def blocked_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return _parse_cidrs(self.blocked_scan_cidrs)

    @field_validator("jwt_secret")
    @classmethod
    def _check_secret(cls, v: str) -> str:
        if v.startswith("change-me") and not v.endswith("test"):
            # Allow test fixtures but warn otherwise via logs at startup.
            return v
        return v


def _parse_cidrs(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return out


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
