"""Request / response Pydantic models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.asset import AssetKind, AssetStatus
from app.models.billing import PlanTier, SubscriptionStatus
from app.models.monitor import MonitorCadence, ProofMethod, ProofStatus
from app.models.user import UserRole


# ===================== Auth =====================


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=120)

    @field_validator("password")
    @classmethod
    def _password_complexity(cls, v: str) -> str:
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not (has_upper and has_lower and has_digit):
            raise ValueError("password must contain at least one upper, lower, and digit character")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=10, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _password_complexity(cls, v: str) -> str:
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not (has_upper and has_lower and has_digit):
            raise ValueError("password must contain at least one upper, lower, and digit character")
        return v


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=10, max_length=128)


# ===================== Users =====================


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_email_verified: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=120)


# ===================== API Keys =====================


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class APIKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None
    usage_count: int = 0


class APIKeyCreated(BaseModel):
    """Returned exactly once when a key is first minted."""

    id: str
    name: str
    prefix: str
    plaintext_key: str = Field(..., description="Full key. Store securely; cannot be retrieved again.")
    created_at: datetime


# ===================== Search =====================


class SearchHit(BaseModel):
    ip: str
    hostname: str | None = None
    country: str | None = None
    city: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    tags: list[str] = Field(default_factory=list)
    last_seen: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class SearchFacet(BaseModel):
    name: str
    buckets: list[dict[str, Any]]


class SearchResponse(BaseModel):
    total: int
    page: int
    page_size: int
    took_ms: int
    hits: list[SearchHit]
    facets: list[SearchFacet]
    query: str


# ===================== Host detail =====================


class HostObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    observed_at: datetime
    open_ports: list[int]
    raw_banner: str | None = None
    http_headers: dict[str, Any] | None = None
    tls_info: dict[str, Any] | None = None
    whois_info: dict[str, Any] | None = None
    notes: str | None = None


class HostDetail(BaseModel):
    ip: str
    hostname: str | None = None
    country: str | None = None
    city: str | None = None
    region: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    organization: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    tls: dict[str, Any] | None = None
    http: dict[str, Any] | None = None
    risk_score: float = 0.0
    risk_level: str = "low"
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    last_seen: str | None = None
    ai_summary: str | None = None


# ===================== Assets / Ownership / Monitor =====================


class AssetCreate(BaseModel):
    kind: AssetKind
    value: str = Field(..., min_length=1, max_length=255)
    label: str | None = Field(None, max_length=120)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: AssetKind
    value: str
    label: str | None = None
    status: AssetStatus
    verified_at: datetime | None = None
    created_at: datetime


class OwnershipProofCreate(BaseModel):
    method: ProofMethod


class OwnershipProofOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    method: ProofMethod
    status: ProofStatus
    challenge: str
    expected_value: str
    attempts: int
    verified_at: datetime | None = None
    created_at: datetime
    instructions: str | None = None
    last_check_detail: str | None = None


class MonitorCreate(BaseModel):
    asset_id: str
    cadence: MonitorCadence = MonitorCadence.daily
    config: dict[str, Any] | None = None


class MonitorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    cadence: MonitorCadence
    is_active: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    config: dict[str, Any] | None = None
    created_at: datetime


# ===================== Alerts =====================


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str | None = None
    monitor_id: str | None = None
    host_id: str | None = None
    severity: str
    kind: str
    title: str
    message: str
    is_read: bool
    is_resolved: bool
    created_at: datetime


# ===================== Billing =====================


class CheckoutRequest(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str


class CheckoutResponse(BaseModel):
    url: str


class SubscriptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    plan: PlanTier
    status: SubscriptionStatus
    current_period_end: datetime | None = None
    cancel_at: datetime | None = None
    monthly_search_quota: int
    monthly_api_quota: int
    monitor_quota: int


# ===================== Screenshots =====================


class ScreenshotOut(BaseModel):
    id: str
    ip: str
    port: int
    url: str
    title: str | None = None
    captured_at: datetime
    technology_stack: list[str] = Field(default_factory=list)
    image_url: str | None = None
    thumbnail_url: str | None = None


# ===================== Admin =====================


class AdminStats(BaseModel):
    users: int
    hosts: int
    open_alerts: int
    jobs_queued: int
    jobs_running: int
    scan_queue_depth: int
    alert_queue_depth: int


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_user_id: str | None = None
    organization_id: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    metadata_json: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
