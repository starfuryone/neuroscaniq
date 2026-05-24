"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-24 00:00:00
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enums --------------------------------------------------------------
    user_role = postgresql.ENUM("user", "admin", "auditor", name="userrole", create_type=True)
    org_role = postgresql.ENUM("owner", "admin", "member", "viewer", name="orgrole", create_type=True)
    asset_kind = postgresql.ENUM("ip", "cidr", "domain", "asn", name="assetkind", create_type=True)
    asset_status = postgresql.ENUM("pending", "verified", "rejected", "revoked", name="assetstatus", create_type=True)
    proof_method = postgresql.ENUM("dns_txt", "email", "file_upload", "asn_attestation", name="proofmethod", create_type=True)
    proof_status = postgresql.ENUM("pending", "verified", "rejected", "expired", name="proofstatus", create_type=True)
    monitor_cadence = postgresql.ENUM("hourly", "daily", "weekly", name="monitorcadence", create_type=True)
    alert_severity = postgresql.ENUM("info", "low", "medium", "high", "critical", name="alertseverity", create_type=True)
    alert_kind = postgresql.ENUM(
        "new_port", "service_change", "tls_change", "exposure_drift",
        "vulnerability_match", "risk_score_jump", "monitor_failure",
        name="alertkind", create_type=True,
    )
    job_status = postgresql.ENUM("queued", "running", "completed", "failed", "cancelled", "rejected", name="jobstatus", create_type=True)
    job_kind = postgresql.ENUM("banner", "tls", "http", "screenshot", "monitor_diff", name="jobkind", create_type=True)
    plan_tier = postgresql.ENUM("free", "pro", "enterprise", name="plantier", create_type=True)
    subscription_status = postgresql.ENUM(
        "active", "trialing", "past_due", "canceled", "incomplete", "incomplete_expired", "unpaid", "paused",
        name="subscriptionstatus", create_type=True,
    )

    bind = op.get_bind()
    for enum in (
        user_role, org_role, asset_kind, asset_status, proof_method, proof_status,
        monitor_cadence, alert_severity, alert_kind, job_status, job_kind,
        plan_tier, subscription_status,
    ):
        enum.create(bind, checkfirst=True)

    # users --------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False, server_default=""),
        sa.Column("role", user_role, nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_email_verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("default_organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_created_at", "users", ["created_at"])

    # organizations ------------------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("slug", sa.String(120), nullable=False, unique=True),
        sa.Column("stripe_customer_id", sa.String(80), nullable=True),
    )
    op.create_index("ix_organizations_created_at", "organizations", ["created_at"])

    op.create_table(
        "organization_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", org_role, nullable=False, server_default="member"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_member"),
    )

    # api_keys -----------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("prefix", sa.String(32), nullable=False, unique=True),
        sa.Column("secret_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("usage_count", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("rate_limit_override", sa.Integer, nullable=True),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])

    # hosts --------------------------------------------------------------
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ip", postgresql.INET, nullable=False, unique=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("region", sa.String(120), nullable=True),
        sa.Column("city", sa.String(120), nullable=True),
        sa.Column("lat", sa.Float, nullable=True),
        sa.Column("lon", sa.Float, nullable=True),
        sa.Column("asn", sa.Integer, nullable=True),
        sa.Column("asn_org", sa.String(255), nullable=True),
        sa.Column("organization", sa.String(255), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("open_port_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="low"),
        sa.Column("tags", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_hosts_ip", "hosts", ["ip"])
    op.create_index("ix_hosts_asn", "hosts", ["asn"])
    op.create_index("ix_hosts_country", "hosts", ["country"])
    op.create_index("ix_hosts_risk_score", "hosts", ["risk_score"])

    op.create_table(
        "host_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("open_ports", postgresql.JSONB, nullable=True),
        sa.Column("raw_banner", sa.Text, nullable=True),
        sa.Column("http_headers", postgresql.JSONB, nullable=True),
        sa.Column("tls_info", postgresql.JSONB, nullable=True),
        sa.Column("whois_info", postgresql.JSONB, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_host_observations_host_id", "host_observations", ["host_id"])
    op.create_index("ix_host_observations_observed_at", "host_observations", ["observed_at"])

    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(16), nullable=False, server_default="open"),
        sa.Column("service_name", sa.String(120), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("host_id", "port", "protocol", name="uq_host_port_proto"),
    )
    op.create_index("ix_ports_port", "ports", ["port"])

    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("port_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product", sa.String(120), nullable=True),
        sa.Column("version", sa.String(120), nullable=True),
        sa.Column("cpe", sa.String(255), nullable=True),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("server_header", sa.String(255), nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("raw", postgresql.JSONB, nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # screenshots --------------------------------------------------------
    op.create_table(
        "screenshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("port", sa.Integer, nullable=True),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("s3_key", sa.String(500), nullable=True),
        sa.Column("thumbnail_s3_key", sa.String(500), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("technology_stack", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_screenshots_host_id", "screenshots", ["host_id"])

    # assets / monitors / proofs ----------------------------------------
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("kind", asset_kind, nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("label", sa.String(120), nullable=True),
        sa.Column("status", asset_status, nullable=False, server_default="pending"),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_assets_created_by", "assets", ["created_by"])
    op.create_index("ix_assets_value", "assets", ["value"])

    op.create_table(
        "ownership_proofs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", proof_method, nullable=False),
        sa.Column("status", proof_status, nullable=False, server_default="pending"),
        sa.Column("challenge", sa.String(120), nullable=False),
        sa.Column("expected_value", sa.String(255), nullable=False),
        sa.Column("submitted_value", sa.String(255), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ownership_proofs_asset_id", "ownership_proofs", ["asset_id"])

    op.create_table(
        "monitors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("cadence", monitor_cadence, nullable=False, server_default="daily"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config", postgresql.JSONB, nullable=True),
        sa.Column("last_snapshot", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_monitors_asset_id", "monitors", ["asset_id"])
    op.create_index("ix_monitors_next_run_at", "monitors", ["next_run_at"])

    # alerts -------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("monitor_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("monitors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("severity", alert_severity, nullable=False, server_default="info"),
        sa.Column("kind", alert_kind, nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("is_resolved", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("delivered_email", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("delivered_webhook", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_alerts_asset_id", "alerts", ["asset_id"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    # scan_jobs ----------------------------------------------------------
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("kind", job_kind, nullable=False),
        sa.Column("status", job_status, nullable=False, server_default="queued"),
        sa.Column("monitor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("result", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])

    # risk_scores --------------------------------------------------------
    op.create_table(
        "risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("factors", postgresql.JSONB, nullable=True),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
    )

    # subscriptions ------------------------------------------------------
    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("plan", plan_tier, nullable=False, server_default="free"),
        sa.Column("status", subscription_status, nullable=False, server_default="active"),
        sa.Column("stripe_customer_id", sa.String(80), nullable=True, unique=True),
        sa.Column("stripe_subscription_id", sa.String(80), nullable=True, unique=True),
        sa.Column("stripe_price_id", sa.String(80), nullable=True),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("monthly_search_quota", sa.Integer, nullable=False, server_default="100"),
        sa.Column("monthly_api_quota", sa.Integer, nullable=False, server_default="1000"),
        sa.Column("monitor_quota", sa.Integer, nullable=False, server_default="1"),
    )

    # audit_log ----------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=True),
        sa.Column("resource_id", sa.String(80), nullable=True),
        sa.Column("ip_address", postgresql.INET, nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("request_id", sa.String(80), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index("ix_audit_log_actor_user_id", "audit_log", ["actor_user_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    for tbl in (
        "audit_log", "subscriptions", "risk_scores", "scan_jobs", "alerts",
        "monitors", "ownership_proofs", "assets", "screenshots", "services",
        "ports", "host_observations", "hosts", "api_keys",
        "organization_members", "organizations", "users",
    ):
        op.drop_table(tbl)
    for enum_name in (
        "subscriptionstatus", "plantier", "jobkind", "jobstatus", "alertkind",
        "alertseverity", "monitorcadence", "proofstatus", "proofmethod",
        "assetstatus", "assetkind", "orgrole", "userrole",
    ):
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")
