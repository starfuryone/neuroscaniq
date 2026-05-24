"""Alerts raised by monitors or admin systems."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class AlertSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertKind(str, enum.Enum):
    new_port = "new_port"
    service_change = "service_change"
    tls_change = "tls_change"
    exposure_drift = "exposure_drift"
    vulnerability_match = "vulnerability_match"
    risk_score_jump = "risk_score_jump"
    monitor_failure = "monitor_failure"


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    organization_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    monitor_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitors.id", ondelete="SET NULL"),
        index=True,
    )
    asset_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        index=True,
    )

    kind: Mapped[AlertKind] = mapped_column(Enum(AlertKind, name="alert_kind"), nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"),
        default=AlertSeverity.medium,
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    delivered_email: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    delivered_webhook: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
