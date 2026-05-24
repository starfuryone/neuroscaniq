"""Detailed risk score breakdowns.

The Host model stores the current aggregate; this table stores per-signal
contributions so the UI can explain "why" a host is high-risk.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class RiskScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "risk_scores"

    host_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
