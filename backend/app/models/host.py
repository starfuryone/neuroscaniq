"""Host and observation history models.

A `Host` is the canonical record for one IP address we've observed.
`HostObservation` rows are append-only and capture the state of that
host at a moment in time. The latest observation is denormalized into
`Host.latest_*` columns for fast list reads. Full search lives in
OpenSearch — these tables are the source of truth.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Host(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "hosts"

    ip: Mapped[str] = mapped_column(INET, unique=True, index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)

    # GeoIP / network
    country: Mapped[str | None] = mapped_column(String(2), index=True)
    region: Mapped[str | None] = mapped_column(String(120))
    city: Mapped[str | None] = mapped_column(String(120))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    asn: Mapped[int | None] = mapped_column(Integer, index=True)
    asn_org: Mapped[str | None] = mapped_column(String(255), index=True)
    organization: Mapped[str | None] = mapped_column(String(255))

    # Denormalized "current state" (kept in sync by scanner workers)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    open_port_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), index=True)  # low/medium/high/critical

    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    observations: Mapped[list["HostObservation"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", order_by="HostObservation.observed_at.desc()"
    )
    ports: Mapped[list["Port"]] = relationship(  # noqa: F821 (forward ref)
        back_populates="host", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Host {self.ip}>"


class HostObservation(Base, UUIDMixin, TimestampMixin):
    """Append-only snapshot of a host at one point in time."""

    __tablename__ = "host_observations"
    __table_args__ = (
        UniqueConstraint("host_id", "observed_at", name="uq_host_observed_at"),
    )

    host_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    open_ports: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    raw_banner: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    http_headers: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    tls_info: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    whois_info: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    notes: Mapped[str | None] = mapped_column(Text)

    host: Mapped["Host"] = relationship(back_populates="observations")
