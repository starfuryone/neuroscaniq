"""Service / fingerprint records.

A Service is the application protocol / software identified on a given
Port. Multiple services can be observed on one port over time as
versions change.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Service(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "services"

    port_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ports.id", ondelete="CASCADE"), index=True
    )

    product: Mapped[str | None] = mapped_column(String(120), index=True)
    version: Mapped[str | None] = mapped_column(String(80))
    cpe: Mapped[str | None] = mapped_column(String(255), index=True)
    title: Mapped[str | None] = mapped_column(String(255))
    server_header: Mapped[str | None] = mapped_column(String(255))
    banner: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    port = relationship("Port", back_populates="services")
