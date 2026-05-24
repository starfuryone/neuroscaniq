"""Open port records for a host."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Port(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_host_port"),
    )

    host_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    port: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")  # open/closed/filtered
    service_name: Mapped[str | None] = mapped_column(String(80), index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    host = relationship("Host", back_populates="ports")
    services: Mapped[list["Service"]] = relationship(  # noqa: F821
        back_populates="port", cascade="all, delete-orphan"
    )
