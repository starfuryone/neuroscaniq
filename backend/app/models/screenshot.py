"""Screenshot metadata.

Binaries live in S3; we index URL + metadata for browse and search.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class Screenshot(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "screenshots"

    host_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int | None] = mapped_column(Integer, index=True)
    url: Mapped[str] = mapped_column(String(500), nullable=False)

    s3_key: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    thumbnail_s3_key: Mapped[str | None] = mapped_column(String(500))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)

    title: Mapped[str | None] = mapped_column(String(255))
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    technology_stack: Mapped[dict[str, Any] | None] = mapped_column(JSON)
