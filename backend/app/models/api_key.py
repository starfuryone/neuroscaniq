"""API keys for programmatic access.

Keys are issued as `nsiq_<prefix>_<random>` and stored only by their
bcrypt hash. The prefix (`nsiq_<prefix>`) is retained for display so
users can identify which key is which without revealing the secret.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class APIKey(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "api_keys"

    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(80), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Optional per-key override of plan rate limit (req/min)
    rate_limit_override: Mapped[int | None] = mapped_column(Integer)

    user: Mapped["User"] = relationship(back_populates="api_keys")
