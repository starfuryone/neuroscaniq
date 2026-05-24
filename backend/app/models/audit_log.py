"""Append-only audit log.

Every sensitive action (login, API key creation, monitor creation,
admin actions, billing changes) emits an audit row. These rows must
never be modified; deletion is restricted to retention policy jobs.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class AuditLog(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    actor_user_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    organization_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), index=True
    )

    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(80), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(80), index=True)

    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(500))
    request_id: Mapped[str | None] = mapped_column(String(80), index=True)

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
