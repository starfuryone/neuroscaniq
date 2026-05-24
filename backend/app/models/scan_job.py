"""Scan job records.

Each scan job is queued onto Redis and processed by a scanner worker.
The DB row is the durable history; the queue is transient.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    rejected = "rejected"   # asset not authorized for scanning


class JobKind(str, enum.Enum):
    banner = "banner"
    tls = "tls"
    http = "http"
    screenshot = "screenshot"
    monitor_diff = "monitor_diff"
    deep_scan = "deep_scan"


class ScanJob(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scan_jobs"

    monitor_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitors.id", ondelete="SET NULL"),
        index=True,
    )
    asset_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    kind: Mapped[JobKind] = mapped_column(Enum(JobKind, name="job_kind"), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status"),
        default=JobStatus.queued,
        nullable=False,
        index=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
