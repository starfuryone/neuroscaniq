"""Monitors and ownership proofs.

Monitors run only against assets in the `verified` state. Every monitor
must reference a verified Asset; the API layer enforces this.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class ProofMethod(str, enum.Enum):
    dns_txt = "dns_txt"
    email = "email"
    file_upload = "file_upload"
    asn_attestation = "asn_attestation"


class ProofStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    failed = "failed"
    expired = "expired"


class OwnershipProof(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ownership_proofs"

    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    method: Mapped[ProofMethod] = mapped_column(
        Enum(ProofMethod, name="proof_method"), nullable=False
    )
    status: Mapped[ProofStatus] = mapped_column(
        Enum(ProofStatus, name="proof_status"),
        default=ProofStatus.pending,
        nullable=False,
        index=True,
    )

    challenge: Mapped[str] = mapped_column(String(255), nullable=False)
    expected_value: Mapped[str | None] = mapped_column(String(255))
    submitted_value: Mapped[str | None] = mapped_column(String(255))

    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset = relationship("Asset", back_populates="proofs")


class MonitorCadence(str, enum.Enum):
    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"


class Monitor(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "monitors"

    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    cadence: Mapped[MonitorCadence] = mapped_column(
        Enum(MonitorCadence, name="monitor_cadence"),
        default=MonitorCadence.daily,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    # Configuration: which signals trigger alerts
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Snapshot of last scan result (compared against new scans)
    last_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
