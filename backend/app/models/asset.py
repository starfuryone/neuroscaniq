"""Assets a user has claimed.

An Asset is a piece of internet-facing infrastructure (IP, CIDR, domain,
or ASN) that a user asserts ownership of. Before any active monitoring
runs, the user must satisfy an `OwnershipProof` challenge. This is the
gate that keeps NeuroScanIQ a defensive tool.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    pass


class AssetKind(str, enum.Enum):
    ip = "ip"
    cidr = "cidr"
    domain = "domain"
    asn = "asn"


class AssetStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    rejected = "rejected"
    revoked = "revoked"


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    organization_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    created_by: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    kind: Mapped[AssetKind] = mapped_column(Enum(AssetKind, name="asset_kind"), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    label: Mapped[str | None] = mapped_column(String(120))

    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus, name="asset_status"),
        default=AssetStatus.pending,
        nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    proofs: Mapped[list["OwnershipProof"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan"
    )
