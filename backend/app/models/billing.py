"""Stripe-backed subscriptions and plan tracking."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class PlanTier(str, enum.Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class SubscriptionStatus(str, enum.Enum):
    active = "active"
    trialing = "trialing"
    past_due = "past_due"
    canceled = "canceled"
    incomplete = "incomplete"


class Subscription(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "subscriptions"

    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    plan: Mapped[PlanTier] = mapped_column(
        Enum(PlanTier, name="plan_tier"),
        default=PlanTier.free,
        nullable=False,
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(SubscriptionStatus, name="subscription_status"),
        default=SubscriptionStatus.active,
        nullable=False,
    )

    stripe_customer_id: Mapped[str | None] = mapped_column(String(120))
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(120), unique=True)
    stripe_price_id: Mapped[str | None] = mapped_column(String(120))

    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Plan quotas (cached from price metadata)
    monthly_search_quota: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    monthly_api_quota: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    monitor_quota: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    user = relationship("User", back_populates="subscription")
