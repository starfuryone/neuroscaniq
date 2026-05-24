"""Stripe integration for subscriptions.

We only call Stripe from the API process — workers never reach Stripe.
"""

from __future__ import annotations

from typing import Any

import stripe
import structlog

from app.config import settings
from app.models.billing import PlanTier

log = structlog.get_logger(__name__)

if settings.stripe_secret_key:
    stripe.api_key = settings.stripe_secret_key


PLAN_QUOTAS: dict[PlanTier, dict[str, int]] = {
    PlanTier.free: {"monthly_search": 100, "monthly_api": 1000, "monitors": 1},
    PlanTier.pro: {"monthly_search": 10_000, "monthly_api": 100_000, "monitors": 25},
    PlanTier.enterprise: {"monthly_search": 1_000_000, "monthly_api": 5_000_000, "monitors": 1000},
}


def plan_for_price(price_id: str) -> PlanTier:
    if price_id == settings.stripe_price_pro:
        return PlanTier.pro
    if price_id == settings.stripe_price_enterprise:
        return PlanTier.enterprise
    return PlanTier.free


async def create_checkout_session(*, user_email: str, customer_id: str | None, price_id: str, success_url: str, cancel_url: str) -> dict[str, Any]:
    if not settings.stripe_secret_key:
        raise RuntimeError("Stripe is not configured")
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        customer=customer_id,
        customer_email=None if customer_id else user_email,
        success_url=success_url,
        cancel_url=cancel_url,
        allow_promotion_codes=True,
    )
    return {"id": session.id, "url": session.url}


def construct_event(payload: bytes, sig_header: str) -> stripe.Event:
    return stripe.Webhook.construct_event(payload, sig_header, settings.stripe_webhook_secret)
