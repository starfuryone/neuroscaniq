"""Stripe billing endpoints.

The webhook handler validates Stripe signature, then upserts the
Subscription row keyed by `stripe_subscription_id`. We intentionally do
NOT trust webhook ordering -- every event refetches the subscription
from Stripe (when possible) to converge to canonical state.
"""

from __future__ import annotations

from datetime import datetime, timezone

import stripe
import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.deps import get_current_user
from app.core.errors import NotFound
from app.db.session import get_db, session_scope
from app.models.billing import PlanTier, Subscription, SubscriptionStatus
from app.models.user import User
from app.schemas.schemas import CheckoutRequest, CheckoutResponse, SubscriptionOut
from app.services.stripe_service import stripe_service

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/subscription", response_model=SubscriptionOut)
async def get_subscription(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SubscriptionOut:
    sub = await session.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if sub is None:
        # Return implicit free-tier representation.
        return SubscriptionOut(
            plan=PlanTier.free,
            status=SubscriptionStatus.active,
            current_period_end=None,
            cancel_at=None,
            monthly_search_quota=100,
            monthly_api_quota=1000,
            monitor_quota=1,
        )
    return SubscriptionOut.model_validate(sub)


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    payload: CheckoutRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CheckoutResponse:
    settings = get_settings()
    if not settings.STRIPE_API_KEY:
        raise HTTPException(status_code=503, detail="Billing is not configured.")

    sub = await session.scalar(select(Subscription).where(Subscription.user_id == user.id))
    customer_id = sub.stripe_customer_id if sub else None
    if customer_id is None:
        customer_id = await stripe_service.create_customer(email=user.email, name=user.full_name)

    session_url = await stripe_service.create_checkout_session(
        customer_id=customer_id,
        price_id=payload.price_id,
        success_url=payload.success_url,
        cancel_url=payload.cancel_url,
        metadata={"user_id": str(user.id)},
    )

    if sub is None:
        sub = Subscription(
            user_id=user.id,
            plan=PlanTier.free,
            status=SubscriptionStatus.incomplete,
            stripe_customer_id=customer_id,
            monthly_search_quota=100,
            monthly_api_quota=1000,
            monitor_quota=1,
        )
        session.add(sub)
        await session.commit()

    return CheckoutResponse(url=session_url)


@router.post("/portal")
async def create_portal_session(
    return_url: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    sub = await session.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if sub is None or sub.stripe_customer_id is None:
        raise NotFound("No billing customer for this user.")
    url = await stripe_service.create_portal_session(sub.stripe_customer_id, return_url)
    return {"url": url}


@router.post("/webhook", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(..., alias="Stripe-Signature"),
) -> dict[str, str]:
    settings = get_settings()
    payload = await request.body()
    try:
        event = stripe_service.construct_event(payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as exc:
        log.warning("stripe.webhook_invalid_signature", error=str(exc))
        raise HTTPException(status_code=400, detail="Invalid signature.") from exc

    event_type = event["type"]
    data = event["data"]["object"]
    log.info("stripe.webhook", event_type=event_type, id=event.get("id"))

    if event_type in {"customer.subscription.created", "customer.subscription.updated"}:
        await _upsert_subscription_from_stripe(data)
    elif event_type == "customer.subscription.deleted":
        await _mark_subscription_cancelled(data)
    elif event_type == "checkout.session.completed":
        sub_id = data.get("subscription")
        if sub_id:
            full = await stripe_service.retrieve_subscription(sub_id)
            await _upsert_subscription_from_stripe(full)

    return {"status": "ok"}


async def _upsert_subscription_from_stripe(obj: dict) -> None:
    async with session_scope() as session:
        customer_id = obj["customer"]
        sub = await session.scalar(
            select(Subscription).where(Subscription.stripe_customer_id == customer_id)
        )
        if sub is None:
            user_id = (obj.get("metadata") or {}).get("user_id")
            if user_id:
                sub = await session.scalar(select(Subscription).where(Subscription.user_id == user_id))
        if sub is None:
            log.warning("stripe.webhook_no_user", customer_id=customer_id)
            return

        price_id = obj["items"]["data"][0]["price"]["id"]
        plan = stripe_service.plan_for_price(price_id)
        quotas = stripe_service.PLAN_QUOTAS[plan]

        sub.stripe_subscription_id = obj["id"]
        sub.stripe_price_id = price_id
        sub.plan = plan
        sub.status = SubscriptionStatus(obj["status"])
        sub.current_period_start = datetime.fromtimestamp(obj["current_period_start"], tz=timezone.utc)
        sub.current_period_end = datetime.fromtimestamp(obj["current_period_end"], tz=timezone.utc)
        sub.cancel_at = (
            datetime.fromtimestamp(obj["cancel_at"], tz=timezone.utc) if obj.get("cancel_at") else None
        )
        sub.monthly_search_quota = quotas["monthly_search_quota"]
        sub.monthly_api_quota = quotas["monthly_api_quota"]
        sub.monitor_quota = quotas["monitor_quota"]
        await session.commit()


async def _mark_subscription_cancelled(obj: dict) -> None:
    async with session_scope() as session:
        sub = await session.scalar(
            select(Subscription).where(Subscription.stripe_subscription_id == obj["id"])
        )
        if sub is None:
            return
        sub.status = SubscriptionStatus.canceled
        sub.plan = PlanTier.free
        sub.monthly_search_quota = 100
        sub.monthly_api_quota = 1000
        sub.monitor_quota = 1
        await session.commit()
