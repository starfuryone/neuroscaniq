"""Alert inbox endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.errors import NotFound
from app.db.session import get_db
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.schemas.schemas import AlertOut

router = APIRouter()


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
) -> list[AlertOut]:
    stmt = (
        select(Alert)
        .join(Asset, Asset.id == Alert.asset_id)
        .where(Asset.created_by == user.id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if unread_only:
        stmt = stmt.where(Alert.is_read.is_(False))
    rows = (await session.scalars(stmt)).all()
    return [AlertOut.model_validate(r) for r in rows]


@router.post("/{alert_id}/read", response_model=AlertOut)
async def mark_read(
    alert_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> AlertOut:
    alert = await session.scalar(
        select(Alert)
        .join(Asset, Asset.id == Alert.asset_id)
        .where(Alert.id == alert_id, Asset.created_by == user.id)
    )
    if alert is None:
        raise NotFound("Alert not found.")
    alert.is_read = True
    await session.commit()
    return AlertOut.model_validate(alert)


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve(
    alert_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> AlertOut:
    alert = await session.scalar(
        select(Alert)
        .join(Asset, Asset.id == Alert.asset_id)
        .where(Alert.id == alert_id, Asset.created_by == user.id)
    )
    if alert is None:
        raise NotFound("Alert not found.")
    alert.is_resolved = True
    alert.is_read = True
    await session.commit()
    return AlertOut.model_validate(alert)
