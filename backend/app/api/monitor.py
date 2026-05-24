"""Asset, ownership, and monitor endpoints.

This is the *authorization* surface of the platform. A Monitor (recurring
scan) can only be created against an Asset whose OwnershipProof has been
verified. The scan workers consult Asset+Proof state via `scan_guard` before
issuing any probe -- this endpoint is therefore the source of truth for
"who is allowed to scan what."
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.errors import Conflict, Forbidden, NotFound, OwnershipRequired
from app.db.session import get_db
from app.models.asset import Asset, AssetStatus
from app.models.monitor import (
    Monitor,
    MonitorCadence,
    OwnershipProof,
    ProofMethod,
    ProofStatus,
)
from app.models.user import User
from app.schemas.schemas import (
    AssetCreate,
    AssetOut,
    MonitorCreate,
    MonitorOut,
    OwnershipProofCreate,
    OwnershipProofOut,
)
from app.services.ownership import ownership_service
from app.services.redis import get_redis

log = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------- assets ----------------------------------------


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[AssetOut]:
    rows = (
        await session.scalars(
            select(Asset)
            .where(Asset.created_by == user.id)
            .order_by(Asset.created_at.desc())
        )
    ).all()
    return [AssetOut.model_validate(r) for r in rows]


@router.post("/assets", response_model=AssetOut, status_code=201)
async def create_asset(
    payload: AssetCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> AssetOut:
    """Register an asset claim. Status is `pending` until ownership is proven."""
    asset = Asset(
        organization_id=user.default_organization_id,
        created_by=user.id,
        kind=payload.kind,
        value=payload.value.strip(),
        label=(payload.label or "").strip() or None,
        status=AssetStatus.pending,
    )
    session.add(asset)
    await session.flush()
    await session.commit()
    log.info("asset.created", asset_id=str(asset.id), kind=asset.kind.value, value=asset.value)
    return AssetOut.model_validate(asset)


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    asset = await session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.created_by == user.id)
    )
    if asset is None:
        raise NotFound("Asset not found.")
    # Soft revoke -- preserves audit trail
    asset.status = AssetStatus.revoked
    await session.commit()


# ---------------------------- proofs ----------------------------------------


@router.post("/assets/{asset_id}/proofs", response_model=OwnershipProofOut, status_code=201)
async def create_proof(
    asset_id: str,
    payload: OwnershipProofCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> OwnershipProofOut:
    """Begin an ownership-verification challenge for the asset."""
    asset = await session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.created_by == user.id)
    )
    if asset is None:
        raise NotFound("Asset not found.")

    challenge = ownership_service.new_challenge()
    proof = OwnershipProof(
        asset_id=asset.id,
        method=payload.method,
        status=ProofStatus.pending,
        challenge=challenge,
        expected_value=ownership_service.expected_for(payload.method, challenge),
        attempts=0,
    )
    session.add(proof)
    await session.flush()
    await session.commit()

    instructions = ownership_service.instructions(payload.method, asset.value, challenge)
    log.info(
        "proof.created",
        asset_id=str(asset.id),
        proof_id=str(proof.id),
        method=payload.method.value,
    )
    out = OwnershipProofOut.model_validate(proof)
    out.instructions = instructions
    return out


@router.post("/assets/{asset_id}/proofs/{proof_id}/verify", response_model=OwnershipProofOut)
async def verify_proof(
    asset_id: str,
    proof_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> OwnershipProofOut:
    """Attempt to satisfy the challenge. Increments attempt counter."""
    asset = await session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.created_by == user.id)
    )
    if asset is None:
        raise NotFound("Asset not found.")

    proof = await session.scalar(
        select(OwnershipProof).where(OwnershipProof.id == proof_id, OwnershipProof.asset_id == asset.id)
    )
    if proof is None:
        raise NotFound("Proof challenge not found.")

    if proof.status == ProofStatus.verified:
        return OwnershipProofOut.model_validate(proof)

    if proof.attempts >= 10:
        proof.status = ProofStatus.expired
        await session.commit()
        raise Forbidden("Too many verification attempts. Create a new challenge.")

    proof.attempts += 1
    proof.last_checked_at = datetime.now(timezone.utc)

    result = await ownership_service.verify(
        method=proof.method,
        asset_value=asset.value,
        challenge=proof.challenge,
    )
    if result.ok:
        proof.status = ProofStatus.verified
        proof.verified_at = datetime.now(timezone.utc)
        asset.status = AssetStatus.verified
        asset.verified_at = datetime.now(timezone.utc)
        log.info(
            "proof.verified",
            asset_id=str(asset.id),
            proof_id=str(proof.id),
            method=proof.method.value,
        )
    else:
        log.info(
            "proof.failed",
            asset_id=str(asset.id),
            proof_id=str(proof.id),
            method=proof.method.value,
            detail=result.detail,
        )

    await session.commit()
    out = OwnershipProofOut.model_validate(proof)
    out.last_check_detail = result.detail
    return out


# ---------------------------- monitors --------------------------------------


@router.get("/monitors", response_model=list[MonitorOut])
async def list_monitors(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[MonitorOut]:
    rows = (
        await session.scalars(
            select(Monitor)
            .join(Asset, Asset.id == Monitor.asset_id)
            .where(Asset.created_by == user.id)
            .order_by(Monitor.created_at.desc())
        )
    ).all()
    return [MonitorOut.model_validate(r) for r in rows]


@router.post("/monitors", response_model=MonitorOut, status_code=201)
async def create_monitor(
    payload: MonitorCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MonitorOut:
    """Create a recurring monitor. Requires a *verified* asset."""
    asset = await session.scalar(
        select(Asset).where(Asset.id == payload.asset_id, Asset.created_by == user.id)
    )
    if asset is None:
        raise NotFound("Asset not found.")
    if asset.status != AssetStatus.verified:
        raise OwnershipRequired(
            "Asset must be verified before it can be monitored.",
            details={"asset_id": str(asset.id), "asset_status": asset.status.value},
        )

    existing = await session.scalar(
        select(Monitor).where(Monitor.asset_id == asset.id, Monitor.is_active.is_(True))
    )
    if existing is not None:
        raise Conflict("An active monitor already exists for this asset.")

    monitor = Monitor(
        asset_id=asset.id,
        organization_id=asset.organization_id,
        cadence=payload.cadence,
        is_active=True,
        config=payload.config or {},
        next_run_at=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    session.add(monitor)
    await session.flush()
    await session.commit()

    # Enqueue an immediate baseline scan.
    redis = await get_redis()
    await redis.enqueue(
        "scan",
        {
            "kind": "monitor_diff",
            "monitor_id": str(monitor.id),
            "asset_id": str(asset.id),
            "target": asset.value,
            "asset_authorized": True,
        },
    )
    log.info("monitor.created", monitor_id=str(monitor.id), asset_id=str(asset.id))
    return MonitorOut.model_validate(monitor)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def stop_monitor(
    monitor_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    monitor = await session.scalar(
        select(Monitor)
        .join(Asset, Asset.id == Monitor.asset_id)
        .where(Monitor.id == monitor_id, Asset.created_by == user.id)
    )
    if monitor is None:
        raise NotFound("Monitor not found.")
    monitor.is_active = False
    await session.commit()
    log.info("monitor.stopped", monitor_id=str(monitor.id))
