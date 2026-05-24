"""Host detail endpoints.

GET /host/{ip}            full host record with services, TLS, risk factors, AI summary
GET /host/{ip}/history    paginated observation history (append-only)
GET /host/{ip}/screenshots screenshots indexed for this host
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.errors import NotFound
from app.db.session import get_db
from app.models.host import Host, HostObservation
from app.models.screenshot import Screenshot
from app.models.user import User
from app.schemas.schemas import (
    HostDetail,
    HostObservationOut,
    ScreenshotOut,
)
from app.services.ai_analyzer import ai_analyzer
from app.services.opensearch import get_opensearch
from app.services.storage import storage_service

log = structlog.get_logger(__name__)
router = APIRouter()


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise NotFound("Invalid IP address.") from exc


@router.get("/{ip}", response_model=HostDetail)
async def get_host(
    ip: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    include_ai: bool = Query(True, description="Include AI-generated summary."),
) -> HostDetail:
    """Return the most recent enriched record for a single IPv4/v6."""
    normalized = _validate_ip(ip)

    os_client = await get_opensearch()
    try:
        doc = await os_client.get(index="hosts", id=normalized)
    except Exception:  # noqa: BLE001
        # Fall through to Postgres lookup; OpenSearch may simply not have indexed yet.
        doc = None

    if doc is not None and doc.get("found"):
        src = doc["_source"]
    else:
        host = await session.scalar(select(Host).where(Host.ip == normalized))
        if host is None:
            raise NotFound(f"Host {normalized} is not in the index.")
        src = {
            "ip": str(host.ip),
            "hostname": host.hostname,
            "country": host.country,
            "city": host.city,
            "region": host.region,
            "asn": host.asn,
            "asn_org": host.asn_org,
            "organization": host.organization,
            "risk_score": host.risk_score,
            "risk_level": host.risk_level,
            "tags": host.tags or [],
            "ports": [],
            "services": [],
            "tls": None,
            "http": None,
            "last_seen": host.last_seen_at.isoformat() if host.last_seen_at else None,
        }

    ai_summary: str | None = None
    if include_ai:
        try:
            ai_summary = await ai_analyzer.summarize_host(src)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai_summary_failed", ip=normalized, error=str(exc))
            ai_summary = None

    return HostDetail(
        ip=src["ip"],
        hostname=src.get("hostname"),
        country=src.get("country"),
        city=src.get("city"),
        region=src.get("region"),
        asn=src.get("asn"),
        asn_org=src.get("asn_org"),
        organization=src.get("organization"),
        ports=src.get("ports", []),
        services=src.get("services", []),
        tls=src.get("tls"),
        http=src.get("http"),
        risk_score=float(src.get("risk_score", 0.0)),
        risk_level=src.get("risk_level", "low"),
        risk_factors=src.get("risk_factors", {}),
        tags=src.get("tags", []),
        last_seen=src.get("last_seen"),
        ai_summary=ai_summary,
    )


@router.get("/{ip}/history", response_model=list[HostObservationOut])
async def host_history(
    ip: str,
    limit: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[HostObservationOut]:
    """Return recent immutable observations for trend/change analysis."""
    normalized = _validate_ip(ip)
    host = await session.scalar(select(Host).where(Host.ip == normalized))
    if host is None:
        raise NotFound(f"Host {normalized} is not tracked.")

    rows = (
        await session.scalars(
            select(HostObservation)
            .where(HostObservation.host_id == host.id)
            .order_by(HostObservation.observed_at.desc())
            .limit(limit)
        )
    ).all()
    return [HostObservationOut.model_validate(r) for r in rows]


@router.get("/{ip}/screenshots", response_model=list[ScreenshotOut])
async def host_screenshots(
    ip: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[ScreenshotOut]:
    """List screenshots captured for this host. Returns presigned download URLs."""
    normalized = _validate_ip(ip)
    host = await session.scalar(select(Host).where(Host.ip == normalized))
    if host is None:
        return []

    shots = (
        await session.scalars(
            select(Screenshot)
            .where(Screenshot.host_id == host.id)
            .order_by(Screenshot.captured_at.desc())
        )
    ).all()

    out: list[ScreenshotOut] = []
    for s in shots:
        url = storage_service.presigned_url(s.s3_key) if s.s3_key else None
        thumb = storage_service.presigned_url(s.thumbnail_s3_key) if s.thumbnail_s3_key else None
        out.append(
            ScreenshotOut(
                id=str(s.id),
                ip=str(host.ip),
                port=s.port,
                url=s.url,
                title=s.title,
                captured_at=s.captured_at or datetime.now(timezone.utc),
                technology_stack=s.technology_stack or [],
                image_url=url,
                thumbnail_url=thumb,
            )
        )
    return out
