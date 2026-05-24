"""Liveness and readiness probes.

`/health` is unauthenticated and intentionally lightweight; `/health/ready`
performs deeper checks against Postgres, Redis, and OpenSearch.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.db.session import get_db
from app.services.opensearch import get_opensearch
from app.services.redis import get_redis

log = structlog.get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Cheap liveness probe used by Docker/k8s."""
    return {"status": "ok", "version": __version__}


@router.get("/health/ready")
async def ready(session: AsyncSession = Depends(get_db)) -> dict[str, object]:
    """Readiness probe verifying all critical dependencies are reachable."""
    checks: dict[str, str] = {}

    try:
        await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("readiness.postgres_failed", error=str(exc))
        checks["postgres"] = f"fail: {exc.__class__.__name__}"

    try:
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("readiness.redis_failed", error=str(exc))
        checks["redis"] = f"fail: {exc.__class__.__name__}"

    try:
        os_client = await get_opensearch()
        await os_client.cluster.health(params={"timeout": "1s"})
        checks["opensearch"] = "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("readiness.opensearch_failed", error=str(exc))
        checks["opensearch"] = f"fail: {exc.__class__.__name__}"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks, "version": __version__}
