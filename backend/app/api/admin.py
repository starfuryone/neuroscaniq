"""Administrative endpoints.

All routes require role=admin. Operations include user moderation,
queue introspection, and abuse-signal review.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_role
from app.core.errors import NotFound
from app.db.session import get_db
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.host import Host
from app.models.scan_job import JobStatus, ScanJob
from app.models.user import User, UserRole
from app.schemas.schemas import AdminStats, AuditLogOut, UserOut
from app.services.redis import get_redis

router = APIRouter()


@router.get("/stats", response_model=AdminStats)
async def stats(
    _: User = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_db),
) -> AdminStats:
    """High-level operational metrics for the admin console."""
    user_count = await session.scalar(select(func.count()).select_from(User)) or 0
    host_count = await session.scalar(select(func.count()).select_from(Host)) or 0
    alert_open = (
        await session.scalar(
            select(func.count()).select_from(Alert).where(Alert.is_resolved.is_(False))
        )
        or 0
    )
    jobs_queued = (
        await session.scalar(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == JobStatus.queued)
        )
        or 0
    )
    jobs_running = (
        await session.scalar(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == JobStatus.running)
        )
        or 0
    )

    redis = await get_redis()
    try:
        scan_q_len = int(await redis.llen("queue:scan"))
        alert_q_len = int(await redis.llen("queue:alert"))
    except Exception:  # noqa: BLE001
        scan_q_len = -1
        alert_q_len = -1

    return AdminStats(
        users=int(user_count),
        hosts=int(host_count),
        open_alerts=int(alert_open),
        jobs_queued=int(jobs_queued),
        jobs_running=int(jobs_running),
        scan_queue_depth=scan_q_len,
        alert_queue_depth=alert_q_len,
    )


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: User = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    q: str | None = Query(None),
) -> list[UserOut]:
    stmt = select(User).order_by(User.created_at.desc())
    if q:
        stmt = stmt.where(User.email.ilike(f"%{q.strip()}%"))
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await session.scalars(stmt)).all()
    return [UserOut.model_validate(r) for r in rows]


@router.post("/users/{user_id}/deactivate", response_model=UserOut)
async def deactivate_user(
    user_id: str,
    _: User = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await session.get(User, user_id)
    if user is None:
        raise NotFound("User not found.")
    user.is_active = False
    await session.commit()
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/activate", response_model=UserOut)
async def activate_user(
    user_id: str,
    _: User = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await session.get(User, user_id)
    if user is None:
        raise NotFound("User not found.")
    user.is_active = True
    await session.commit()
    return UserOut.model_validate(user)


@router.get("/audit-log", response_model=list[AuditLogOut])
async def list_audit(
    _: User = Depends(require_role(UserRole.admin)),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    user_id: str | None = Query(None),
    action: str | None = Query(None),
) -> list[AuditLogOut]:
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if user_id:
        stmt = stmt.where(AuditLog.actor_user_id == user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await session.scalars(stmt)).all()
    return [AuditLogOut.model_validate(r) for r in rows]
