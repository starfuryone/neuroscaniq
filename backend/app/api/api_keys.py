"""API key management.

The plaintext secret is only ever returned in the create response; thereafter
only the prefix and metadata are visible. Revocation flips `is_active` and
is enforced inside `core.deps.get_current_user`.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.errors import NotFound
from app.core.security import generate_api_key
from app.db.session import get_db
from app.models.api_key import APIKey
from app.models.user import User
from app.schemas.schemas import APIKeyCreate, APIKeyCreated, APIKeyOut

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("", response_model=list[APIKeyOut])
async def list_keys(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[APIKeyOut]:
    keys = (
        await session.scalars(
            select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
        )
    ).all()
    return [APIKeyOut.model_validate(k) for k in keys]


@router.post("", response_model=APIKeyCreated, status_code=201)
async def create_key(
    payload: APIKeyCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> APIKeyCreated:
    """Create a new API key. Plaintext is shown once -- store it now."""
    display, prefix, secret_hash = generate_api_key()
    record = APIKey(
        user_id=user.id,
        name=payload.name.strip(),
        prefix=prefix,
        secret_hash=secret_hash,
        is_active=True,
    )
    session.add(record)
    await session.flush()
    await session.commit()

    log.info("api_key.created", user_id=str(user.id), key_id=str(record.id), prefix=prefix)
    return APIKeyCreated(
        id=str(record.id),
        name=record.name,
        prefix=prefix,
        plaintext_key=display,
        created_at=record.created_at,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    record = await session.scalar(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    )
    if record is None:
        raise NotFound("API key not found.")
    record.is_active = False
    await session.commit()
    log.info("api_key.revoked", user_id=str(user.id), key_id=key_id)
