"""User profile endpoints (self-service)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.errors import Unauthorized
from app.core.security import hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.schemas import PasswordChangeRequest, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def get_me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.patch("/me", response_model=UserOut)
async def update_me(
    payload: UserUpdate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    await session.commit()
    return UserOut.model_validate(user)


@router.post("/me/password", response_model=UserOut)
async def change_password(
    payload: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserOut:
    if not verify_password(user.password_hash, payload.current_password):
        raise Unauthorized("Current password is incorrect.")
    user.password_hash = hash_password(payload.new_password)
    await session.commit()
    return UserOut.model_validate(user)
