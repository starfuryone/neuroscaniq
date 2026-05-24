"""Seed an initial admin user.

Usage:
    python -m app.scripts.seed_admin --email admin@example.com --password 'SuperSecret123'

Idempotent: if the user exists, only role/active flags are updated.
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from app.core.logging import configure_logging
from app.core.security import hash_password
from app.db.session import session_scope
from app.models.user import User, UserRole


async def seed(email: str, password: str, full_name: str) -> None:
    async with session_scope() as session:
        user = await session.scalar(select(User).where(User.email == email.lower()))
        if user is None:
            user = User(
                email=email.lower(),
                full_name=full_name,
                password_hash=hash_password(password),
                role=UserRole.admin,
                is_active=True,
                is_email_verified=True,
            )
            session.add(user)
            print(f"[seed] Created admin: {email}")
        else:
            user.role = UserRole.admin
            user.is_active = True
            user.is_email_verified = True
            user.password_hash = hash_password(password)
            print(f"[seed] Updated admin: {email}")
        await session.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--name", default="Admin")
    args = parser.parse_args()
    configure_logging()
    asyncio.run(seed(args.email, args.password, args.name))


if __name__ == "__main__":
    main()
