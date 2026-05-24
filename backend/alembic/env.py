"""Alembic migration environment.

Uses our async engine but runs migrations synchronously via
`run_sync` so that operations like CREATE INDEX CONCURRENTLY work the
same as in any traditional Alembic project.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import get_settings
from app.db.base import Base
# Import all models so Alembic sees them.
from app.models import (  # noqa: F401
    alert,
    api_key,
    asset,
    audit_log,
    billing,
    host,
    monitor,
    organization,
    port,
    risk,
    scan_job,
    screenshot,
    service,
    user,
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _build_url() -> str:
    """Pull DB URL from the settings layer."""
    return get_settings().DATABASE_URL


def run_migrations_offline() -> None:
    context.configure(
        url=_build_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    cfg_section = config.get_section(config.config_ini_section, {})
    cfg_section["sqlalchemy.url"] = _build_url()

    connectable = async_engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
