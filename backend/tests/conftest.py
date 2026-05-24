"""Shared test fixtures."""

from __future__ import annotations

import asyncio
import os

import pytest

# Force test environment before anything imports app.config.
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/neuroscaniq_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("OPENSEARCH_URL", "http://localhost:9200")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("ALLOWED_SCAN_CIDRS", "203.0.113.0/24")  # TEST-NET-3 -- safe to use in docs/tests


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
