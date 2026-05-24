"""Async Redis client singleton and small helpers."""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis

from app.config import settings


class RedisClient:
    def __init__(self, url: str):
        self.client: aioredis.Redis = aioredis.from_url(
            url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=64,
        )

    async def ping(self) -> bool:
        return await self.client.ping()

    async def aclose(self) -> None:
        await self.client.aclose()

    # Convenience: JSON get/set
    async def set_json(self, key: str, value: Any, *, ttl: int | None = None) -> None:
        await self.client.set(key, json.dumps(value, default=str), ex=ttl)

    async def get_json(self, key: str) -> Any:
        raw = await self.client.get(key)
        return json.loads(raw) if raw else None

    # Job queue helpers (BullMQ-style semantics via simple list + pubsub).
    # We avoid full BullMQ here; workers use rq for the heavy lifting.
    async def enqueue(self, queue: str, payload: dict) -> str:
        from uuid import uuid4
        job_id = str(uuid4())
        await self.client.lpush(f"queue:{queue}", json.dumps({"id": job_id, **payload}))
        await self.client.publish(f"queue:{queue}:new", job_id)
        return job_id


redis_client = RedisClient(settings.redis_url)


async def get_redis() -> aioredis.Redis:
    """Return the raw async Redis connection for direct operations."""
    return redis_client.client
