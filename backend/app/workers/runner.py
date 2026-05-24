"""Worker runner -- dispatches jobs from Redis queues to handlers.

Usage:
    python -m app.workers.runner --queue scan
    python -m app.workers.runner --queue screenshot
    python -m app.workers.runner --queue monitor
    python -m app.workers.runner --queue alert

Each queue handler is registered below. The runner uses Redis BLPOP for
backpressure-free dispatch. Job results are persisted to the `scan_jobs`
table for observability.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from datetime import datetime, timezone
from typing import Awaitable, Callable

import structlog
from prometheus_client import start_http_server

import app.services.metrics  # noqa: F401

from app.core.logging import configure_logging
from app.db.session import session_scope
from app.models.scan_job import JobKind, JobStatus, ScanJob
from app.services.redis import get_redis
from app.workers.alert import handle_alert
from app.workers.monitor import handle_monitor
from app.workers.scanner import handle_scan
from app.workers.screenshot import handle_screenshot

log = structlog.get_logger(__name__)

Handler = Callable[[dict], Awaitable[dict | None]]

HANDLERS: dict[str, Handler] = {
    "scan": handle_scan,
    "scanner": handle_scan,
    "screenshot": handle_screenshot,
    "monitor": handle_monitor,
    "alert": handle_alert,
}

_shutdown = asyncio.Event()


def _signal_handler(signum: int, _frame: object) -> None:  # noqa: ARG001
    log.info("worker.signal", signal=signum)
    _shutdown.set()


async def _run_one(queue: str, handler: Handler) -> None:
    """Pop a single job and run it through the handler.

    Persists a ScanJob row tracking lifecycle. Errors are caught and logged
    -- they should never crash the worker loop.
    """
    redis = await get_redis()
    queue_key = f"queue:{queue}"
    payload_raw = await redis.blpop([queue_key], timeout=2)
    if payload_raw is None:
        return

    _, body = payload_raw
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        log.error("worker.bad_payload", queue=queue, body=body[:200] if isinstance(body, str) else str(body)[:200])
        return

    job_kind_raw = payload.get("kind", queue)
    try:
        job_kind = JobKind(job_kind_raw)
    except ValueError:
        job_kind = JobKind.banner

    target = payload.get("target", "")
    job_id: str | None = None

    async with session_scope() as session:
        job = ScanJob(
            kind=job_kind,
            status=JobStatus.running,
            target=target,
            monitor_id=payload.get("monitor_id"),
            asset_id=payload.get("asset_id"),
            started_at=datetime.now(timezone.utc),
        )
        session.add(job)
        await session.flush()
        job_id = str(job.id)
        await session.commit()

    started = asyncio.get_event_loop().time()
    result: dict | None = None
    error: str | None = None
    status: JobStatus = JobStatus.completed

    try:
        result = await handler(payload)
    except Exception as exc:  # noqa: BLE001
        error = f"{exc.__class__.__name__}: {exc}"
        status = JobStatus.failed
        log.exception("worker.job_failed", queue=queue, target=target, error=error)

    duration_ms = int((asyncio.get_event_loop().time() - started) * 1000)

    async with session_scope() as session:
        job = await session.get(ScanJob, job_id)
        if job is not None:
            job.status = status
            job.finished_at = datetime.now(timezone.utc)
            job.duration_ms = duration_ms
            job.error = error
            job.result = result if isinstance(result, dict) else None
            await session.commit()

    log.info(
        "worker.job_done",
        queue=queue,
        target=target,
        status=status.value,
        duration_ms=duration_ms,
    )


async def run(queue: str) -> None:
    if queue not in HANDLERS:
        raise SystemExit(f"Unknown queue: {queue}. Available: {sorted(HANDLERS)}")

    handler = HANDLERS[queue]
    log.info("worker.started", queue=queue)

    while not _shutdown.is_set():
        try:
            await _run_one(queue, handler)
        except Exception as exc:  # noqa: BLE001
            log.exception("worker.loop_error", queue=queue, error=str(exc))
            await asyncio.sleep(1.0)

    log.info("worker.stopped", queue=queue)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", required=True, choices=sorted(HANDLERS))
    args = parser.parse_args()

    configure_logging()
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    start_http_server(9100)

    try:
        asyncio.run(run(args.queue))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
