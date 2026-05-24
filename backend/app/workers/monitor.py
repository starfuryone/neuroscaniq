"""Monitor worker.

Two responsibilities:
  1. SCHEDULER -- handle_monitor receives `kind: tick` periodically and
     enqueues `scan` jobs for all Monitors whose `next_run_at` has elapsed.
  2. DIFF -- handle_monitor receives `kind: diff` after each monitor scan
     and compares the new snapshot to the prior one, emitting Alerts as
     appropriate.

The "tick" cadence is driven by a small cron-like dispatcher started by
the compose stack (`docker compose run --rm worker-monitor python -m
app.workers.tick`) or by a sidecar container.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select

from app.db.session import session_scope
from app.models.alert import Alert, AlertKind, AlertSeverity
from app.models.asset import Asset
from app.models.monitor import Monitor, MonitorCadence
from app.services.redis import get_redis

log = structlog.get_logger(__name__)


CADENCE_TO_DELTA = {
    MonitorCadence.hourly: timedelta(hours=1),
    MonitorCadence.daily: timedelta(days=1),
    MonitorCadence.weekly: timedelta(days=7),
}


async def handle_monitor(payload: dict) -> dict[str, Any]:
    kind = payload.get("kind", "tick")
    if kind == "tick":
        return await _tick()
    if kind == "diff":
        return await _diff(payload)
    log.warning("monitor.unknown_kind", kind=kind)
    return {"ok": False, "reason": "unknown_kind"}


async def _tick() -> dict[str, Any]:
    """Find monitors whose next_run_at has elapsed and enqueue scans."""
    now = datetime.now(timezone.utc)
    enqueued = 0
    async with session_scope() as session:
        rows = (
            await session.scalars(
                select(Monitor).where(
                    Monitor.is_active.is_(True),
                    Monitor.next_run_at <= now,
                )
            )
        ).all()

        redis = await get_redis()
        for m in rows:
            asset = await session.get(Asset, m.asset_id)
            if asset is None or asset.status.value != "verified":
                continue

            await redis.enqueue(
                "scan",
                {
                    "kind": "monitor_diff",
                    "monitor_id": str(m.id),
                    "asset_id": str(asset.id),
                    "target": asset.value,
                    "asset_authorized": True,
                },
            )
            m.last_run_at = now
            m.next_run_at = now + CADENCE_TO_DELTA[m.cadence]
            enqueued += 1
        await session.commit()

    return {"tick_at": now.isoformat(), "enqueued": enqueued}


async def _diff(payload: dict) -> dict[str, Any]:
    """Compare current vs last snapshot for a monitor; emit Alerts."""
    monitor_id = payload["monitor_id"]
    current = payload.get("current", {})

    async with session_scope() as session:
        monitor = await session.get(Monitor, monitor_id)
        if monitor is None:
            return {"ok": False, "reason": "monitor_gone"}

        prev = monitor.last_snapshot or {}
        monitor.last_snapshot = current

        alerts_emitted: list[dict] = []

        prev_ports = set(prev.get("ports") or [])
        cur_ports = set(current.get("ports") or [])
        new_ports = cur_ports - prev_ports
        closed_ports = prev_ports - cur_ports

        for port in sorted(new_ports):
            a = Alert(
                asset_id=monitor.asset_id,
                monitor_id=monitor.id,
                host_id=payload.get("host_id"),
                severity=AlertSeverity.medium,
                kind=AlertKind.new_port,
                title=f"New open port: {port}",
                message=f"Port {port}/tcp is now open on this asset.",
            )
            session.add(a)
            alerts_emitted.append({"kind": "new_port", "port": port})

        for port in sorted(closed_ports):
            a = Alert(
                asset_id=monitor.asset_id,
                monitor_id=monitor.id,
                host_id=payload.get("host_id"),
                severity=AlertSeverity.info,
                kind=AlertKind.service_change,
                title=f"Port closed: {port}",
                message=f"Port {port}/tcp is no longer open.",
            )
            session.add(a)
            alerts_emitted.append({"kind": "closed_port", "port": port})

        prev_score = float(prev.get("risk_score") or 0.0)
        cur_score = float(current.get("risk_score") or 0.0)
        if cur_score - prev_score >= 15.0:
            a = Alert(
                asset_id=monitor.asset_id,
                monitor_id=monitor.id,
                host_id=payload.get("host_id"),
                severity=AlertSeverity.high,
                kind=AlertKind.risk_score_jump,
                title=f"Risk score jumped from {prev_score:.0f} to {cur_score:.0f}",
                message="Inspect the host detail page for new exposure factors.",
            )
            session.add(a)
            alerts_emitted.append({"kind": "risk_jump", "from": prev_score, "to": cur_score})

        prev_tls = (prev.get("tls") or {}).get("fingerprint_sha256")
        cur_tls = (current.get("tls") or {}).get("fingerprint_sha256")
        if prev_tls and cur_tls and prev_tls != cur_tls:
            a = Alert(
                asset_id=monitor.asset_id,
                monitor_id=monitor.id,
                host_id=payload.get("host_id"),
                severity=AlertSeverity.medium,
                kind=AlertKind.tls_change,
                title="TLS certificate changed",
                message=f"Cert fingerprint changed from {prev_tls[:12]}... to {cur_tls[:12]}...",
            )
            session.add(a)
            alerts_emitted.append({"kind": "tls_change"})

        await session.commit()

        # Fan out to the alert delivery worker.
        if alerts_emitted:
            redis = await get_redis()
            await redis.enqueue(
                "alert",
                {
                    "kind": "deliver",
                    "asset_id": str(monitor.asset_id),
                    "monitor_id": str(monitor.id),
                    "events": alerts_emitted,
                },
            )

    return {"monitor_id": monitor_id, "alerts": len(alerts_emitted)}
