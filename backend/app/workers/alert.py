"""Alert delivery worker.

Sends email + webhook notifications for unread alerts on an asset.
Idempotency: marks `delivered_email` / `delivered_webhook` on the row.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog
from sqlalchemy import select

from app.db.session import session_scope
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.monitor import Monitor
from app.models.user import User
from app.services.email import email_service

log = structlog.get_logger(__name__)


async def handle_alert(payload: dict) -> dict[str, Any]:
    asset_id = payload.get("asset_id")
    monitor_id = payload.get("monitor_id")
    if asset_id is None:
        return {"ok": False, "reason": "no_asset"}

    sent_email = 0
    sent_webhook = 0

    async with session_scope() as session:
        asset = await session.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "asset_gone"}

        owner = await session.get(User, asset.created_by) if asset.created_by else None
        monitor = await session.get(Monitor, monitor_id) if monitor_id else None
        webhook_url = (monitor.config or {}).get("webhook_url") if monitor else None

        alerts = (
            await session.scalars(
                select(Alert).where(
                    Alert.asset_id == asset.id,
                    Alert.delivered_email.is_(False) | Alert.delivered_webhook.is_(False),
                )
            )
        ).all()

        for alert in alerts:
            if owner and not alert.delivered_email:
                try:
                    await email_service.send(
                        to=owner.email,
                        template="alert",
                        context={
                            "full_name": owner.full_name,
                            "asset_value": asset.value,
                            "severity": alert.severity.value,
                            "title": alert.title,
                            "message": alert.message,
                        },
                    )
                    alert.delivered_email = True
                    sent_email += 1
                except Exception as exc:  # noqa: BLE001
                    log.warning("alert.email_failed", alert_id=str(alert.id), error=str(exc))

            if webhook_url and not alert.delivered_webhook:
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            webhook_url,
                            json={
                                "alert_id": str(alert.id),
                                "asset_id": str(asset.id),
                                "severity": alert.severity.value,
                                "kind": alert.kind.value,
                                "title": alert.title,
                                "message": alert.message,
                                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                            },
                        )
                        if 200 <= resp.status_code < 300:
                            alert.delivered_webhook = True
                            sent_webhook += 1
                        else:
                            log.warning(
                                "alert.webhook_non_2xx",
                                alert_id=str(alert.id),
                                status=resp.status_code,
                            )
                except Exception as exc:  # noqa: BLE001
                    log.warning("alert.webhook_failed", alert_id=str(alert.id), error=str(exc))

        await session.commit()

    return {"asset_id": asset_id, "email": sent_email, "webhook": sent_webhook}
