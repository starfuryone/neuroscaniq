"""Screenshot worker.

Uses Playwright Chromium (headless) to capture a single screenshot of an
authorized HTTP endpoint, then uploads to S3/MinIO and indexes in OpenSearch.

Like all workers, gates the operation through `assert_scan_allowed`.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from typing import Any

import structlog
from PIL import Image
from sqlalchemy import select

from app.core.scan_guard import assert_scan_allowed
from app.db.session import session_scope
from app.models.host import Host
from app.models.screenshot import Screenshot
from app.services.opensearch import get_opensearch
from app.services.storage import storage_service

log = structlog.get_logger(__name__)


async def _capture(url: str) -> tuple[bytes, str | None, list[str]] | None:
    """Return (png_bytes, page_title, tech_stack_hints) or None on failure."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("screenshot.playwright_missing")
        return None

    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            ctx = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent="NeuroScanIQ/0.1 (defensive screenshot)",
            )
            page = await ctx.new_page()
            try:
                await page.goto(url, timeout=10_000, wait_until="domcontentloaded")
            except Exception:  # noqa: BLE001
                return None

            title: str | None = None
            try:
                title = await page.title()
            except Exception:  # noqa: BLE001
                title = None

            tech_hints = await page.evaluate(
                """() => {
                    const out = [];
                    if (window.React) out.push('react');
                    if (window.Vue) out.push('vue');
                    if (window.angular) out.push('angular');
                    if (window.jQuery || window.$) out.push('jquery');
                    if (document.querySelector('meta[name="generator"]')) {
                        out.push('generator:' + document.querySelector('meta[name="generator"]').content);
                    }
                    return out;
                }"""
            )

            png = await page.screenshot(type="png", full_page=False)
            return png, title, list(tech_hints or [])
        finally:
            await browser.close()


def _thumbnail(png: bytes, size: tuple[int, int] = (320, 200)) -> bytes:
    img = Image.open(io.BytesIO(png))
    img.thumbnail(size)
    out = io.BytesIO()
    img.convert("RGB").save(out, format="JPEG", quality=80)
    return out.getvalue()


async def handle_screenshot(payload: dict) -> dict[str, Any]:
    target = payload.get("target", "")
    url = payload.get("url") or f"http://{target}/"
    asset_authorized = bool(payload.get("asset_authorized", False))

    # Re-gate before any browser network activity.
    await assert_scan_allowed(target, asset_authorized=asset_authorized)

    result = await _capture(url)
    if result is None:
        return {"captured": False, "url": url}

    png, title, tech = result
    sha = hashlib.sha256(png).hexdigest()
    thumb = _thumbnail(png)

    s3_key = f"screenshots/{sha[:2]}/{sha}.png"
    thumb_key = f"screenshots/{sha[:2]}/{sha}.thumb.jpg"

    storage_service.put_object(s3_key, png, content_type="image/png")
    storage_service.put_object(thumb_key, thumb, content_type="image/jpeg")

    now = datetime.now(timezone.utc)
    host_id = payload.get("host_id")

    async with session_scope() as session:
        if host_id is None:
            host = await session.scalar(select(Host).where(Host.ip == target))
            host_id = str(host.id) if host else None

        shot = Screenshot(
            host_id=host_id,
            port=int(url.split(":")[-1].split("/")[0]) if ":" in url.split("//", 1)[-1] else (443 if url.startswith("https") else 80),
            url=url,
            s3_key=s3_key,
            thumbnail_s3_key=thumb_key,
            sha256=sha,
            title=title,
            captured_at=now,
            technology_stack=tech,
        )
        session.add(shot)
        await session.flush()
        shot_id = str(shot.id)
        await session.commit()

    os_client = await get_opensearch()
    try:
        await os_client.index(
            index="screenshots",
            id=shot_id,
            body={
                "ip": target,
                "host_id": host_id,
                "port": shot.port if False else (443 if url.startswith("https") else 80),
                "url": url,
                "title": title,
                "s3_key": s3_key,
                "thumbnail_s3_key": thumb_key,
                "sha256": sha,
                "captured_at": now.isoformat(),
                "technology_stack": tech,
            },
            refresh=False,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("screenshot.os_index_failed", url=url, error=str(exc))

    return {"captured": True, "url": url, "sha256": sha, "title": title}
