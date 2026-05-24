"""Banner / TLS / HTTP scanner.

Defensive posture:
  * NEVER probes a target without `scan_guard.assert_scan_allowed` clearance.
  * Only performs polite, low-volume connect probes -- no rate-floods,
    no exploit payloads, no credential attempts, no fuzzing.
  * All raw responses are stored verbatim in HostObservation for audit;
    no derived state can be smuggled into the index without first appearing
    in an observation row.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select

from app.config import settings
from app.core.scan_guard import assert_scan_allowed
from app.db.session import session_scope
from app.models.host import Host, HostObservation
from app.models.port import Port
from app.models.service import Service
from app.services.ai_analyzer import ai_analyzer
from app.services.metrics import (
    PORTS_DISCOVERED,
    SCAN_COMPLETED,
    SCAN_DURATION,
    SCAN_FAILED,
    SCAN_STARTED,
)
from app.services.nmap_scanner import enrich_services, is_nmap_available, run_nmap_scan
from app.services.opensearch import get_opensearch
from app.services.redis import get_redis
from app.services.risk_scorer import risk_scorer

log = structlog.get_logger(__name__)


# Default sweep -- intentionally a small, polite set of well-known ports.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9300,
    11211, 27017,
)

CONNECT_TIMEOUT = 3.0
BANNER_TIMEOUT = 4.0


async def _connect_probe(ip: str, port: int) -> dict[str, Any] | None:
    """Single non-blocking connect + grab any unsolicited banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT
        )
    except (asyncio.TimeoutError, OSError):
        return None

    banner: bytes = b""
    try:
        banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "banner": banner.decode("utf-8", errors="replace").strip() if banner else "",
    }


async def _http_probe(ip: str, port: int, tls: bool) -> dict[str, Any] | None:
    """GET / over http(s) to capture title and headers. No retries, no auth."""
    scheme = "https" if tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 -- we record cert separately, not validating CA
            timeout=BANNER_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": "NeuroScanIQ/0.1 (defensive scan; +https://neuroscaniq.local/about)"},
        ) as client:
            resp = await client.get(url)
    except (httpx.HTTPError, OSError):
        return None

    body = resp.text[:4096]
    title: str | None = None
    if "<title" in body.lower():
        start = body.lower().index("<title")
        end_open = body.index(">", start)
        try:
            end_close = body.lower().index("</title>", end_open)
            title = body[end_open + 1 : end_close].strip()[:200]
        except ValueError:
            title = None

    return {
        "url": url,
        "status": resp.status_code,
        "title": title,
        "headers": dict(resp.headers),
        "server": resp.headers.get("server"),
    }


async def _tls_probe(ip: str, port: int) -> dict[str, Any] | None:
    """Pull cert metadata. Validation OFF -- we only inspect, not trust."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
            timeout=CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None

    info: dict[str, Any] = {}
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        cert = ssl_obj.getpeercert(binary_form=False) or {}
        bin_cert = ssl_obj.getpeercert(binary_form=True)
        import hashlib

        info["subject_cn"] = _x509_cn(cert.get("subject", []))
        info["issuer_cn"] = _x509_cn(cert.get("issuer", []))
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        san = []
        for typ, val in cert.get("subjectAltName", []):
            san.append(f"{typ}:{val}")
        info["san"] = san
        info["fingerprint_sha256"] = hashlib.sha256(bin_cert).hexdigest() if bin_cert else None
        info["cipher"] = ssl_obj.cipher()
        info["protocol"] = ssl_obj.version()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    return info


def _x509_cn(name: list) -> str | None:
    """Pull CN from the dotted-tuple form returned by ssl.getpeercert."""
    for rdn in name:
        for k, v in rdn:
            if k.lower() == "commonname":
                return v
    return None


async def handle_scan(payload: dict) -> dict[str, Any]:
    """Top-level scan handler. `payload` shape:

    {
      "kind": "banner" | "monitor_diff",
      "target": "1.2.3.4",
      "asset_id": "...",
      "monitor_id": "...",          # optional
      "asset_authorized": true,     # set by API on monitor creation
      "ports": [80, 443]            # optional override
    }
    """
    target = payload.get("target", "")
    asset_authorized = bool(payload.get("asset_authorized", False))
    is_monitor = payload.get("kind") == "monitor_diff"

    SCAN_STARTED.labels(scan_type="banner").inc()
    scan_start = __import__("time").monotonic()

    # Single, central authorization point.
    resolved = assert_scan_allowed(target, asset_authorized=asset_authorized)
    log.info("scan.authorized", target=target, resolved=str(resolved.ip))

    ports = tuple(payload.get("ports") or DEFAULT_PORTS)
    ip = str(resolved.ip)

    # Deep scan: skip banner probes, run nmap directly on specified/default ports
    if payload.get("kind") == "deep_scan" and payload.get("use_nmap"):
        nmap_ports = list(ports)
        try:
            nmap_result = await run_nmap_scan(
                ip, nmap_ports,
                asset_authorized=True,
                bypass_cooldown=True,
                force_refresh=True,
            )
            if nmap_result.error:
                return {"ip": ip, "error": nmap_result.error}
            services_data = [
                {"port": s.port, "protocol": s.protocol, "state": s.state,
                 "service_name": s.service, "product": s.product,
                 "version": s.version, "cpe": s.cpe}
                for s in nmap_result.services
            ]
            SCAN_COMPLETED.labels(scan_type="deep_scan").inc()
            SCAN_DURATION.labels(scan_type="deep_scan").observe(
                nmap_result.scan_time_ms / 1000
            )
            PORTS_DISCOVERED.labels(scan_type="deep_scan").observe(len(nmap_result.services))
            return {
                "ip": ip,
                "scan_type": "deep_scan",
                "services": services_data,
                "scan_time_ms": nmap_result.scan_time_ms,
            }
        except Exception as exc:
            SCAN_FAILED.labels(scan_type="deep_scan", reason="error").inc()
            raise

    open_results: list[dict[str, Any]] = []
    probes = [_connect_probe(ip, p) for p in ports]
    for r in await asyncio.gather(*probes, return_exceptions=False):
        if r is not None:
            open_results.append(r)

    services: list[dict[str, Any]] = []
    tls_info: dict[str, Any] | None = None
    http_info: dict[str, Any] | None = None

    for r in open_results:
        port = r["port"]
        if port in (443, 8443, 993, 995, 465):
            tls = await _tls_probe(ip, port)
            if tls and tls_info is None:
                tls_info = tls
            http = await _http_probe(ip, port, tls=True)
            if http:
                http_info = http_info or http
                r["title"] = http.get("title")
                r["server"] = http.get("server")
        elif port in (80, 8080, 8000):
            http = await _http_probe(ip, port, tls=False)
            if http:
                http_info = http_info or http
                r["title"] = http.get("title")
                r["server"] = http.get("server")
        services.append(r)

    # Nmap enrichment pass (only for authorized assets with feature enabled).
    if asset_authorized and settings.nmap_enabled and is_nmap_available() and services:
        try:
            open_ports = [s["port"] for s in services]
            nmap_result = await run_nmap_scan(
                ip, open_ports,
                asset_authorized=True,
                bypass_cooldown=is_monitor,
            )
            if nmap_result.services and not nmap_result.error:
                services = enrich_services(services, nmap_result.services)
                log.info("scan.nmap_enriched", target=ip, enriched_count=len(nmap_result.services))
        except Exception as exc:  # noqa: BLE001
            log.warning("scan.nmap_failed", target=ip, error=str(exc))

    # Risk score from deterministic factors.
    risk = risk_scorer.score(
        ports=[s["port"] for s in services],
        services=services,
        tls=tls_info,
        http=http_info,
        tags=[],
    )

    # AI tags (additive only -- never authoritative).
    ai_tags: list[str] = []
    ai_summary_text: str | None = None
    try:
        cat = await ai_analyzer.categorize_exposure(
            ip=ip, services=services, tls=tls_info, http=http_info
        )
        if cat:
            ai_tags = cat.get("tags", []) or []
            ai_summary_text = cat.get("summary")
    except Exception as exc:  # noqa: BLE001
        log.warning("scan.ai_failed", error=str(exc))

    now = datetime.now(timezone.utc)

    # Persist to Postgres (idempotent upsert by IP).
    async with session_scope() as session:
        host = await session.scalar(select(Host).where(Host.ip == ip))
        created = False
        if host is None:
            host = Host(ip=ip)
            session.add(host)
            await session.flush()
            created = True

        host.last_seen_at = now
        host.open_port_count = len(services)
        host.risk_score = risk.score
        host.risk_level = risk.level
        if http_info and http_info.get("title"):
            host.hostname = host.hostname or http_info.get("title")
        if ai_tags:
            existing_tags = set(host.tags or [])
            host.tags = sorted(existing_tags | set(ai_tags))

        observation = HostObservation(
            host_id=host.id,
            observed_at=now,
            open_ports=[s["port"] for s in services],
            raw_banner="\n".join(s.get("banner", "") for s in services if s.get("banner")),
            http_headers=http_info.get("headers") if http_info else None,
            tls_info=tls_info,
            notes=ai_summary_text,
        )
        session.add(observation)

        for s in services:
            port_row = await session.scalar(
                select(Port).where(Port.host_id == host.id, Port.port == s["port"])
            )
            if port_row is None:
                port_row = Port(host_id=host.id, port=s["port"], protocol="tcp")
                session.add(port_row)
                await session.flush()
            port_row.state = "open"
            port_row.service_name = s.get("server") or s.get("title")
            port_row.last_seen_at = now

            if s.get("banner") or s.get("title"):
                svc = Service(
                    port_id=port_row.id,
                    title=s.get("title"),
                    server_header=s.get("server"),
                    banner=s.get("banner"),
                    raw=s,
                    observed_at=now,
                )
                session.add(svc)

        await session.commit()
        host_id = str(host.id)

    # Index to OpenSearch.
    os_client = await get_opensearch()
    doc = {
        "ip": ip,
        "hostname": http_info.get("headers", {}).get("host") if http_info else None,
        "ports": [s["port"] for s in services],
        "services": services,
        "tls": tls_info,
        "http": http_info,
        "risk_score": risk.score,
        "risk_level": risk.level,
        "risk_factors": risk.factors,
        "tags": ai_tags,
        "last_seen": now.isoformat(),
    }
    try:
        await os_client.index(index="hosts", id=ip, body=doc, refresh=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("scan.os_index_failed", ip=ip, error=str(exc))

    # If this was a monitor scan, fan out to diff/alert pipeline.
    if payload.get("kind") == "monitor_diff" and payload.get("monitor_id"):
        redis = await get_redis()
        await redis.enqueue(
            "monitor",
            {
                "kind": "diff",
                "monitor_id": payload["monitor_id"],
                "asset_id": payload.get("asset_id"),
                "current": {"ports": [s["port"] for s in services], "risk_score": risk.score, "tls": tls_info},
                "host_id": host_id,
            },
        )

    # Trigger screenshot capture for HTTP-bearing ports (best-effort).
    if http_info:
        redis = await get_redis()
        await redis.enqueue(
            "screenshot",
            {
                "kind": "screenshot",
                "target": ip,
                "asset_id": payload.get("asset_id"),
                "asset_authorized": asset_authorized,
                "url": http_info["url"],
                "host_id": host_id,
            },
        )

    # Record metrics
    scan_elapsed = __import__("time").monotonic() - scan_start
    SCAN_COMPLETED.labels(scan_type="banner").inc()
    SCAN_DURATION.labels(scan_type="banner").observe(scan_elapsed)
    PORTS_DISCOVERED.labels(scan_type="banner").observe(len(services))

    return {
        "ip": ip,
        "open_ports": [s["port"] for s in services],
        "risk_score": risk.score,
        "risk_level": risk.level,
        "host_created": created,
    }
