"""Defensive Nmap integration for service/version enrichment.

This module wraps Nmap as an optional enrichment engine that runs ONLY
against verified, authorized assets. It is strictly constrained:

  * Requires asset_authorized=True — no exceptions.
  * Enforces the same scan_guard authorization as the rest of the platform.
  * Blocks dangerous flags (OS fingerprinting, NSE scripts, spoofing, etc.)
  * Only performs TCP connect + service/version detection with conservative timing.
  * Returns structured, typed results for merging into existing service records.
  * Bounded concurrency via asyncio.Semaphore (NMAP_MAX_CONCURRENT).
  * Redis-backed cooldown to prevent abuse of deep scans.
  * Redis-backed result cache to avoid redundant scanning.

This is NOT a general-purpose scanner. It enriches already-discovered open
ports with product/version/CPE data for defensive asset management.

NOTE: Workers run as non-root. We use -sT (TCP connect) not -sS (SYN).
      -sS requires CAP_NET_RAW which we deliberately do not grant.
      To enable SYN scanning in the future (not recommended):
        # In Dockerfile, before USER app:
        # RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
        # Then change SAFE_DEFAULTS to use -sS instead of -sT.
        # This increases attack surface and is not needed for version detection.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog

from app.config import settings
from app.core.errors import ScanTargetRejected
from app.core.scan_guard import assert_scan_allowed
from app.services.metrics import (
    NMAP_CACHE_HIT,
    NMAP_CACHE_MISS,
    NMAP_CONCURRENCY_WAITING,
    NMAP_COOLDOWN_REJECTED,
    SCAN_COMPLETED,
    SCAN_DURATION,
    SCAN_FAILED,
    SCAN_REJECTED,
    SCAN_STARTED,
    SCAN_TIMEOUT,
    PORTS_DISCOVERED,
)

log = structlog.get_logger(__name__)

NMAP_TIMEOUT_SECONDS = 120

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    """Lazy-init semaphore (must be created inside a running event loop)."""
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.nmap_max_concurrent)
    return _semaphore


BLOCKED_FLAGS: frozenset[str] = frozenset({
    "-A",
    "-O",
    "--script",
    "-iL",
    "-D",
    "-S",
    "-sS",
    "--spoof-mac",
    "-sU",
    "--script-args",
    "--script-help",
    "--script-trace",
    "--script-updatedb",
    "-iR",
    "--excludefile",
    "-e",
    "--ttl",
    "--badsum",
    "--data-length",
    "--ip-options",
    "--source-port",
    "--proxies",
})

SAFE_DEFAULTS: list[str] = [
    "-sT",
    "-sV",
    "-T3",
    "--max-rate", str(settings.nmap_max_rate_pps),
    "--host-timeout", "90s",
    "--open",
    "-oX", "-",
]

CACHE_KEY_PREFIX = "nmap:result:"
COOLDOWN_KEY_PREFIX = "nmap:cooldown:"


@dataclass
class NmapServiceResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    cpe: str
    extra_info: str = ""


@dataclass
class NmapScanResult:
    ip: str
    services: list[NmapServiceResult] = field(default_factory=list)
    scan_time_ms: int = 0
    nmap_version: str = ""
    error: str | None = None
    from_cache: bool = False


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _validate_flags(extra_flags: list[str] | None) -> list[str]:
    """Reject any flag in the blocklist. Returns sanitized flag list."""
    if not extra_flags:
        return []
    validated: list[str] = []
    for flag in extra_flags:
        normalized = flag.split("=")[0] if "=" in flag else flag
        if normalized in BLOCKED_FLAGS:
            raise ValueError(f"Blocked Nmap flag: {normalized}")
        for blocked in BLOCKED_FLAGS:
            if flag.startswith(blocked):
                raise ValueError(f"Blocked Nmap flag: {flag}")
        validated.append(flag)
    return validated


def _parse_xml(xml_output: str) -> list[NmapServiceResult]:
    """Parse Nmap XML output into structured results."""
    results: list[NmapServiceResult] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        log.warning("nmap.xml_parse_failed", error=str(exc))
        return results

    for host_elem in root.findall(".//host"):
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue
        for port_elem in ports_elem.findall("port"):
            portid = port_elem.get("portid", "0")
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service_name = ""
            product = ""
            version = ""
            cpe = ""
            extra_info = ""

            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra_info = service_elem.get("extrainfo", "")
                cpe_elem = service_elem.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    cpe = cpe_elem.text

            results.append(NmapServiceResult(
                port=int(portid),
                protocol=protocol,
                state=state,
                service=service_name,
                product=product,
                version=version,
                cpe=cpe,
                extra_info=extra_info,
            ))

    return results


def _build_command(ip: str, ports: list[int], extra_flags: list[str] | None = None) -> list[str]:
    """Build the nmap command line with safe defaults."""
    validated_extra = _validate_flags(extra_flags)
    port_spec = ",".join(str(p) for p in ports)
    cmd = ["nmap"] + SAFE_DEFAULTS + ["-p", port_spec] + validated_extra + [ip]
    return cmd


def _result_to_cache_dict(result: NmapScanResult) -> dict[str, Any]:
    """Serialize NmapScanResult for Redis storage."""
    return {
        "ip": result.ip,
        "services": [asdict(s) for s in result.services],
        "scan_time_ms": result.scan_time_ms,
        "error": result.error,
    }


def _cache_dict_to_result(data: dict[str, Any]) -> NmapScanResult:
    """Deserialize NmapScanResult from Redis cache."""
    services = [NmapServiceResult(**s) for s in data.get("services", [])]
    return NmapScanResult(
        ip=data["ip"],
        services=services,
        scan_time_ms=data.get("scan_time_ms", 0),
        error=data.get("error"),
        from_cache=True,
    )


async def _check_cache(ip: str) -> NmapScanResult | None:
    """Return cached result if present and not expired."""
    from app.services.redis import get_redis
    try:
        redis = await get_redis()
        raw = await redis.get(f"{CACHE_KEY_PREFIX}{ip}")
        if raw:
            data = json.loads(raw)
            NMAP_CACHE_HIT.inc()
            return _cache_dict_to_result(data)
    except Exception as exc:  # noqa: BLE001
        log.debug("nmap.cache_read_failed", ip=ip, error=str(exc))
    NMAP_CACHE_MISS.inc()
    return None


async def _store_cache(result: NmapScanResult) -> None:
    """Store result in Redis with configured TTL."""
    from app.services.redis import get_redis
    try:
        redis = await get_redis()
        data = json.dumps(_result_to_cache_dict(result), default=str)
        await redis.set(
            f"{CACHE_KEY_PREFIX}{result.ip}",
            data,
            ex=settings.nmap_cache_ttl_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("nmap.cache_write_failed", ip=result.ip, error=str(exc))


async def _check_cooldown(ip: str) -> bool:
    """Return True if the IP is in cooldown (scan should be rejected)."""
    from app.services.redis import get_redis
    try:
        redis = await get_redis()
        return await redis.exists(f"{COOLDOWN_KEY_PREFIX}{ip}") > 0
    except Exception:  # noqa: BLE001
        return False


async def _set_cooldown(ip: str) -> None:
    """Mark an IP as recently scanned for cooldown enforcement."""
    from app.services.redis import get_redis
    try:
        redis = await get_redis()
        await redis.set(
            f"{COOLDOWN_KEY_PREFIX}{ip}",
            "1",
            ex=settings.nmap_cooldown_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("nmap.cooldown_set_failed", ip=ip, error=str(exc))


async def run_nmap_scan(
    target: str,
    ports: list[int],
    *,
    asset_authorized: bool,
    extra_flags: list[str] | None = None,
    timeout: int = NMAP_TIMEOUT_SECONDS,
    force_refresh: bool = False,
    bypass_cooldown: bool = False,
) -> NmapScanResult:
    """Run an Nmap service/version scan against an authorized target.

    This function enforces all security constraints before executing:
      1. asset_authorized MUST be True
      2. Target must pass scan_guard checks
      3. No blocked flags may be present
      4. Nmap must be installed
      5. Concurrency bounded by semaphore
      6. Cooldown period enforced (unless bypass_cooldown=True for monitors)

    Args:
        target: IP address or hostname to scan.
        ports: List of TCP ports to probe.
        asset_authorized: MUST be True. Enforced unconditionally.
        extra_flags: Additional nmap flags (validated against blocklist).
        timeout: Max seconds to wait for nmap process.
        force_refresh: Skip cache and run fresh scan.
        bypass_cooldown: Skip cooldown check (for monitor worker only).
    """
    if not asset_authorized:
        log.warning("nmap.rejected_unauthorized", target=target)
        SCAN_REJECTED.labels(scan_type="nmap", reason="unauthorized").inc()
        raise ScanTargetRejected(
            "Nmap enrichment requires asset_authorized=True. "
            "Only verified asset owners may run deep scans."
        )

    resolved = assert_scan_allowed(target, asset_authorized=True)
    ip = str(resolved.ip)

    if not ports:
        return NmapScanResult(ip=ip, error="no_ports_specified")

    try:
        cmd = _build_command(ip, ports, extra_flags)
    except ValueError as exc:
        log.warning("nmap.blocked_flag", target=ip, error=str(exc))
        SCAN_REJECTED.labels(scan_type="nmap", reason="blocked_flag").inc()
        raise ScanTargetRejected(str(exc)) from exc

    if not settings.nmap_enabled:
        log.debug("nmap.disabled", target=ip)
        return NmapScanResult(ip=ip, error="nmap_disabled")

    # Check cooldown (skip for monitor-triggered scans)
    if not bypass_cooldown and await _check_cooldown(ip):
        log.info("nmap.cooldown_active", target=ip)
        NMAP_COOLDOWN_REJECTED.inc()
        return NmapScanResult(ip=ip, error="cooldown_active")

    # Check cache (skip if force_refresh)
    if not force_refresh:
        cached = await _check_cache(ip)
        if cached:
            log.debug("nmap.cache_hit", target=ip)
            return cached

    if not is_nmap_available():
        log.warning("nmap.not_installed", target=ip)
        return NmapScanResult(ip=ip, error="nmap_not_installed")

    # Acquire concurrency semaphore
    sem = _get_semaphore()
    sem_start = time.monotonic()

    SCAN_STARTED.labels(scan_type="nmap").inc()
    log.info("nmap.scan_started", target=ip, ports=ports)

    async with sem:
        sem_wait = time.monotonic() - sem_start
        NMAP_CONCURRENCY_WAITING.observe(sem_wait)
        if sem_wait > 1.0:
            log.info("nmap.semaphore_waited", target=ip, wait_s=round(sem_wait, 2))

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            log.warning("nmap.timeout", target=ip, timeout_s=timeout)
            SCAN_TIMEOUT.labels(scan_type="nmap").inc()
            try:
                proc.kill()
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return NmapScanResult(ip=ip, error="timeout")
        except OSError as exc:
            log.error("nmap.exec_failed", target=ip, error=str(exc))
            SCAN_FAILED.labels(scan_type="nmap", reason="exec_error").inc()
            return NmapScanResult(ip=ip, error=f"exec_failed: {exc}")

        elapsed = time.monotonic() - start
        elapsed_ms = int(elapsed * 1000)
        SCAN_DURATION.labels(scan_type="nmap").observe(elapsed)

        if proc.returncode != 0:
            err_msg = stderr.decode("utf-8", errors="replace").strip()[:500]
            log.warning("nmap.nonzero_exit", target=ip, code=proc.returncode, stderr=err_msg)
            SCAN_FAILED.labels(scan_type="nmap", reason="nonzero_exit").inc()
            return NmapScanResult(ip=ip, error=f"exit_code_{proc.returncode}: {err_msg}", scan_time_ms=elapsed_ms)

        xml_output = stdout.decode("utf-8", errors="replace")
        services = _parse_xml(xml_output)

        SCAN_COMPLETED.labels(scan_type="nmap").inc()
        PORTS_DISCOVERED.labels(scan_type="nmap").observe(len(services))
        log.info("nmap.scan_completed", target=ip, services_found=len(services), elapsed_ms=elapsed_ms)

        result = NmapScanResult(
            ip=ip,
            services=services,
            scan_time_ms=elapsed_ms,
        )

        # Store in cache and set cooldown
        await _store_cache(result)
        await _set_cooldown(ip)

        return result


def enrich_services(
    existing_services: list[dict[str, Any]],
    nmap_results: list[NmapServiceResult],
) -> list[dict[str, Any]]:
    """Merge Nmap fingerprinting data into existing service records.

    Only enriches — never adds new ports or removes existing data.
    Nmap results are additive to the fields: product, version, cpe.
    """
    nmap_by_port: dict[int, NmapServiceResult] = {r.port: r for r in nmap_results}
    enriched: list[dict[str, Any]] = []

    for svc in existing_services:
        port = svc.get("port")
        entry = dict(svc)

        nmap_hit = nmap_by_port.get(port)
        if nmap_hit and nmap_hit.state == "open":
            if nmap_hit.product:
                entry["product"] = nmap_hit.product
            if nmap_hit.version:
                entry["version"] = nmap_hit.version
            if nmap_hit.cpe:
                entry["cpe"] = nmap_hit.cpe
            if nmap_hit.service:
                entry.setdefault("service_name", nmap_hit.service)
            if nmap_hit.extra_info:
                entry["extra_info"] = nmap_hit.extra_info

        enriched.append(entry)

    return enriched
