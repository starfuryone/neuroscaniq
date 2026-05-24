"""Defensive Nmap integration for service/version enrichment.

This module wraps Nmap as an optional enrichment engine that runs ONLY
against verified, authorized assets. It is strictly constrained:

  * Requires asset_authorized=True — no exceptions.
  * Enforces the same scan_guard authorization as the rest of the platform.
  * Blocks dangerous flags (OS fingerprinting, NSE scripts, spoofing, etc.)
  * Only performs TCP SYN + service/version detection with conservative timing.
  * Returns structured, typed results for merging into existing service records.

This is NOT a general-purpose scanner. It enriches already-discovered open
ports with product/version/CPE data for defensive asset management.
"""

from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.config import settings
from app.core.errors import ScanTargetRejected
from app.core.scan_guard import assert_scan_allowed

log = structlog.get_logger(__name__)

NMAP_TIMEOUT_SECONDS = 120

BLOCKED_FLAGS: frozenset[str] = frozenset({
    "-A",
    "-O",
    "--script",
    "-iL",
    "-D",
    "-S",
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
    "-sS",
    "-sV",
    "-T3",
    "--max-rate", "100",
    "--host-timeout", "90s",
    "--open",
    "-oX", "-",
]


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


async def run_nmap_scan(
    target: str,
    ports: list[int],
    *,
    asset_authorized: bool,
    extra_flags: list[str] | None = None,
    timeout: int = NMAP_TIMEOUT_SECONDS,
) -> NmapScanResult:
    """Run an Nmap service/version scan against an authorized target.

    This function enforces all security constraints before executing:
      1. asset_authorized MUST be True
      2. Target must pass scan_guard checks
      3. No blocked flags may be present
      4. Nmap must be installed
    """
    if not asset_authorized:
        log.warning("nmap.rejected_unauthorized", target=target)
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
        raise ScanTargetRejected(str(exc)) from exc

    if not settings.nmap_enabled:
        log.debug("nmap.disabled", target=ip)
        return NmapScanResult(ip=ip, error="nmap_disabled")

    if not is_nmap_available():
        log.warning("nmap.not_installed", target=ip)
        return NmapScanResult(ip=ip, error="nmap_not_installed")

    log.info("nmap.scan_started", target=ip, ports=ports, cmd=" ".join(cmd))

    import time
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
        try:
            proc.kill()
            await proc.wait()
        except Exception:  # noqa: BLE001
            pass
        return NmapScanResult(ip=ip, error="timeout")
    except OSError as exc:
        log.error("nmap.exec_failed", target=ip, error=str(exc))
        return NmapScanResult(ip=ip, error=f"exec_failed: {exc}")

    elapsed_ms = int((time.monotonic() - start) * 1000)

    if proc.returncode != 0:
        err_msg = stderr.decode("utf-8", errors="replace").strip()[:500]
        log.warning("nmap.nonzero_exit", target=ip, code=proc.returncode, stderr=err_msg)
        return NmapScanResult(ip=ip, error=f"exit_code_{proc.returncode}: {err_msg}", scan_time_ms=elapsed_ms)

    xml_output = stdout.decode("utf-8", errors="replace")
    services = _parse_xml(xml_output)

    log.info("nmap.scan_completed", target=ip, services_found=len(services), elapsed_ms=elapsed_ms)

    return NmapScanResult(
        ip=ip,
        services=services,
        scan_time_ms=elapsed_ms,
    )


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
