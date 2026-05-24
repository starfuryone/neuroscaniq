"""Scan target authorization.

Workers MUST call `assert_scan_allowed(target)` before any network probe.
This is the single chokepoint that keeps NeuroScanIQ defensive:

  * Private / loopback / link-local ranges are always rejected.
  * Targets must be explicitly allowed via `ALLOWED_SCAN_CIDRS` *or* via
    a verified Asset ownership proof attached to the queued job.
  * Domains are resolved and the resolved IP must satisfy the same rules.

In production you should bind ALLOWED_SCAN_CIDRS narrowly (typically
empty, with monitoring jobs whitelisted ad-hoc via Asset ownership).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from app.config import settings
from app.core.errors import ScanTargetRejected


@dataclass(frozen=True)
class ResolvedTarget:
    target: str            # original
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    via_dns: bool


def _resolve(target: str) -> ResolvedTarget:
    try:
        return ResolvedTarget(target, ipaddress.ip_address(target), via_dns=False)
    except ValueError:
        pass

    try:
        info = socket.getaddrinfo(target, None)
        for fam, _, _, _, sockaddr in info:
            ip_str = sockaddr[0]
            try:
                return ResolvedTarget(target, ipaddress.ip_address(ip_str), via_dns=True)
            except ValueError:
                continue
    except socket.gaierror as e:
        raise ScanTargetRejected(f"Cannot resolve {target}: {e}")

    raise ScanTargetRejected(f"Cannot resolve {target}")


def _in_any(ip: ipaddress._BaseAddress, nets) -> bool:
    return any(ip in n for n in nets)


def _is_non_routable(ip: ipaddress._BaseAddress) -> bool:
    """Check if an IP is in a non-routable range we always block."""
    if ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    if ip.version == 4:
        return _in_any(ip, _ALWAYS_BLOCKED_V4)
    return _in_any(ip, _ALWAYS_BLOCKED_V6)


_ALWAYS_BLOCKED_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_ALWAYS_BLOCKED_V6 = [
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def assert_scan_allowed(target: str, *, asset_authorized: bool = False) -> ResolvedTarget:
    """Raise ScanTargetRejected if `target` may not be probed.

    Args:
        target: IP, hostname, or CIDR root.
        asset_authorized: True when the caller already verified an Asset
            ownership proof covers this target.
    """
    resolved = _resolve(target)
    ip = resolved.ip

    # Always-blocked: RFC 1918, loopback, link-local, multicast
    if _is_non_routable(ip):
        raise ScanTargetRejected(f"{target} resolves to a non-public address ({ip})")

    if _in_any(ip, settings.blocked_networks):
        raise ScanTargetRejected(f"{target} is in a blocked CIDR")

    if asset_authorized:
        return resolved

    if settings.allowed_networks and _in_any(ip, settings.allowed_networks):
        return resolved

    raise ScanTargetRejected(
        f"{target} is not within an allowed scan range. "
        "Register the target as a verified Asset to monitor it."
    )
