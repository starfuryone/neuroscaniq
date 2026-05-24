"""Risk scoring.

Deterministic, explainable scoring that pairs well with the AI layer.
The scorer takes a dict-shaped Host snapshot (the same shape stored in
OpenSearch) and returns (score: 0-100, level: low|medium|high|critical,
factors: dict).

We deliberately keep this transparent — the goal is operational risk
prioritization, not an opaque model. The AI layer can refine these
results downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# (port, label, weight) for direct port-based signals
SENSITIVE_PORTS: list[tuple[int, str, int]] = [
    (21, "ftp_exposed", 10),
    (23, "telnet_exposed", 25),
    (135, "smb_rpc_exposed", 15),
    (445, "smb_exposed", 25),
    (1433, "mssql_exposed", 25),
    (3306, "mysql_exposed", 25),
    (3389, "rdp_exposed", 30),
    (5432, "postgres_exposed", 25),
    (5900, "vnc_exposed", 25),
    (6379, "redis_exposed", 30),
    (9200, "elasticsearch_exposed", 30),
    (11211, "memcached_exposed", 20),
    (27017, "mongodb_exposed", 50),
]

ADMIN_KEYWORDS = ("admin", "phpmyadmin", "cpanel", "router login", "webmin", "management")


@dataclass
class RiskResult:
    score: float       # 0-100
    level: str         # low / medium / high / critical
    factors: dict[str, Any]


def score_host(snapshot: dict[str, Any]) -> RiskResult:
    """Score a host snapshot."""
    factors: dict[str, Any] = {}
    score = 0.0

    ports = set(snapshot.get("ports") or [])
    services = snapshot.get("services") or []
    http_title = (snapshot.get("http") or {}).get("title", "") or ""
    tls = snapshot.get("tls") or {}
    tags = set(snapshot.get("tags") or [])

    # 1) Sensitive port exposure
    for port, label, weight in SENSITIVE_PORTS:
        if port in ports:
            score += weight
            factors[label] = weight

    # 2) Admin / login panel keywords in HTTP title
    lower_title = http_title.lower()
    for kw in ADMIN_KEYWORDS:
        if kw in lower_title:
            score += 8
            factors["admin_panel_in_title"] = lower_title[:120]
            break

    # 3) Plain HTTP on non-standard ports (no TLS at all)
    if not tls and 80 in ports and 443 not in ports:
        score += 4
        factors["plain_http_only"] = True

    # 4) Expired or expiring TLS
    not_after = tls.get("not_after")
    if not_after:
        # not_after is ISO 8601 in our index
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left < 0:
                score += 12
                factors["tls_expired"] = days_left
            elif days_left < 14:
                score += 6
                factors["tls_expiring_soon"] = days_left
        except ValueError:
            pass

    # 5) Outdated software (very rough heuristic: presence of version digits below known floors)
    for svc in services:
        prod = (svc.get("product") or "").lower()
        ver = (svc.get("version") or "").strip()
        if prod and ver:
            try:
                major = int(ver.split(".")[0])
            except ValueError:
                continue
            if prod == "openssh" and major < 8:
                score += 5
                factors.setdefault("outdated_software", []).append(f"openssh {ver}")
            if prod == "apache" and major < 2:
                score += 8
                factors.setdefault("outdated_software", []).append(f"apache {ver}")
            if prod == "nginx" and major < 1:
                score += 6
                factors.setdefault("outdated_software", []).append(f"nginx {ver}")

    # 6) Known-bad tags from prior analysis
    for bad in ("known_botnet_c2", "exposed_secret", "default_credentials_likely"):
        if bad in tags:
            score += 20
            factors[bad] = True

    # 7) Database without authentication required (banner indicates)
    for svc in services:
        banner = (svc.get("banner") or "").lower()
        if "no auth" in banner or "no password" in banner:
            score += 25
            factors["unauthenticated_service"] = svc.get("product")

    score = min(100.0, score)
    return RiskResult(score=score, level=_level_for(score), factors=factors)


def _level_for(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


class RiskScorer:
    def score(
        self,
        *,
        ports: list[int],
        services: list[dict[str, Any]],
        tls: dict[str, Any] | None,
        http: dict[str, Any] | None,
        tags: list[str],
    ) -> RiskResult:
        snapshot: dict[str, Any] = {
            "ports": ports,
            "services": services,
            "tls": tls,
            "http": http,
            "tags": tags,
        }
        return score_host(snapshot)


risk_scorer = RiskScorer()
