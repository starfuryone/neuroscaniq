"""Shodan-style query parser.

Translates user queries like:

    apache port:443 country:US org:"Acme Corp" tls.subject_cn:*.example.com

into an OpenSearch query DSL document. The parser is deliberately small
and defensive — unknown filters are dropped, and free text is matched
against banner / title / product fields.

Supported filters (case-insensitive):
    ip            — exact IP
    port          — integer (repeatable)
    service       — keyword in services.product
    asn           — integer
    org           — keyword (asn_org / organization)
    country       — ISO-2 country code
    city          — keyword
    product       — services.product
    version       — services.version
    title         — http.title text
    server        — http.server
    tls.subject_cn, tls.issuer_cn, tls.san — TLS metadata
    tag           — tag keyword (repeatable)
    risk          — low/medium/high/critical
"""

from __future__ import annotations

import re
import shlex
from typing import Any

_FILTER_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_.]*):(.+)$")

_FIELD_MAP = {
    "ip": ("term", "ip"),
    "port": ("term", "ports"),
    "service": ("nested.product", None),
    "product": ("nested.product", None),
    "version": ("nested.version", None),
    "asn": ("term", "asn"),
    "org": ("multi", ["asn_org", "organization"]),
    "country": ("term", "country"),
    "city": ("term", "city"),
    "title": ("match", "http.title"),
    "server": ("term", "http.server"),
    "tls.subject_cn": ("term", "tls.subject_cn"),
    "tls.issuer_cn": ("term", "tls.issuer_cn"),
    "tls.san": ("term", "tls.san"),
    "tag": ("term", "tags"),
    "risk": ("term", "risk_level"),
}


def parse_query(raw: str) -> dict[str, Any]:
    """Return an OpenSearch query body for the given input.

    Empty input becomes match_all (with a reasonable sort by last_seen).
    """
    raw = (raw or "").strip()
    if not raw:
        return {
            "query": {"match_all": {}},
            "sort": [{"last_seen": {"order": "desc"}}],
        }

    must: list[dict[str, Any]] = []
    free_text: list[str] = []

    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()

    for token in tokens:
        m = _FILTER_RE.match(token)
        if not m:
            free_text.append(token)
            continue

        key = m.group(1).lower()
        value = m.group(2).strip('"').strip("'")
        clause = _build_clause(key, value)
        if clause:
            must.append(clause)
        else:
            free_text.append(token)

    if free_text:
        joined = " ".join(free_text)
        must.append(
            {
                "multi_match": {
                    "query": joined,
                    "fields": [
                        "hostname.text^2",
                        "asn_org.text",
                        "organization.text",
                        "http.title^3",
                        "services.banner",
                        "services.title",
                        "services.product.text^2",
                        "tls.subject_cn^2",
                        "tags^2",
                    ],
                    "type": "best_fields",
                    "operator": "and",
                }
            }
        )

    return {
        "query": {"bool": {"must": must or [{"match_all": {}}]}},
        "sort": [
            {"_score": {"order": "desc"}},
            {"last_seen": {"order": "desc"}},
        ],
    }


def _build_clause(key: str, value: str) -> dict[str, Any] | None:
    spec = _FIELD_MAP.get(key)
    if not spec:
        return None
    kind, field = spec

    if kind == "term":
        # Numbers stay numeric where useful
        if value.isdigit():
            return {"term": {field: int(value)}}
        return {"term": {field: value.lower() if field == "country" else value}}

    if kind == "match":
        return {"match": {field: value}}

    if kind == "multi":
        return {
            "multi_match": {"query": value, "fields": field, "operator": "and"}
        }

    if kind == "nested.product":
        return {
            "nested": {
                "path": "services",
                "query": {
                    "multi_match": {
                        "query": value,
                        "fields": ["services.product", "services.product.text"],
                    }
                },
            }
        }

    if kind == "nested.version":
        return {
            "nested": {
                "path": "services",
                "query": {"term": {"services.version": value}},
            }
        }

    return None


# ---------- Filter aggregations for sidebar ----------
def filter_aggs() -> dict[str, Any]:
    """Aggregation block for the search filter sidebar."""
    return {
        "country": {"terms": {"field": "country", "size": 20}},
        "asn_org": {"terms": {"field": "asn_org", "size": 20}},
        "port": {"terms": {"field": "ports", "size": 20}},
        "risk_level": {"terms": {"field": "risk_level", "size": 5}},
        "tags": {"terms": {"field": "tags", "size": 20}},
    }
