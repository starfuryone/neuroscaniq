"""OpenSearch client and index management.

We maintain two indices:
  * `hosts`        — searchable host snapshots (most recent state)
  * `screenshots`  — screenshot metadata for the Images browser

Schemas are defined here as Python dicts; on startup we `ensure_indices()`
which creates indices that don't exist but never overwrites mappings.
Schema changes are managed via versioned aliases (`hosts_v1` -> `hosts`).
"""

from __future__ import annotations

from typing import Any

import structlog
from opensearchpy import AsyncOpenSearch, exceptions as os_exc

from app.config import settings

log = structlog.get_logger(__name__)


HOSTS_MAPPING: dict[str, Any] = {
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "lowercase_keyword": {
                    "type": "custom",
                    "tokenizer": "keyword",
                    "filter": ["lowercase"],
                }
            }
        },
    },
    "mappings": {
        "properties": {
            "ip": {"type": "ip"},
            "hostname": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "country": {"type": "keyword"},
            "city": {"type": "keyword"},
            "location": {"type": "geo_point"},
            "asn": {"type": "long"},
            "asn_org": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "organization": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "ports": {"type": "integer"},
            "services": {
                "type": "nested",
                "properties": {
                    "port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "product": {"type": "keyword", "fields": {"text": {"type": "text"}}},
                    "version": {"type": "keyword"},
                    "title": {"type": "text"},
                    "server": {"type": "keyword"},
                    "banner": {"type": "text"},
                },
            },
            "tls": {
                "properties": {
                    "subject_cn": {"type": "keyword"},
                    "issuer_cn": {"type": "keyword"},
                    "san": {"type": "keyword"},
                    "not_before": {"type": "date"},
                    "not_after": {"type": "date"},
                    "fingerprint_sha256": {"type": "keyword"},
                }
            },
            "http": {
                "properties": {
                    "title": {"type": "text"},
                    "server": {"type": "keyword"},
                    "status": {"type": "integer"},
                    "headers": {"type": "object", "enabled": False},
                }
            },
            "tags": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "risk_level": {"type": "keyword"},
            "last_seen": {"type": "date"},
            "first_seen": {"type": "date"},
        }
    },
}

SCREENSHOTS_MAPPING: dict[str, Any] = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "host_ip": {"type": "ip"},
            "port": {"type": "integer"},
            "url": {"type": "keyword"},
            "title": {"type": "text"},
            "country": {"type": "keyword"},
            "technologies": {"type": "keyword"},
            "captured_at": {"type": "date"},
            "thumbnail_url": {"type": "keyword"},
            "screenshot_url": {"type": "keyword"},
            "sha256": {"type": "keyword"},
        }
    },
}


class OpenSearchClient:
    def __init__(self):
        self.client = AsyncOpenSearch(
            hosts=[settings.opensearch_url],
            http_auth=(settings.opensearch_user, settings.opensearch_password)
            if settings.opensearch_user
            else None,
            use_ssl=settings.opensearch_url.startswith("https"),
            verify_certs=False,
            timeout=30,
        )

    async def close(self) -> None:
        await self.client.close()

    async def ensure_indices(self) -> None:
        for name, mapping in [
            (settings.opensearch_index_hosts, HOSTS_MAPPING),
            (settings.opensearch_index_screenshots, SCREENSHOTS_MAPPING),
        ]:
            try:
                exists = await self.client.indices.exists(index=name)
                if not exists:
                    await self.client.indices.create(index=name, body=mapping)
                    log.info("opensearch_index_created", index=name)
            except os_exc.OpenSearchException as e:
                log.warning("opensearch_ensure_failed", index=name, error=str(e))

    # ---------- Hosts ----------
    async def index_host(self, doc: dict[str, Any]) -> None:
        await self.client.index(
            index=settings.opensearch_index_hosts,
            id=doc["ip"],
            body=doc,
            refresh=False,
        )

    async def search_hosts(self, query: dict[str, Any], *, size: int = 25, from_: int = 0):
        return await self.client.search(
            index=settings.opensearch_index_hosts,
            body=query,
            size=size,
            from_=from_,
        )

    async def get_host(self, ip: str) -> dict[str, Any] | None:
        try:
            doc = await self.client.get(index=settings.opensearch_index_hosts, id=ip)
            return doc["_source"]
        except os_exc.NotFoundError:
            return None

    # ---------- Screenshots ----------
    async def index_screenshot(self, doc: dict[str, Any]) -> None:
        await self.client.index(
            index=settings.opensearch_index_screenshots,
            body=doc,
            refresh=False,
        )

    async def search_screenshots(self, query: dict[str, Any], *, size: int = 24, from_: int = 0):
        return await self.client.search(
            index=settings.opensearch_index_screenshots,
            body=query,
            size=size,
            from_=from_,
        )


opensearch_client = OpenSearchClient()
