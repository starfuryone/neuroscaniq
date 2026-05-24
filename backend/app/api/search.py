"""Host search endpoint.

Translates a Shodan-style query string into OpenSearch DSL, enforces the
caller's monthly search quota, and returns paginated hits along with facets
suitable for a sidebar UI.

A normal anonymous-class consumer can search; running an *active* scan against
a target still goes through `monitor` endpoints + `scan_guard`, so this
endpoint never initiates network probing.
"""

from __future__ import annotations

import time

import structlog
from fastapi import APIRouter, Depends, Query

from app.core.deps import get_current_user, get_subscription
from app.core.errors import RateLimited
from app.models.billing import Subscription
from app.models.user import User
from app.schemas.schemas import SearchFacet, SearchHit, SearchResponse
from app.services.opensearch import get_opensearch
from app.services.query_parser import filter_aggs, parse_query
from app.services.redis import get_redis

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/search", tags=["search"])


SEARCH_QUOTA_KEY = "quota:search:{user_id}:{period}"
MAX_PAGE_SIZE = 100


async def _check_and_increment_quota(user_id: str, monthly_quota: int) -> None:
    """Atomically increment month-bucketed counter and enforce quota."""
    redis = await get_redis()
    period = time.strftime("%Y-%m", time.gmtime())
    key = SEARCH_QUOTA_KEY.format(user_id=user_id, period=period)
    # Pipeline: increment, set 35-day expiry, get value
    pipe = redis.pipeline()
    pipe.incr(key)
    pipe.expire(key, 35 * 86400)
    used, _ = await pipe.execute()
    if used > monthly_quota:
        raise RateLimited(
            f"Monthly search quota of {monthly_quota} reached. "
            "Upgrade your plan or wait until next billing cycle.",
            details={"quota": monthly_quota, "used": int(used), "period": period},
        )


@router.get("", response_model=SearchResponse)
async def search_hosts(
    q: str = Query("", description="Shodan-style query. e.g. `port:443 country:US tls.subject_cn:example.com`"),
    page: int = Query(1, ge=1, le=100),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    sort: str = Query("risk", regex="^(risk|recent|relevance)$"),
    user: User = Depends(get_current_user),
    subscription: Subscription = Depends(get_subscription),
) -> SearchResponse:
    """Execute a host search across the OpenSearch index."""
    await _check_and_increment_quota(str(user.id), subscription.monthly_search_quota)

    os_client = await get_opensearch()
    dsl = parse_query(q)

    sort_clause: list[dict[str, object]]
    if sort == "risk":
        sort_clause = [{"risk_score": {"order": "desc"}}, {"last_seen": {"order": "desc"}}]
    elif sort == "recent":
        sort_clause = [{"last_seen": {"order": "desc"}}]
    else:
        sort_clause = ["_score"]

    body: dict[str, object] = {
        "query": dsl,
        "from": (page - 1) * page_size,
        "size": page_size,
        "sort": sort_clause,
        "aggs": filter_aggs(),
        "track_total_hits": True,
    }

    started = time.perf_counter()
    resp = await os_client.search(index="hosts", body=body)
    took_ms = int((time.perf_counter() - started) * 1000)

    hits_raw = resp.get("hits", {}).get("hits", [])
    total = resp.get("hits", {}).get("total", {}).get("value", 0)

    hits: list[SearchHit] = []
    for h in hits_raw:
        src = h.get("_source", {})
        loc = src.get("location") or {}
        hits.append(
            SearchHit(
                ip=src.get("ip", ""),
                hostname=src.get("hostname"),
                country=src.get("country"),
                city=src.get("city"),
                asn=src.get("asn"),
                asn_org=src.get("asn_org"),
                ports=src.get("ports", []),
                services=src.get("services", []),
                risk_score=float(src.get("risk_score", 0.0)),
                risk_level=src.get("risk_level", "low"),
                tags=src.get("tags", []),
                last_seen=src.get("last_seen"),
                lat=loc.get("lat"),
                lon=loc.get("lon"),
            )
        )

    aggs = resp.get("aggregations", {})
    facets: list[SearchFacet] = []
    for name, container in aggs.items():
        buckets = container.get("buckets", [])
        facets.append(
            SearchFacet(
                name=name,
                buckets=[{"key": str(b["key"]), "count": int(b["doc_count"])} for b in buckets],
            )
        )

    return SearchResponse(
        total=int(total),
        page=page,
        page_size=page_size,
        took_ms=took_ms,
        hits=hits,
        facets=facets,
        query=q,
    )
