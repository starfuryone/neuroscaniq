"""Screenshot search and retrieval."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from app.core.deps import get_current_user
from app.models.user import User
from app.schemas.schemas import ScreenshotOut
from app.services.opensearch import get_opensearch
from app.services.storage import storage_service

router = APIRouter(prefix="/screenshots", tags=["screenshots"])


@router.get("", response_model=list[ScreenshotOut])
async def search_screenshots(
    q: str = Query("", description="Optional title/technology free-text query"),
    technology: str | None = Query(None, description="Filter by detected technology"),
    page: int = Query(1, ge=1, le=100),
    page_size: int = Query(24, ge=1, le=96),
    user: User = Depends(get_current_user),
) -> list[ScreenshotOut]:
    """Search the screenshot index. Returns presigned URLs for thumbnails."""
    os_client = await get_opensearch()

    must: list[dict] = []
    if q:
        must.append({"multi_match": {"query": q, "fields": ["title^2", "technology_stack"]}})
    if technology:
        must.append({"term": {"technology_stack": technology.lower()}})
    if not must:
        must.append({"match_all": {}})

    body = {
        "query": {"bool": {"must": must}},
        "from": (page - 1) * page_size,
        "size": page_size,
        "sort": [{"captured_at": {"order": "desc"}}],
    }
    resp = await os_client.search(index="screenshots", body=body)

    out: list[ScreenshotOut] = []
    for h in resp.get("hits", {}).get("hits", []):
        src = h["_source"]
        out.append(
            ScreenshotOut(
                id=h["_id"],
                ip=src.get("ip", ""),
                port=src.get("port", 0),
                url=src.get("url", ""),
                title=src.get("title"),
                captured_at=src.get("captured_at") or datetime.now(timezone.utc),
                technology_stack=src.get("technology_stack", []),
                image_url=storage_service.presigned_url(src["s3_key"]) if src.get("s3_key") else None,
                thumbnail_url=(
                    storage_service.presigned_url(src["thumbnail_s3_key"])
                    if src.get("thumbnail_s3_key")
                    else None
                ),
            )
        )
    return out
