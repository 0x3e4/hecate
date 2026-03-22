from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.schemas.changelog import ChangelogResponse
from app.services.changelog_service import ChangelogService, get_changelog_service

router = APIRouter()


@router.get("", response_model=ChangelogResponse)
async def get_changelog(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of entries to return"),
    offset: int = Query(default=0, ge=0, description="Number of entries to skip"),
    from_date: datetime | None = Query(default=None, alias="fromDate", description="Filter: earliest ingested_at (ISO 8601)"),
    to_date: datetime | None = Query(default=None, alias="toDate", description="Filter: latest ingested_at (ISO 8601)"),
    source: str | None = Query(default=None, description="Filter by source / job name (e.g. NVD, EUVD, GHSA)"),
    service: ChangelogService = Depends(get_changelog_service),
) -> ChangelogResponse:
    """
    Retrieve recent vulnerability changes (creations and updates).
    """
    return await service.get_recent_changes(limit=limit, offset=offset, from_date=from_date, to_date=to_date, source=source)
