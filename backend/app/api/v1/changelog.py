from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.schemas.changelog import ChangelogResponse
from app.services.changelog_service import ChangelogService, get_changelog_service

router = APIRouter()


@router.get("", response_model=ChangelogResponse)
async def get_changelog(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of entries to return"),
    offset: int = Query(default=0, ge=0, description="Number of entries to skip"),
    service: ChangelogService = Depends(get_changelog_service),
) -> ChangelogResponse:
    """
    Retrieve recent vulnerability changes (creations and updates).
    """
    return await service.get_recent_changes(limit=limit, offset=offset)
