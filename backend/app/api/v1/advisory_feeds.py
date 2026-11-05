"""
Advisory feeds added on System -> Data. Writes take the admin gate at include time;
the list is public like the other lists, so URLs come back with credentials masked.
"""
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.schemas.advisory_feed import (
    AdvisoryFeedCreateRequest,
    AdvisoryFeedListResponse,
    AdvisoryFeedResponse,
    AdvisoryFeedUpdateRequest,
)
from app.services.advisory_feed_service import (
    AdvisoryFeedService,
    FeedConflictError,
    FeedNotFoundError,
    get_advisory_feed_service,
)
from app.services.audit_service import AuditService, get_audit_service

router = APIRouter()


def _audit_result(feed: AdvisoryFeedResponse) -> dict:
    return {"name": feed.name, "url": feed.url, "kind": feed.kind, "enabled": feed.enabled}


@router.get("", response_model=AdvisoryFeedListResponse)
async def list_advisory_feeds(
    service: AdvisoryFeedService = Depends(get_advisory_feed_service),
) -> AdvisoryFeedListResponse:
    return AdvisoryFeedListResponse(items=await service.list_feeds(), sync_enabled=settings.cert_feeds_enabled)


@router.post("", response_model=AdvisoryFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_advisory_feed(
    payload: AdvisoryFeedCreateRequest,
    service: AdvisoryFeedService = Depends(get_advisory_feed_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> AdvisoryFeedResponse:
    try:
        created = await service.create_feed(payload)
    except FeedConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await audit_service.record_event(
        "advisory_feed_added",
        metadata={"label": "Advisory feed added", "feedName": created.name},
        result=_audit_result(created),
    )
    return created


@router.put("/{feed_id}", response_model=AdvisoryFeedResponse)
async def update_advisory_feed(
    feed_id: str,
    payload: AdvisoryFeedUpdateRequest,
    service: AdvisoryFeedService = Depends(get_advisory_feed_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> AdvisoryFeedResponse:
    try:
        updated = await service.update_feed(feed_id, payload)
    except FeedNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Advisory feed not found") from exc
    except FeedConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await audit_service.record_event(
        "advisory_feed_updated",
        metadata={"label": "Advisory feed updated", "feedName": updated.name},
        result=_audit_result(updated),
    )
    return updated


@router.delete("/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_advisory_feed(
    feed_id: str,
    service: AdvisoryFeedService = Depends(get_advisory_feed_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    try:
        deleted = await service.delete_feed(feed_id)
    except FeedNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Advisory feed not found") from exc
    await audit_service.record_event(
        "advisory_feed_removed",
        metadata={"label": "Advisory feed removed", "feedName": deleted.name},
        result=_audit_result(deleted),
    )
