from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.stats_service import (
    StatsService,
    TimelineRangeError,
    TimelineUnavailableError,
    get_stats_service,
)

router = APIRouter()


@router.get("/overview")
async def get_overview(service: StatsService = Depends(get_stats_service)) -> dict:
    return await service.get_overview()


@router.get("/timeline")
async def get_timeline(
    from_: str | None = Query(
        default=None,
        alias="from",
        max_length=40,
        description="ISO 8601 date or datetime; a bare date is local midnight in `tz`. Omitted: the earliest publication.",
    ),
    to: str | None = Query(default=None, max_length=40, description="Exclusive end, ISO 8601. Omitted: now."),
    interval: Literal["auto", "day", "week", "month"] = "auto",
    tz: str | None = Query(default=None, max_length=64, description="IANA zone for the buckets; unknown names fall back to UTC."),
    service: StatsService = Depends(get_stats_service),
) -> dict:
    """Publications per bucket, aligned to the interval in `tz`, with the count published before the window."""
    try:
        return await service.get_timeline(from_=from_, to=to, interval=interval, tz=tz)
    except TimelineRangeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TimelineUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/today")
async def get_today_summary(
    date: str | None = None,
    tz: str | None = None,
    service: StatsService = Depends(get_stats_service),
) -> dict:
    return await service.get_today_summary(date=date, tz=tz)


@router.get("/cert-advisories")
async def get_cert_overview(
    days: int = Query(default=30, ge=1, le=90),
    tz: str | None = None,
    service: StatsService = Depends(get_stats_service),
) -> dict:
    return await service.get_cert_overview(days=days, tz=tz)


@router.get("/attention")
async def get_attention(
    days: int = Query(default=7, ge=1, le=30),
    tz: str | None = None,
    service: StatsService = Depends(get_stats_service),
) -> dict:
    return await service.get_attention(days=days, tz=tz)
