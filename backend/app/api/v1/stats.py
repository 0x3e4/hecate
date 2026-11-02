from fastapi import APIRouter, Depends, Query

from app.services.stats_service import StatsService, get_stats_service

router = APIRouter()


@router.get("/overview")
async def get_overview(service: StatsService = Depends(get_stats_service)) -> dict:
    return await service.get_overview()


@router.get("/today")
async def get_today_summary(
    date: str | None = None,
    tz: str | None = None,
    service: StatsService = Depends(get_stats_service),
) -> dict:
    return await service.get_today_summary(date=date, tz=tz)


@router.get("/attention")
async def get_attention(
    days: int = Query(default=7, ge=1, le=30),
    tz: str | None = None,
    service: StatsService = Depends(get_stats_service),
) -> dict:
    return await service.get_attention(days=days, tz=tz)
