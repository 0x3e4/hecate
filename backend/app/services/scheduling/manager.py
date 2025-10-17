from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.pipeline import IngestionPipeline, run_ingestion

log = structlog.get_logger()


class SchedulerManager:
    def __init__(self) -> None:
        self.scheduler = AsyncIOScheduler(timezone=settings.scheduler_timezone)

    def start(self) -> None:
        if not settings.scheduler_enabled:
            log.info("scheduler.disabled")
            return

        self.scheduler.add_job(
            lambda: asyncio.create_task(run_ingestion()),
            trigger=IntervalTrigger(minutes=settings.scheduler_euvd_interval_minutes),
            id="euvd_ingestion",
            replace_existing=True,
        )

        self.scheduler.add_job(
            lambda: asyncio.create_task(_run_cpe_sync()),
            trigger=IntervalTrigger(hours=settings.scheduler_cpe_interval_hours),
            id="cpe_sync",
            replace_existing=True,
        )

        self.scheduler.start()
        log.info("scheduler.started")

    def shutdown(self) -> None:
        if not self.scheduler.running:
            return
        self.scheduler.shutdown(wait=False)
        log.info("scheduler.stopped")


_scheduler_manager: SchedulerManager | None = None


def get_scheduler() -> SchedulerManager:
    global _scheduler_manager
    if _scheduler_manager is None:
        _scheduler_manager = SchedulerManager()
    return _scheduler_manager


async def _run_cpe_sync() -> None:
    pipeline = CPEPipeline()
    try:
        result = await pipeline.sync()
        log.info("scheduler.cpe_sync_completed", **result)
    except Exception as exc:  # noqa: BLE001
        log.exception("scheduler.cpe_sync_failed", error=str(exc))
    finally:
        await pipeline.close()
