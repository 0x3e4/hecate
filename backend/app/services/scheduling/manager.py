from __future__ import annotations

import asyncio

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.nvd_pipeline import NVDPipeline

log = structlog.get_logger()


class SchedulerManager:
    def __init__(self) -> None:
        self.scheduler = AsyncIOScheduler(timezone=settings.scheduler_timezone)
        self._bootstrapped = False
        self._bootstrap_task: asyncio.Task[None] | None = None

    @property
    def bootstrapped(self) -> bool:
        return self._bootstrapped

    async def start(self) -> None:
        if not settings.scheduler_enabled:
            log.info("scheduler.disabled")
            return

        if not self.scheduler.running:
            self._schedule_jobs()
            self.scheduler.start()
            log.info("scheduler.started")
        else:
            log.info("scheduler.already_running")

        if settings.ingestion_bootstrap_on_startup and not self._bootstrapped:
            if self._bootstrap_task is None or self._bootstrap_task.done():
                self._bootstrap_task = asyncio.create_task(
                    self._run_bootstrap_jobs(),
                    name="scheduler-bootstrap",
                )

    def _schedule_jobs(self) -> None:
        self.scheduler.add_job(
            _scheduled_euvd_ingestion,
            trigger=IntervalTrigger(minutes=settings.scheduler_euvd_interval_minutes),
            id="euvd_ingestion",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_cpe_sync,
            trigger=IntervalTrigger(hours=settings.scheduler_cpe_interval_hours),
            id="cpe_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_nvd_sync,
            trigger=IntervalTrigger(hours=settings.scheduler_nvd_interval_hours),
            id="nvd_sync",
            replace_existing=True,
        )

    async def shutdown(self) -> None:
        if self._bootstrap_task is not None and not self._bootstrap_task.done():
            self._bootstrap_task.cancel()
            try:
                await self._bootstrap_task
            except asyncio.CancelledError:
                pass

        if not self.scheduler.running:
            return
        self.scheduler.shutdown(wait=False)
        log.info("scheduler.stopped")

    async def _run_bootstrap_jobs(self) -> None:
        log.info("scheduler.initial_sync_start")
        euvd_task = asyncio.create_task(_initial_euvd_ingestion(), name="bootstrap-euvd")
        cpe_task = asyncio.create_task(_initial_cpe_sync(), name="bootstrap-cpe")
        nvd_task = asyncio.create_task(_initial_nvd_sync(), name="bootstrap-nvd")

        results = await asyncio.gather(euvd_task, cpe_task, nvd_task, return_exceptions=True)
        for label, result in zip(("euvd", "cpe", "nvd"), results, strict=True):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                log.exception(f"scheduler.initial_sync_{label}_failed", error=str(result))
            else:
                log.info(f"scheduler.initial_sync_{label}_completed")

        self._bootstrapped = True
        log.info("scheduler.initial_sync_complete")


_scheduler_manager: SchedulerManager | None = None


def get_scheduler() -> SchedulerManager:
    global _scheduler_manager
    if _scheduler_manager is None:
        _scheduler_manager = SchedulerManager()
    return _scheduler_manager


async def _scheduled_cpe_sync() -> None:
    manager = get_scheduler()
    if settings.ingestion_bootstrap_on_startup and not manager.bootstrapped:
        log.info("scheduler.cpe_sync_skipped_initial_sync_incomplete")
        return
    await _execute_cpe_sync(limit=None, initial_sync=False)


async def _initial_cpe_sync() -> None:
    await _execute_cpe_sync(limit=0, initial_sync=True)


async def _execute_cpe_sync(*, limit: int | None, initial_sync: bool) -> None:
    pipeline = CPEPipeline()
    try:
        result = await pipeline.sync(limit=limit, initial_sync=initial_sync)
        event = "scheduler.cpe_sync_completed" if not initial_sync else "scheduler.cpe_initial_sync_completed"
        log.info(event, **result)
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.cpe_sync_failed" if not initial_sync else "scheduler.cpe_initial_sync_failed"
        log.exception(event, error=str(exc))
    finally:
        await pipeline.close()

async def _scheduled_nvd_sync() -> None:
    manager = get_scheduler()
    if settings.ingestion_bootstrap_on_startup and not manager.bootstrapped:
        log.info("scheduler.nvd_sync_skipped_initial_sync_incomplete")
        return
    await _execute_nvd_sync(initial_sync=False)


async def _initial_nvd_sync() -> None:
    await _execute_nvd_sync(initial_sync=True)


async def _execute_nvd_sync(*, initial_sync: bool) -> None:
    pipeline = NVDPipeline()
    try:
        result = await pipeline.sync(initial_sync=initial_sync)
        event = "scheduler.nvd_sync_completed" if not initial_sync else "scheduler.nvd_initial_sync_completed"
        log.info(event, **result)
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.nvd_sync_failed" if not initial_sync else "scheduler.nvd_initial_sync_failed"
        log.exception(event, error=str(exc))

async def _scheduled_euvd_ingestion() -> None:
    manager = get_scheduler()
    if settings.ingestion_bootstrap_on_startup and not manager.bootstrapped:
        log.info("scheduler.euvd_ingestion_skipped_initial_sync_incomplete")
        return
    await _execute_euvd_ingestion(limit=None, initial_sync=False)


async def _initial_euvd_ingestion() -> None:
    await _execute_euvd_ingestion(limit=0, initial_sync=True)


async def _execute_euvd_ingestion(*, limit: int | None, initial_sync: bool) -> None:
    try:
        result = await run_ingestion(limit=limit, initial_sync=initial_sync)
        event = (
            "scheduler.euvd_ingestion_completed"
            if not initial_sync
            else "scheduler.euvd_initial_sync_completed"
        )
        log.info(event, **result)
    except Exception as exc:  # noqa: BLE001
        event = (
            "scheduler.euvd_ingestion_failed"
            if not initial_sync
            else "scheduler.euvd_initial_sync_failed"
        )
        log.exception(event, error=str(exc))
