from __future__ import annotations

import asyncio
from typing import Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.kev_pipeline import KevPipeline
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.ingestion.job_tracker import JobTracker
from app.services.cwe_service import get_cwe_service
from app.repositories.ingestion_state_repository import IngestionStateRepository

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
            trigger=IntervalTrigger(minutes=settings.scheduler_cpe_interval_minutes),
            id="cpe_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_nvd_sync,
            trigger=IntervalTrigger(minutes=settings.scheduler_nvd_interval_minutes),
            id="nvd_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_kev_sync,
            trigger=IntervalTrigger(minutes=settings.scheduler_kev_interval_minutes),
            id="kev_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_cwe_sync,
            trigger=IntervalTrigger(days=settings.scheduler_cwe_interval_days),
            id="cwe_sync",
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
        job_configs = (
            ("euvd", "euvd_initial_sync", _initial_euvd_ingestion, "bootstrap-euvd"),
            ("cpe", "cpe_initial_sync", _initial_cpe_sync, "bootstrap-cpe"),
            ("nvd", "nvd_initial_sync", _initial_nvd_sync, "bootstrap-nvd"),
            ("kev", "kev_initial_sync", _initial_kev_sync, "bootstrap-kev"),
            ("cwe", "cwe_initial_sync", _initial_cwe_sync, "bootstrap-cwe"),
        )

        tasks: list[tuple[str, asyncio.Task[None]]] = []
        for label, job_name, job_fn, task_name in job_configs:
            completed = await _initial_sync_already_completed(job_name)
            if completed:
                log.info(f"scheduler.initial_sync_{label}_already_completed")
                continue
            tasks.append((label, asyncio.create_task(job_fn(), name=task_name)))

        if not tasks:
            log.info("scheduler.initial_sync_already_completed")
            self._bootstrapped = True
            return

        results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
        for (label, _), result in zip(tasks, results, strict=True):
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
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("cpe_initial_sync")
        if not completed:
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
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("nvd_initial_sync")
        if not completed:
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


async def _scheduled_kev_sync() -> None:
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("kev_initial_sync")
        if not completed:
            log.info("scheduler.kev_sync_skipped_initial_sync_incomplete")
            return
    await _execute_kev_sync(initial_sync=False)


async def _initial_kev_sync() -> None:
    await _execute_kev_sync(initial_sync=True)


async def _execute_kev_sync(*, initial_sync: bool) -> None:
    pipeline = KevPipeline()
    try:
        result = await pipeline.sync(initial_sync=initial_sync)
        event = "scheduler.kev_sync_completed" if not initial_sync else "scheduler.kev_initial_sync_completed"
        log.info(event, **result)
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.kev_sync_failed" if not initial_sync else "scheduler.kev_initial_sync_failed"
        log.exception(event, error=str(exc))

async def _scheduled_euvd_ingestion() -> None:
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("euvd_initial_sync")
        if not completed:
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


async def _initial_sync_already_completed(job_name: str) -> bool:
    """Return True if the given initial sync job finished successfully before."""

    try:
        state_repo = await IngestionStateRepository.create()
        state: dict[str, Any] | None = await state_repo.get_state(f"job:{job_name}")
    except Exception as exc:  # noqa: BLE001 - bootstrap should continue even if lookup fails
        log.warning(
            "scheduler.initial_sync_state_check_failed",
            job=job_name,
            error=str(exc),
        )
        return False

    if not state:
        return False
    return state.get("status") == "completed"


async def _initial_cwe_sync() -> None:
    """Initial CWE cache prefetch on startup."""
    await _execute_cwe_sync(initial_sync=True)


async def _scheduled_cwe_sync() -> None:
    """Scheduled CWE cache refresh job (runs weekly)."""
    await _execute_cwe_sync(initial_sync=False)


async def _execute_cwe_sync(*, initial_sync: bool) -> None:
    """Execute CWE cache refresh with job tracking."""
    state_repository = await IngestionStateRepository.create()
    tracker = JobTracker(state_repository)

    job_name = "cwe_initial_sync" if initial_sync else "cwe_sync"
    label = "CWE Initial Cache Prefetch" if initial_sync else "CWE Cache Refresh"

    ctx = await tracker.start(
        job_name,
        label=label,
        initial_sync=initial_sync,
    )

    try:
        log.info("scheduler.cwe_sync_started", initial_sync=initial_sync)
        cwe_service = get_cwe_service()

        # Clear in-memory cache
        cwe_service.clear_cache()

        # Sync ALL CWEs from MITRE API
        stats = await cwe_service.sync_all_cwes()

        # Only delete old entries if sync was successful (fetched > 0)
        deleted = 0
        if stats["fetched"] > 0:
            # Delete old MongoDB entries (older than 7 days)
            deleted = await cwe_service.clear_old_entries()
        else:
            log.warning("scheduler.cwe_sync_no_data_fetched",
                       message="Skipping deletion of old entries as no new data was fetched")

        result = {
            "fetched": stats["fetched"],
            "inserted": stats["inserted"],
            "updated": stats["updated"],
            "unchanged": stats["unchanged"],
            "failed": stats["failed"],
            "deleted_old": deleted,
            "initial_sync": initial_sync,
        }

        await tracker.finish(ctx, **result)
        log.info("scheduler.cwe_sync_completed", **result)
    except Exception as exc:  # noqa: BLE001
        error_msg = str(exc)
        await tracker.fail(ctx, error_msg)
        log.exception("scheduler.cwe_sync_failed", error=error_msg, initial_sync=initial_sync)
