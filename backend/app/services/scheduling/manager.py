from __future__ import annotations

import asyncio
from typing import Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.services.ingestion.circl_pipeline import CirclPipeline
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.ghsa_pipeline import GhsaPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.kev_pipeline import KevPipeline
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.ingestion.job_tracker import JobTracker
from app.services.capec_service import get_capec_service
from app.services.cwe_service import get_cwe_service
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.services.event_bus import publish_new_vulnerabilities
from app.services.notification_service import get_notification_service
from app.services.scan_service import get_scan_service

log = structlog.get_logger()


async def _notify_sync_failed(job_name: str, error: str) -> None:
    """Fire-and-forget notification for sync failures."""
    try:
        notifier = get_notification_service()
        await notifier.notify_sync_failed(job_name=job_name, error=error)
    except Exception:
        pass


async def _notify_new_vulnerabilities(job_name: str, inserted: int) -> None:
    """Fire-and-forget notification when new vulnerabilities are ingested."""
    if inserted <= 0:
        return
    # Publish SSE event so dashboards / lists refresh in real-time
    publish_new_vulnerabilities(source=job_name, count=inserted)
    try:
        notifier = get_notification_service()
        await notifier.notify_new_vulnerabilities_event(source=job_name, inserted=inserted)
    except Exception:
        pass


async def _evaluate_watch_rules_after_pipeline(source: str) -> None:
    """Evaluate watch rules after any pipeline that may have changed vulnerability data.

    Unlike _notify_new_vulnerabilities, this always runs regardless of insert/update
    counts, because enrichment pipelines (CIRCL, KEV) modify existing documents in
    ways that can match watch rules.
    """
    try:
        notifier = get_notification_service()
        await notifier.evaluate_watch_rules()
    except Exception:
        log.debug("scheduler.watch_rule_evaluation_failed", source=source)


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

        # Bootstrap auto-scan after a short delay so services are ready
        if settings.sca_enabled and settings.vite_sca_auto_scan_enabled:
            asyncio.create_task(
                _delayed_auto_scan_bootstrap(),
                name="bootstrap-auto-scan",
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

        self.scheduler.add_job(
            _scheduled_capec_sync,
            trigger=IntervalTrigger(days=settings.scheduler_capec_interval_days),
            id="capec_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_circl_sync,
            trigger=IntervalTrigger(minutes=settings.scheduler_circl_interval_minutes),
            id="circl_sync",
            replace_existing=True,
        )

        self.scheduler.add_job(
            _scheduled_ghsa_sync,
            trigger=IntervalTrigger(minutes=settings.scheduler_ghsa_interval_minutes),
            id="ghsa_sync",
            replace_existing=True,
        )

        # EUVD weekly full sync
        if settings.scheduler_euvd_full_sync_enabled:
            self.scheduler.add_job(
                _scheduled_euvd_full_sync,
                trigger=CronTrigger(
                    day_of_week=settings.scheduler_euvd_full_sync_cron_day_of_week,
                    hour=settings.scheduler_euvd_full_sync_cron_hour,
                    minute=0,
                    timezone=settings.scheduler_timezone,
                ),
                id="euvd_full_sync",
                replace_existing=True,
            )

        # SCA auto-scan
        if settings.sca_enabled and settings.vite_sca_auto_scan_enabled:
            self.scheduler.add_job(
                _scheduled_auto_scans,
                trigger=IntervalTrigger(minutes=settings.sca_auto_scan_interval_minutes),
                id="sca_auto_scan",
                replace_existing=True,
            )

        # NVD weekly full sync
        if settings.scheduler_nvd_full_sync_enabled:
            self.scheduler.add_job(
                _scheduled_nvd_full_sync,
                trigger=CronTrigger(
                    day_of_week=settings.scheduler_nvd_full_sync_cron_day_of_week,
                    hour=settings.scheduler_nvd_full_sync_cron_hour,
                    minute=0,
                    timezone=settings.scheduler_timezone,
                ),
                id="nvd_full_sync",
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
            ("capec", "capec_initial_sync", _initial_capec_sync, "bootstrap-capec"),
            ("ghsa", "ghsa_initial_sync", _initial_ghsa_sync, "bootstrap-ghsa"),
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
        await _notify_sync_failed("cpe_sync", str(exc))
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
        await _notify_new_vulnerabilities("NVD", result.get("ingested", 0))
        await _evaluate_watch_rules_after_pipeline("NVD")
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.nvd_sync_failed" if not initial_sync else "scheduler.nvd_initial_sync_failed"
        log.exception(event, error=str(exc))
        await _notify_sync_failed("nvd_sync", str(exc))


async def _scheduled_nvd_full_sync() -> None:
    """Weekly NVD full sync for data verification and integrity."""
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("nvd_initial_sync")
        if not completed:
            log.info("scheduler.nvd_full_sync_skipped_initial_sync_incomplete")
            return

    log.info("scheduler.nvd_full_sync_starting")
    await _execute_nvd_sync(initial_sync=True)


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
        await _evaluate_watch_rules_after_pipeline("KEV")
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.kev_sync_failed" if not initial_sync else "scheduler.kev_initial_sync_failed"
        log.exception(event, error=str(exc))
        await _notify_sync_failed("kev_sync", str(exc))

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
        await _notify_new_vulnerabilities("EUVD", result.get("ingested", 0))
        await _evaluate_watch_rules_after_pipeline("EUVD")
    except Exception as exc:  # noqa: BLE001
        event = (
            "scheduler.euvd_ingestion_failed"
            if not initial_sync
            else "scheduler.euvd_initial_sync_failed"
        )
        log.exception(event, error=str(exc))
        await _notify_sync_failed("euvd_ingestion", str(exc))


async def _scheduled_euvd_full_sync() -> None:
    """Weekly EUVD full sync for data verification and integrity."""
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("euvd_initial_sync")
        if not completed:
            log.info("scheduler.euvd_full_sync_skipped_initial_sync_incomplete")
            return

    log.info("scheduler.euvd_full_sync_starting")
    await _execute_euvd_ingestion(limit=None, initial_sync=True)


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
        await _notify_sync_failed("cwe_sync", error_msg)


async def _initial_capec_sync() -> None:
    """Initial CAPEC cache prefetch on startup."""
    await _execute_capec_sync(initial_sync=True)


async def _scheduled_capec_sync() -> None:
    """Scheduled CAPEC cache refresh job (runs weekly)."""
    await _execute_capec_sync(initial_sync=False)


async def _execute_capec_sync(*, initial_sync: bool) -> None:
    """Execute CAPEC cache refresh with job tracking."""
    state_repository = await IngestionStateRepository.create()
    tracker = JobTracker(state_repository)

    job_name = "capec_initial_sync" if initial_sync else "capec_sync"
    label = "CAPEC Initial Cache Prefetch" if initial_sync else "CAPEC Cache Refresh"

    ctx = await tracker.start(
        job_name,
        label=label,
        initial_sync=initial_sync,
    )

    try:
        log.info("scheduler.capec_sync_started", initial_sync=initial_sync)
        capec_service = get_capec_service()

        capec_service.clear_cache()

        stats = await capec_service.sync_all_capecs()

        deleted = 0
        if stats["fetched"] > 0:
            deleted = await capec_service.clear_old_entries()
        else:
            log.warning(
                "scheduler.capec_sync_no_data_fetched",
                message="Skipping deletion of old entries as no new data was fetched",
            )

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
        log.info("scheduler.capec_sync_completed", **result)
    except Exception as exc:  # noqa: BLE001
        error_msg = str(exc)
        await tracker.fail(ctx, error_msg)
        log.exception("scheduler.capec_sync_failed", error=error_msg, initial_sync=initial_sync)
        await _notify_sync_failed("capec_sync", error_msg)


async def _scheduled_circl_sync() -> None:
    """Scheduled CIRCL enrichment sync job."""
    await _execute_circl_sync()


async def _execute_circl_sync() -> None:
    """Execute CIRCL enrichment sync."""
    pipeline = CirclPipeline()
    try:
        result = await pipeline.sync()
        log.info("scheduler.circl_sync_completed", **result)
        await _evaluate_watch_rules_after_pipeline("CIRCL")
    except Exception as exc:  # noqa: BLE001
        log.exception("scheduler.circl_sync_failed", error=str(exc))
        await _notify_sync_failed("circl_sync", str(exc))
    finally:
        await pipeline.close()


async def _scheduled_ghsa_sync() -> None:
    """Scheduled GHSA sync job."""
    if settings.ingestion_bootstrap_on_startup:
        completed = await _initial_sync_already_completed("ghsa_initial_sync")
        if not completed:
            log.info("scheduler.ghsa_sync_skipped_initial_sync_incomplete")
            return
    await _execute_ghsa_sync(initial_sync=False)


async def _initial_ghsa_sync() -> None:
    """Initial GHSA sync on startup."""
    await _execute_ghsa_sync(initial_sync=True)


async def _execute_ghsa_sync(*, initial_sync: bool) -> None:
    """Execute GHSA sync."""
    pipeline = GhsaPipeline()
    try:
        # limit=0 for initial sync means no limit (fetch all advisories)
        limit = 0 if initial_sync else None
        result = await pipeline.sync(limit=limit, initial_sync=initial_sync)
        event = "scheduler.ghsa_sync_completed" if not initial_sync else "scheduler.ghsa_initial_sync_completed"
        log.info(event, **result)
        await _notify_new_vulnerabilities("GHSA", result.get("created", 0))
        await _evaluate_watch_rules_after_pipeline("GHSA")
    except Exception as exc:  # noqa: BLE001
        event = "scheduler.ghsa_sync_failed" if not initial_sync else "scheduler.ghsa_initial_sync_failed"
        log.exception(event, error=str(exc))
        await _notify_sync_failed("ghsa_sync", str(exc))
    finally:
        await pipeline.close()


async def _delayed_auto_scan_bootstrap() -> None:
    """Run auto-scan once on startup after a short delay."""
    await asyncio.sleep(30)
    log.info("scheduler.auto_scan_bootstrap_start")
    await _scheduled_auto_scans()


async def _scheduled_auto_scans() -> None:
    """Submit scans for all targets with auto_scan enabled, skipping unchanged targets.

    Scans are staggered with a delay between submissions to avoid overwhelming
    the scanner sidecar with concurrent git clones and scanner processes.
    """
    try:
        scan_service = await get_scan_service()
        targets = await scan_service.list_auto_scan_targets()
        if not targets:
            log.info("scheduler.auto_scan_no_targets")
            return

        submitted = 0
        skipped = 0
        for target in targets:
            target_id = target.get("target_id", "")
            target_type = target.get("type", "container_image")
            target_scanners = target.get("scanners") or ["trivy", "grype", "syft"]
            try:
                changed = await scan_service.check_target_changed(target_id, target_type, target)
                if not changed:
                    log.info("scheduler.auto_scan_skipped_unchanged", target_id=target_id)
                    skipped += 1
                    continue
                await scan_service.submit_scan(
                    target=target_id,
                    target_type=target_type,
                    scanners=target_scanners,
                    source="scheduled",
                )
                submitted += 1
                # Stagger submissions so the scanner sidecar doesn't get overwhelmed
                await asyncio.sleep(10)
            except Exception as exc:  # noqa: BLE001
                log.warning("scheduler.auto_scan_target_failed", target_id=target_id, error=str(exc))

        log.info("scheduler.auto_scan_completed", targets=len(targets), submitted=submitted, skipped=skipped)
    except Exception as exc:  # noqa: BLE001
        log.exception("scheduler.auto_scan_failed", error=str(exc))
