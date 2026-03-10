from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.schemas.sync import SyncState
from app.services.ingestion.circl_pipeline import CirclPipeline
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.ghsa_pipeline import GhsaPipeline
from app.services.ingestion.kev_pipeline import KevPipeline
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.scheduling.manager import _execute_capec_sync, _execute_cwe_sync, get_scheduler

log = structlog.get_logger()

# Define all sync jobs with their labels
SYNC_JOBS = [
    ("euvd_ingestion", "EUVD Sync"),
    ("euvd_initial_sync", "EUVD Initial Sync"),
    ("nvd_sync", "NVD Sync"),
    ("nvd_initial_sync", "NVD Initial Sync"),
    ("cpe_sync", "CPE Sync"),
    ("cpe_initial_sync", "CPE Initial Sync"),
    ("kev_sync", "CISA KEV Sync"),
    ("kev_initial_sync", "CISA KEV Initial Sync"),
    ("cwe_sync", "CWE Cache Refresh"),
    ("cwe_initial_sync", "CWE Initial Cache Prefetch"),
    ("capec_sync", "CAPEC Cache Refresh"),
    ("capec_initial_sync", "CAPEC Initial Cache Prefetch"),
    ("circl_sync", "CIRCL Enrichment Sync"),
    ("ghsa_sync", "GHSA Sync"),
    ("ghsa_initial_sync", "GHSA Initial Sync"),
]


class SyncService:
    def __init__(
        self,
        state_repository: IngestionStateRepository,
        log_repository: IngestionLogRepository,
    ) -> None:
        self.state_repository = state_repository
        self.log_repository = log_repository

    async def get_all_sync_states(self) -> list[SyncState]:
        """Get the current state of all sync jobs."""
        states: list[SyncState] = []

        # Get scheduler to check next run times
        scheduler = get_scheduler()
        scheduler_jobs = {}
        if scheduler.scheduler.running:
            for job in scheduler.scheduler.get_jobs():
                scheduler_jobs[job.id] = job

        for job_name, label in SYNC_JOBS:
            # Map job names to scheduler job IDs
            next_run = None
            scheduler_job_id = None

            # Map to appropriate scheduler job
            if job_name == "euvd_initial_sync":
                # Initial sync tracks the weekly full sync schedule
                scheduler_job_id = "euvd_full_sync"
            elif job_name == "nvd_initial_sync":
                # Initial sync tracks the weekly full sync schedule
                scheduler_job_id = "nvd_full_sync"
            elif "_initial_sync" not in job_name:
                # Regular scheduled jobs use their own name
                scheduler_job_id = job_name

            # Get next run time from scheduler if applicable
            if scheduler_job_id and scheduler_job_id in scheduler_jobs:
                next_run_time = scheduler_jobs[scheduler_job_id].next_run_time
                if next_run_time:
                    next_run = next_run_time.astimezone(UTC)

            state = await self._get_sync_state(job_name, label, next_run)
            states.append(state)

        return states

    async def _get_sync_state(self, job_name: str, label: str, next_run: datetime | None = None) -> SyncState:
        """Get the state of a specific sync job."""
        # Try to get current running state
        job_state = await self.state_repository.get_state(f"job:{job_name}")

        if job_state and job_state.get("status") == "running":
            # Job is currently running
            started_at = job_state.get("started_at")
            if isinstance(started_at, datetime) and started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)

            duration = None
            if started_at:
                duration = (datetime.now(tz=UTC) - started_at).total_seconds()

            return SyncState(
                jobName=job_name,
                label=label,
                status="running",
                startedAt=started_at,
                finishedAt=None,
                durationSeconds=duration,
                nextRun=next_run,
                lastResult=None,
                error=None,
            )

        # Not currently running, get last completed run from logs
        total, items = await self.log_repository.list_logs(
            job_name=job_name,
            status=None,
            limit=1,
            offset=0,
        )

        if items:
            last_log = items[0]
            return SyncState(
                jobName=job_name,
                label=label,
                status=last_log.get("status", "idle"),
                startedAt=last_log.get("startedAt"),
                finishedAt=last_log.get("finishedAt"),
                durationSeconds=last_log.get("durationSeconds"),
                nextRun=next_run,
                lastResult=last_log.get("result"),
                error=last_log.get("error"),
            )

        # No state found, job has never run
        return SyncState(
            jobName=job_name,
            label=label,
            status="idle",
            startedAt=None,
            finishedAt=None,
            durationSeconds=None,
            nextRun=next_run,
            lastResult=None,
            error=None,
        )

    async def trigger_euvd_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger EUVD sync (normal or initial)."""
        log.info("sync.trigger_euvd", initial=initial)
        asyncio.create_task(self._execute_euvd_sync(initial=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} EUVD sync triggered",
            "jobName": "euvd_initial_sync" if initial else "euvd_ingestion",
        }

    async def trigger_nvd_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger NVD sync (normal or initial)."""
        log.info("sync.trigger_nvd", initial=initial)
        asyncio.create_task(self._execute_nvd_sync(initial=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} NVD sync triggered",
            "jobName": "nvd_initial_sync" if initial else "nvd_sync",
        }

    async def trigger_cpe_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger CPE sync (normal or initial)."""
        log.info("sync.trigger_cpe", initial=initial)
        asyncio.create_task(self._execute_cpe_sync(initial=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} CPE sync triggered",
            "jobName": "cpe_initial_sync" if initial else "cpe_sync",
        }

    async def trigger_kev_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger CISA KEV sync (normal or initial)."""
        log.info("sync.trigger_kev", initial=initial)
        asyncio.create_task(self._execute_kev_sync(initial=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} CISA KEV sync triggered",
            "jobName": "kev_initial_sync" if initial else "kev_sync",
        }

    async def trigger_cwe_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger CWE sync (normal or initial)."""
        log.info("sync.trigger_cwe", initial=initial)
        asyncio.create_task(_execute_cwe_sync(initial_sync=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} CWE sync triggered",
            "jobName": "cwe_initial_sync" if initial else "cwe_sync",
        }

    async def trigger_capec_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger CAPEC sync (normal or initial)."""
        log.info("sync.trigger_capec", initial=initial)
        asyncio.create_task(_execute_capec_sync(initial_sync=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} CAPEC sync triggered",
            "jobName": "capec_initial_sync" if initial else "capec_sync",
        }

    async def _execute_euvd_sync(self, *, initial: bool) -> None:
        """Execute EUVD sync in background."""
        try:
            limit = None if not initial else 0
            result = await run_ingestion(limit=limit, initial_sync=initial)
            log.info("sync.euvd_completed", initial=initial, **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.euvd_failed", initial=initial, error=str(exc))

    async def _execute_nvd_sync(self, *, initial: bool) -> None:
        """Execute NVD sync in background."""
        pipeline = NVDPipeline()
        try:
            result = await pipeline.sync(initial_sync=initial)
            log.info("sync.nvd_completed", initial=initial, **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.nvd_failed", initial=initial, error=str(exc))

    async def _execute_cpe_sync(self, *, initial: bool) -> None:
        """Execute CPE sync in background."""
        pipeline = CPEPipeline()
        try:
            limit = 0 if initial else None
            result = await pipeline.sync(limit=limit, initial_sync=initial)
            log.info("sync.cpe_completed", initial=initial, **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.cpe_failed", initial=initial, error=str(exc))
        finally:
            await pipeline.close()

    async def _execute_kev_sync(self, *, initial: bool) -> None:
        """Execute CISA KEV sync in background."""
        pipeline = KevPipeline()
        try:
            result = await pipeline.sync(initial_sync=initial)
            log.info("sync.kev_completed", initial=initial, **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.kev_failed", initial=initial, error=str(exc))

    async def trigger_circl_sync(self) -> dict[str, Any]:
        """Trigger CIRCL enrichment sync (no initial_sync support)."""
        log.info("sync.trigger_circl")
        asyncio.create_task(self._execute_circl_sync())
        return {
            "success": True,
            "message": "CIRCL enrichment sync triggered",
            "jobName": "circl_sync",
        }

    async def _execute_circl_sync(self) -> None:
        """Execute CIRCL enrichment sync in background."""
        pipeline = CirclPipeline()
        try:
            result = await pipeline.sync()
            log.info("sync.circl_completed", **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.circl_failed", error=str(exc))
        finally:
            await pipeline.close()

    async def trigger_ghsa_sync(self, *, initial: bool) -> dict[str, Any]:
        """Trigger GHSA sync (normal or initial)."""
        log.info("sync.trigger_ghsa", initial=initial)
        asyncio.create_task(self._execute_ghsa_sync(initial=initial))
        return {
            "success": True,
            "message": f"{'Initial' if initial else 'Normal'} GHSA sync triggered",
            "jobName": "ghsa_initial_sync" if initial else "ghsa_sync",
        }

    async def _execute_ghsa_sync(self, *, initial: bool) -> None:
        """Execute GHSA sync in background."""
        pipeline = GhsaPipeline()
        try:
            result = await pipeline.sync(initial_sync=initial)
            log.info("sync.ghsa_completed", initial=initial, **result)
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.ghsa_failed", initial=initial, error=str(exc))
        finally:
            await pipeline.close()


async def get_sync_service() -> SyncService:
    state_repository = await IngestionStateRepository.create()
    log_repository = await IngestionLogRepository.create()
    return SyncService(state_repository, log_repository)
