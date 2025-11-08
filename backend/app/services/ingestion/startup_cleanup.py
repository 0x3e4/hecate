from __future__ import annotations

from datetime import UTC, datetime

import structlog

from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.ingestion_log_repository import IngestionLogRepository

log = structlog.get_logger()


async def cleanup_stale_jobs() -> None:
    """
    Clean up stale "running" jobs from previous container instances.

    When the container restarts, any jobs that were running are now orphaned
    and will never complete. This function marks them as cancelled in both
    the ingestion_state and ingestion_log collections.
    """
    try:
        state_repo = await IngestionStateRepository.create()
        log_repo = await IngestionLogRepository.create()

        # Find all job:* keys with status "running" in ingestion_state
        stale_states = await state_repo.find_running_jobs()

        if stale_states:
            log.info("startup_cleanup.found_stale_states", count=len(stale_states))

            # Mark each as cancelled
            for job_key in stale_states:
                await state_repo.update_state(
                    job_key,
                    {
                        "status": "cancelled",
                        "finished_at": datetime.now(tz=UTC),
                        "error": "Container restarted while job was running.",
                    },
                )

            log.info("startup_cleanup.states_cancelled", count=len(stale_states))

        # Cancel running logs
        cancelled_count = await log_repo.cancel_all_running(
            reason="Container restarted while job was running."
        )

        if cancelled_count > 0:
            log.info("startup_cleanup.logs_cancelled", count=cancelled_count)

        if not stale_states and cancelled_count == 0:
            log.info("startup_cleanup.no_stale_jobs")

    except Exception as exc:  # noqa: BLE001
        # Don't fail startup if cleanup fails
        log.warning("startup_cleanup.failed", error=str(exc))
