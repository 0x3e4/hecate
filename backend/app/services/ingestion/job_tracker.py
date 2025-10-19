from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.ingestion_log_repository import IngestionLogRepository

from bson import ObjectId

log = structlog.get_logger()


@dataclass(slots=True)
class JobContext:
    name: str
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    log_id: ObjectId | None = None


class JobTracker:
    def __init__(self, state_repo: IngestionStateRepository) -> None:
        self.state_repo = state_repo

    async def start(self, name: str, **metadata: Any) -> JobContext:
        log_repo = await IngestionLogRepository.create()
        cancelled = await log_repo.cancel_running(
            job_name=name,
            reason="Marked as cancelled because a new job run started.",
        )
        if cancelled:
            now = datetime.now(tz=UTC)
            await self.state_repo.update_state(
                f"job:{name}",
                {
                    "status": "cancelled",
                    "finished_at": now,
                    "duration_seconds": None,
                    "result": {"cancelled_runs": cancelled},
                    "error": "Previous run cancelled before completion.",
                },
            )

        ctx = JobContext(name=name, metadata=metadata)
        ctx.log_id = await log_repo.start_log(job_name=name, started_at=ctx.started_at, metadata=metadata)
        await self.state_repo.update_state(
            f"job:{name}",
            {
                "status": "running",
                "started_at": ctx.started_at,
                "metadata": metadata,
            },
        )
        return ctx

    async def finish(self, ctx: JobContext, **result: Any) -> None:
        finished_at = datetime.now(tz=UTC)
        await self.state_repo.update_state(
            f"job:{ctx.name}",
            {
                "status": "completed",
                "finished_at": finished_at,
                "duration_seconds": (finished_at - ctx.started_at).total_seconds(),
                "result": result,
                "progress": None,
            },
        )
        if ctx.log_id is not None:
            log_repo = await IngestionLogRepository.create()
            await log_repo.complete_log(
                ctx.log_id,
                started_at=ctx.started_at,
                finished_at=finished_at,
                result=result,
            )

    async def fail(self, ctx: JobContext, error: str) -> None:
        finished_at = datetime.now(tz=UTC)
        await self.state_repo.update_state(
            f"job:{ctx.name}",
            {
                "status": "failed",
                "finished_at": finished_at,
                "duration_seconds": (finished_at - ctx.started_at).total_seconds(),
                "error": error,
                "progress": None,
            },
        )
        if ctx.log_id is not None:
            log_repo = await IngestionLogRepository.create()
            await log_repo.fail_log(
                ctx.log_id,
                started_at=ctx.started_at,
                finished_at=finished_at,
                error=error,
            )
