from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from bson.objectid import ObjectId

from app.core.config import settings
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.schemas.audit import IngestionLogEntry, IngestionLogResponse


class AuditService:
    def __init__(self, log_repository: IngestionLogRepository) -> None:
        self.log_repository = log_repository

    async def list_logs(self, *, job_name: str | None, limit: int, offset: int) -> IngestionLogResponse:
        total, items = await self.log_repository.list_logs(job_name=job_name, limit=limit, offset=offset)
        entries = [self._map_entry(item) for item in items]
        return IngestionLogResponse(total=total, items=entries)

    def _map_entry(self, document: dict[str, Any]) -> IngestionLogEntry:
        doc = document.copy()
        if isinstance(doc.get("_id"), ObjectId):
            doc["id"] = str(doc.pop("_id"))
        entry = IngestionLogEntry.model_validate(doc)

        updates: dict[str, Any] = {}
        if entry.status == "running" and entry.finished_at is None:
            started_at = entry.started_at
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)

            elapsed = datetime.now(tz=UTC) - started_at
            if entry.duration_seconds is None:
                updates["duration_seconds"] = elapsed.total_seconds()

            timeout_minutes = settings.ingestion_running_timeout_minutes
            if timeout_minutes > 0 and elapsed > timedelta(minutes=timeout_minutes):
                updates["overdue"] = True
                updates.setdefault(
                    "overdue_reason",
                    f"Job has been running for {elapsed.total_seconds() / 60:.1f} minutes "
                    f"(threshold: {timeout_minutes} minutes).",
                )

        if updates:
            entry = entry.model_copy(update=updates)

        return entry


async def get_audit_service() -> AuditService:
    repository = await IngestionLogRepository.create()
    return AuditService(repository)
