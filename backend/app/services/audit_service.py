from __future__ import annotations

from typing import Any

from bson.objectid import ObjectId

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
        return IngestionLogEntry.model_validate(doc)


async def get_audit_service() -> AuditService:
    repository = await IngestionLogRepository.create()
    return AuditService(repository)
