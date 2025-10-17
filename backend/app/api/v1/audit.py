from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.schemas.audit import IngestionLogResponse
from app.services.audit_service import AuditService, get_audit_service

router = APIRouter()


@router.get("/ingestion", response_model=IngestionLogResponse)
async def list_ingestion_logs(
    job: str | None = Query(default=None, description="Optional job name to filter"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: AuditService = Depends(get_audit_service),
) -> IngestionLogResponse:
    return await service.list_logs(job_name=job, limit=limit, offset=offset)
