from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.core.auth_context import get_auth_context
from app.core.config import settings
from app.schemas.audit import IngestionLogResponse
from app.services.audit_service import AuditService, get_audit_service

router = APIRouter()


@router.get("/ingestion", response_model=IngestionLogResponse)
async def list_ingestion_logs(
    request: Request,
    job: str | None = Query(default=None, description="Optional job name to filter"),
    status: str | None = Query(default=None, description="Optional status to filter (running, completed, failed, cancelled)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: AuditService = Depends(get_audit_service),
) -> IngestionLogResponse:
    response = await service.list_logs(job_name=job, status=status, limit=limit, offset=offset)
    # The log is public when login is optional: anonymous readers see who did
    # something by name and role, not by e-mail address or IdP subject.
    if settings.oidc_enabled and (await get_auth_context(request)).user is None:
        for entry in response.items:
            redact_actor(entry.metadata)
    return response


_PERSONAL_KEYS = ("email", "sub")
# What an anonymous reader sees instead of an MCP user's IdP identity (a GitHub
# login, a Microsoft UPN, an OIDC subject).
MCP_IDENTITY_PLACEHOLDER = "MCP user"


def redact_actor(metadata: dict | None) -> None:
    if not metadata:
        return
    # The MCP writers (app/mcp/audit.py) keep the e-mail and the IdP identity at
    # the top level of metadata, not in an actor container.
    for key in _PERSONAL_KEYS:
        metadata.pop(key, None)
    if metadata.get("identity"):
        metadata["identity"] = MCP_IDENTITY_PLACEHOLDER
    for key in ("actor", "user"):
        value = metadata.get(key)
        if isinstance(value, dict):
            metadata[key] = {k: v for k, v in value.items() if k not in _PERSONAL_KEYS}
