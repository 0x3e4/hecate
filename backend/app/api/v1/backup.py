from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse

from app.schemas.backup import BackupRestoreSummary, SavedSearchBackupPayload, VulnerabilityBackupPayload
from app.services.backup_service import BackupService, get_backup_service


router = APIRouter()


@router.get("/vulnerabilities/{source}/export", response_class=StreamingResponse)
async def export_vulnerabilities(
    source: str,
    service: BackupService = Depends(get_backup_service),
) -> StreamingResponse:
    """
    Export all vulnerabilities for the given source (EUVD/NVD/ALL) as a streaming JSON attachment.
    """

    try:
        stream = service.stream_vulnerability_export(source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    filename = f"{source.lower()}-vulnerabilities-backup-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return StreamingResponse(stream, media_type="application/json", headers=headers)


@router.post("/vulnerabilities/{source}/restore", response_model=BackupRestoreSummary)
async def restore_vulnerabilities(
    source: str,
    payload: VulnerabilityBackupPayload,
    service: BackupService = Depends(get_backup_service),
) -> BackupRestoreSummary:
    """
    Restore vulnerabilities from a backup payload for the given source.
    """

    if payload.metadata.dataset != "vulnerabilities":
        raise HTTPException(status_code=400, detail="Backup dataset does not contain vulnerabilities.")

    normalized_payload_source = payload.metadata.source.upper()
    normalized_target_source = source.upper()

    if normalized_target_source != "ALL" and normalized_payload_source != "ALL":
        if normalized_payload_source != normalized_target_source:
            raise HTTPException(status_code=400, detail="Backup source does not match requested target.")

    if payload.metadata.item_count != len(payload.items):
        raise HTTPException(status_code=400, detail="Backup metadata item count does not match payload length.")

    return await service.restore_vulnerabilities(payload)


@router.get("/saved-searches/export", response_class=Response)
async def export_saved_searches(
    service: BackupService = Depends(get_backup_service),
) -> Response:
    """
    Export all saved searches as a JSON attachment.
    """

    payload = await service.export_saved_searches()
    payload_dict = payload.model_dump(mode="json", by_alias=True)
    filename = f"saved-searches-backup-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    content = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return Response(content=content, media_type="application/json", headers=headers)


@router.post("/saved-searches/restore", response_model=BackupRestoreSummary)
async def restore_saved_searches(
    payload: SavedSearchBackupPayload,
    service: BackupService = Depends(get_backup_service),
) -> BackupRestoreSummary:
    """
    Restore saved searches from a backup payload.
    """

    if payload.metadata.dataset != "saved_searches":
        raise HTTPException(status_code=400, detail="Backup dataset does not contain saved searches.")

    if payload.metadata.item_count != len(payload.items):
        raise HTTPException(status_code=400, detail="Backup metadata item count does not match payload length.")

    return await service.restore_saved_searches(payload)
