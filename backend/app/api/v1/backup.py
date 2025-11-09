from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.schemas.backup import BackupRestoreSummary, CPEBackupPayload, VulnerabilityBackupPayload
from app.services.backup_service import BackupService, get_backup_service


router = APIRouter()


@router.get("/vulnerabilities/{source}/export", response_class=Response)
async def export_vulnerabilities(
    source: str,
    service: BackupService = Depends(get_backup_service),
) -> Response:
    """
    Export all vulnerabilities for the given source (EUVD/NVD) as a JSON attachment.
    """

    try:
        payload = await service.export_vulnerabilities(source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload_dict = payload.model_dump(mode="json", by_alias=True)
    filename = f"{source.lower()}-vulnerabilities-backup-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    content = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return Response(content=content, media_type="application/json", headers=headers)


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

    # Allow restoring an "ALL" backup to "ALL", or a specific source backup to that source
    # Also allow restoring an "ALL" backup to a specific source endpoint (backward compat)
    normalized_payload_source = payload.metadata.source.upper()
    normalized_target_source = source.upper()

    if normalized_target_source != "ALL" and normalized_payload_source != "ALL":
        # Both are specific sources, they must match
        if normalized_payload_source != normalized_target_source:
            raise HTTPException(status_code=400, detail="Backup source does not match requested target.")

    if payload.metadata.item_count != len(payload.items):
        raise HTTPException(status_code=400, detail="Backup metadata item count does not match payload length.")

    return await service.restore_vulnerabilities(payload)


@router.get("/cpe/export", response_class=Response)
async def export_cpe(
    service: BackupService = Depends(get_backup_service),
) -> Response:
    """
    Export the entire CPE catalog as JSON attachment.
    """

    payload = await service.export_cpe()
    payload_dict = payload.model_dump(mode="json", by_alias=True)
    filename = f"cpe-backup-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    content = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return Response(content=content, media_type="application/json", headers=headers)


@router.post("/cpe/restore", response_model=BackupRestoreSummary)
async def restore_cpe(
    payload: CPEBackupPayload,
    service: BackupService = Depends(get_backup_service),
) -> BackupRestoreSummary:
    """
    Restore CPE catalog entries from a backup payload.
    """

    if payload.metadata.dataset != "cpe":
        raise HTTPException(status_code=400, detail="Backup dataset does not contain CPE data.")

    if payload.metadata.item_count != len(payload.items):
        raise HTTPException(status_code=400, detail="Backup metadata item count does not match payload length.")

    return await service.restore_cpe(payload)
