from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.config import settings
from app.db.opensearch import async_delete_document
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.sync import SyncStatesResponse, TriggerSyncRequest, TriggerSyncResponse
from app.schemas.vulnerability import VulnerabilityRefreshResponse
from app.services.vulnerability_service import VulnerabilityService, get_vulnerability_service
from app.services.sync_service import SyncService, get_sync_service

log = structlog.get_logger()

router = APIRouter()


@router.get("/states", response_model=SyncStatesResponse)
async def get_sync_states(
    service: SyncService = Depends(get_sync_service),
) -> SyncStatesResponse:
    """Get the current state of all sync jobs."""
    syncs = await service.get_all_sync_states()
    return SyncStatesResponse(syncs=syncs)


@router.post("/trigger/euvd", response_model=TriggerSyncResponse)
async def trigger_euvd_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger EUVD sync (normal or initial)."""
    result = await service.trigger_euvd_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/nvd", response_model=TriggerSyncResponse)
async def trigger_nvd_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger NVD sync (normal or initial)."""
    result = await service.trigger_nvd_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/cpe", response_model=TriggerSyncResponse)
async def trigger_cpe_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger CPE sync (normal or initial)."""
    result = await service.trigger_cpe_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/kev", response_model=TriggerSyncResponse)
async def trigger_kev_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger CISA KEV sync (normal or initial)."""
    result = await service.trigger_kev_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/cwe", response_model=TriggerSyncResponse)
async def trigger_cwe_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger CWE sync (normal or initial)."""
    result = await service.trigger_cwe_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/capec", response_model=TriggerSyncResponse)
async def trigger_capec_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger CAPEC sync (normal or initial)."""
    result = await service.trigger_capec_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/circl", response_model=TriggerSyncResponse)
async def trigger_circl_sync(
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger CIRCL enrichment sync (no initial_sync support)."""
    result = await service.trigger_circl_sync()
    return TriggerSyncResponse(**result)


@router.post("/trigger/ghsa", response_model=TriggerSyncResponse)
async def trigger_ghsa_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger GHSA sync (normal or initial)."""
    result = await service.trigger_ghsa_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


@router.post("/trigger/osv", response_model=TriggerSyncResponse)
async def trigger_osv_sync(
    request: TriggerSyncRequest = TriggerSyncRequest(),
    service: SyncService = Depends(get_sync_service),
) -> TriggerSyncResponse:
    """Trigger OSV sync (normal or initial)."""
    result = await service.trigger_osv_sync(initial=request.initial)
    return TriggerSyncResponse(**result)


class ResyncRequest(BaseModel):
    vuln_id: str = Field(alias="vulnId", serialization_alias="vulnId")

    model_config = {"populate_by_name": True}


class ResyncResponse(BaseModel):
    deleted: bool
    refresh: VulnerabilityRefreshResponse | None = None
    message: str


@router.post("/resync", response_model=ResyncResponse)
async def resync_vulnerability(
    request: ResyncRequest,
    vuln_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> ResyncResponse:
    """Delete a vulnerability from MongoDB and OpenSearch, then re-fetch from upstream sources."""
    from app.schemas.vulnerability import VulnerabilityRefreshRequest

    vuln_id = request.vuln_id.strip()
    if not vuln_id:
        return ResyncResponse(deleted=False, message="Empty vulnerability ID.")

    # Delete from MongoDB
    repo = await VulnerabilityRepository.create()
    mongo_result = await repo.collection.delete_one({"_id": vuln_id})
    mongo_deleted = mongo_result.deleted_count > 0

    # Delete from OpenSearch
    os_deleted = await async_delete_document(settings.opensearch_index, vuln_id)

    if not mongo_deleted and not os_deleted:
        return ResyncResponse(deleted=False, message=f"Vulnerability {vuln_id} not found.")

    log.info("sync.resync_deleted", vuln_id=vuln_id, mongo=mongo_deleted, opensearch=os_deleted)

    # Re-fetch from upstream
    payload = VulnerabilityRefreshRequest(vuln_ids=[vuln_id], source_ids=[vuln_id])
    refresh_result = await vuln_service.trigger_refresh(payload)

    return ResyncResponse(
        deleted=True,
        refresh=refresh_result,
        message=f"Deleted {vuln_id} and re-fetched from upstream.",
    )
