from __future__ import annotations

from fastapi import APIRouter, Depends

from app.schemas.sync import SyncStatesResponse, TriggerSyncRequest, TriggerSyncResponse
from app.services.sync_service import SyncService, get_sync_service

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
