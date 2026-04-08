from __future__ import annotations

import re

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
    vuln_ids: list[str] = Field(alias="vulnIds", serialization_alias="vulnIds")
    delete_only: bool = Field(False, alias="deleteOnly", serialization_alias="deleteOnly")

    model_config = {"populate_by_name": True}


class ResyncResponse(BaseModel):
    deleted: int = 0
    refreshed: int = 0
    resolved_ids: list[str] = Field(default_factory=list, alias="resolvedIds", serialization_alias="resolvedIds")
    errors: list[str] = Field(default_factory=list)
    message: str

    model_config = {"populate_by_name": True}


_WILDCARD_MAX = 1000
_VALID_ID_PATTERN = re.compile(r"^[A-Za-z0-9\-\.\*]+$")


async def _resolve_wildcard_ids(repo: VulnerabilityRepository, raw_id: str) -> list[str]:
    """Expand a wildcard pattern like CVE-2024-* into matching IDs."""
    if "*" not in raw_id:
        return [raw_id]
    if not _VALID_ID_PATTERN.match(raw_id):
        return []
    regex = "^" + re.escape(raw_id).replace(r"\*", ".*") + "$"
    cursor = repo.collection.find({"_id": {"$regex": regex}}, {"_id": 1}).limit(_WILDCARD_MAX)
    return [doc["_id"] async for doc in cursor]


@router.post("/resync", response_model=ResyncResponse)
async def resync_vulnerability(
    request: ResyncRequest,
    vuln_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> ResyncResponse:
    """Delete vulnerabilities from MongoDB and OpenSearch, optionally re-fetch from upstream.

    Supports multiple IDs and wildcard patterns (e.g. CVE-2024-*).
    """
    from app.schemas.vulnerability import VulnerabilityRefreshRequest

    repo = await VulnerabilityRepository.create()

    # Expand wildcards and deduplicate
    all_ids: list[str] = []
    seen: set[str] = set()
    for raw in request.vuln_ids:
        stripped = raw.strip()
        if not stripped:
            continue
        resolved = await _resolve_wildcard_ids(repo, stripped)
        for rid in resolved:
            if rid not in seen:
                seen.add(rid)
                all_ids.append(rid)

    if not all_ids:
        return ResyncResponse(message="No vulnerability IDs provided or matched.")

    deleted_count = 0
    refreshed_count = 0
    errors: list[str] = []

    for vuln_id in all_ids:
        try:
            mongo_result = await repo.collection.delete_one({"_id": vuln_id})
            mongo_deleted = mongo_result.deleted_count > 0
            os_deleted = await async_delete_document(settings.opensearch_index, vuln_id)

            if mongo_deleted or os_deleted:
                deleted_count += 1
                log.info("sync.resync_deleted", vuln_id=vuln_id, mongo=mongo_deleted, opensearch=os_deleted)

                if not request.delete_only:
                    try:
                        payload = VulnerabilityRefreshRequest(vuln_ids=[vuln_id], source_ids=[vuln_id])
                        await vuln_service.trigger_refresh(payload)
                        refreshed_count += 1
                    except Exception as exc:
                        errors.append(f"{vuln_id}: refresh failed ({exc})")
        except Exception as exc:
            errors.append(f"{vuln_id}: delete failed ({exc})")

    if request.delete_only:
        message = f"Deleted {deleted_count} of {len(all_ids)} vulnerabilities."
    else:
        message = f"Deleted {deleted_count} and re-fetched {refreshed_count} of {len(all_ids)} vulnerabilities."

    return ResyncResponse(
        deleted=deleted_count,
        refreshed=refreshed_count,
        resolved_ids=all_ids,
        errors=errors,
        message=message,
    )
