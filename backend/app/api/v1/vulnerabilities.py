from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.config import settings
from app.schemas.ai import (
    AIBatchInvestigationRequest,
    AIBatchInvestigationResponse,
    AIInvestigationRequest,
    AIInvestigationResponse,
    AIProviderInfo,
)
from app.schemas.vulnerability import (
    DQLFieldAggregation,
    PagedVulnerabilityResponse,
    VulnerabilityDetail,
    VulnerabilityLookupRequest,
    VulnerabilityLookupResponse,
    VulnerabilityPreview,
    VulnerabilityQuery,
    VulnerabilityRefreshRequest,
    VulnerabilityRefreshResponse,
)
from app.services.ai_service import AIClient, AIProviderError, get_ai_client
from app.services.vulnerability_service import VulnerabilityService, get_vulnerability_service
from app.services.audit_service import AuditService, get_audit_service
from app.utils.request import get_client_ip

router = APIRouter()


@router.post("/search", response_model=list[VulnerabilityPreview])
async def search_vulnerabilities(
    query: VulnerabilityQuery,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityPreview]:
    return await service.search(query)


@router.post("/refresh", response_model=VulnerabilityRefreshResponse)
async def trigger_refresh(
    payload: VulnerabilityRefreshRequest,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityRefreshResponse:
    """
    Trigger vulnerability feed refresh.
    """
    return await service.trigger_refresh(payload)


@router.post("/lookup", response_model=VulnerabilityLookupResponse)
async def lookup_vulnerability(
    payload: VulnerabilityLookupRequest,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityLookupResponse:
    """
    Look up a single vulnerability by identifier with optional auto-sync.

    This endpoint first checks if the vulnerability exists locally. If not found
    and `autoSync` is true, it will attempt to fetch the vulnerability from
    NVD/EUVD sources. Useful for automation of vulnerability checking and
    data collection.

    Returns:
    - status "found": Vulnerability already exists in database
    - status "synced": Vulnerability was fetched from NVD/EUVD and stored
    - status "not_found": Vulnerability not available in any source
    - status "error": Sync was attempted but failed
    """
    identifier = payload.identifier.strip()

    # First, try to find locally
    existing = await service.get_by_id(identifier)
    if existing is not None:
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="found",
            vulnerability=existing,
        )

    # Not found locally - check if auto_sync is requested
    if not payload.auto_sync:
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="not_found",
            message="Vulnerability not found locally. Set autoSync=true to fetch from NVD/EUVD.",
        )

    # Attempt to sync from NVD/EUVD
    is_cve = identifier.upper().startswith("CVE-")
    refresh_request = VulnerabilityRefreshRequest(
        vuln_ids=[identifier] if is_cve else [],
        source_ids=[] if is_cve else [identifier],
    )

    try:
        refresh_response = await service.trigger_refresh(refresh_request)
    except Exception as exc:
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="error",
            message=f"Sync failed: {exc}",
        )

    # Check the refresh result
    sync_result = next((r for r in refresh_response.results if r.identifier.upper() == identifier.upper()), None)

    if sync_result is None:
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="not_found",
            message="No sync result returned. Vulnerability may not exist in NVD/EUVD.",
        )

    if sync_result.status == "error":
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="error",
            message=sync_result.message or "Sync failed without specific error message.",
            sync_result=sync_result,
        )

    if sync_result.status in ("inserted", "updated"):
        # Successfully synced - fetch the vulnerability
        synced_vuln = await service.get_by_id(identifier)
        return VulnerabilityLookupResponse(
            identifier=identifier,
            status="synced",
            vulnerability=synced_vuln,
            sync_result=sync_result,
        )

    # Status is "skipped" or unknown
    return VulnerabilityLookupResponse(
        identifier=identifier,
        status="not_found",
        message=sync_result.message or "Vulnerability not available in NVD/EUVD sources.",
        sync_result=sync_result,
    )


@router.get("", response_model=PagedVulnerabilityResponse)
async def list_vulnerabilities(
    search: str | None = Query(default=None, description="Keyword search across CVE/EUVD/GHSA"),
    dql: str | None = Query(
        default=None,
        alias="dqlQuery",
        description="Raw OpenSearch query (DQL syntax). Overrides the keyword search when present.",
    ),
    vendorFilters: list[str] = Query(default_factory=list),
    productFilters: list[str] = Query(default_factory=list),
    vendorSlugs: list[str] = Query(default_factory=list),
    productSlugs: list[str] = Query(default_factory=list),
    versionFilters: list[str] = Query(default_factory=list),
    include_rejected: bool = Query(
        default=False,
        alias="includeRejected",
        description="Include rejected CVE records in the response.",
    ),
    include_reserved: bool = Query(
        default=False,
        alias="includeReserved",
        description="Include reserved CVE records (without published date) in the response.",
    ),
    exploited_only: bool = Query(
        default=False,
        alias="exploitedOnly",
        description="Return only vulnerabilities with known exploitation.",
    ),
    ai_analysed_only: bool = Query(
        default=False,
        alias="aiAnalysedOnly",
        description="Return only vulnerabilities with AI analysis.",
    ),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> PagedVulnerabilityResponse:
    max_window = settings.opensearch_index_max_result_window
    if offset + limit > max_window:
        raise HTTPException(
            status_code=400,
            detail=(
                "Requested page exceeds the OpenSearch result window. "
                f"Use a smaller offset or filter the result set (max window: {max_window}, "
                "adjustable via OPENSEARCH_INDEX_MAX_RESULT_WINDOW)."
            ),
        )

    query = VulnerabilityQuery(
        searchTerm=search,
        dqlQuery=dql,
        vendorFilters=vendorFilters,
        productFilters=productFilters,
        vendorSlugs=vendorSlugs,
        productSlugs=productSlugs,
        versionFilters=versionFilters,
        limit=limit,
        includeRejected=include_rejected,
        includeReserved=include_reserved,
        exploitedOnly=exploited_only,
        aiAnalysedOnly=ai_analysed_only,
    )
    return await service.search_paginated(query, limit=limit, offset=offset)


@router.get("/dql/fields/{field_name}/aggregation", response_model=DQLFieldAggregation)
async def get_field_aggregation(
    field_name: str,
    size: int = Query(default=10, ge=1, le=50, description="Number of top values to return"),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> DQLFieldAggregation:
    """
    Get aggregated values for a DQL field with occurrence counts.
    Returns the most common values sorted by count (descending).
    """
    result = await service.get_field_aggregation(field_name, size=size)
    return DQLFieldAggregation.model_validate(result)


@router.get("/ai/providers", response_model=list[AIProviderInfo])
async def list_ai_providers(ai_client: AIClient = Depends(get_ai_client)) -> list[AIProviderInfo]:
    return ai_client.get_available_providers()


@router.get("/{identifier}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    identifier: str,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityDetail:
    """
    Retrieve a single vulnerability by its canonical identifier (CVE or source ID).
    """
    result = await service.get_by_id(identifier)
    if result is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return result


@router.post("/{identifier}/ai-investigation", response_model=AIInvestigationResponse)
async def create_ai_investigation(
    identifier: str,
    payload: AIInvestigationRequest,
    request: Request,
    service: VulnerabilityService = Depends(get_vulnerability_service),
    ai_client: AIClient = Depends(get_ai_client),
    audit_service: AuditService = Depends(get_audit_service),
) -> AIInvestigationResponse:
    vulnerability = await service.get_by_id(identifier)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    try:
        result = await ai_client.analyze_vulnerability(
            payload.provider,
            vulnerability,
            language=payload.language,
            additional_context=payload.additional_context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    assessment_payload = result.model_dump(by_alias=True)
    persisted = await service.save_ai_assessment(identifier, assessment_payload)
    if not persisted:
        raise HTTPException(status_code=502, detail="Failed to persist AI assessment.")

    client_ip = get_client_ip(request)
    metadata = {
        "label": "AI-Analyse abgeschlossen",
        "clientIp": client_ip,
        "provider": payload.provider,
    }
    metadata = {key: value for key, value in metadata.items() if value}
    result_payload = {
        "vulnerabilityId": identifier,
        "language": result.language,
        "summary": result.summary,
    }
    await audit_service.record_event(
        "ai_investigation",
        metadata=metadata or None,
        result=result_payload,
    )

    return result


@router.post("/ai-investigation/batch", response_model=AIBatchInvestigationResponse)
async def create_batch_ai_investigation(
    payload: AIBatchInvestigationRequest,
    request: Request,
    service: VulnerabilityService = Depends(get_vulnerability_service),
    ai_client: AIClient = Depends(get_ai_client),
    audit_service: AuditService = Depends(get_audit_service),
) -> AIBatchInvestigationResponse:
    """
    Analyze multiple vulnerabilities together for combined insights.
    Maximum 10 vulnerabilities per request.
    """
    # Fetch all vulnerabilities
    vulnerabilities: list[VulnerabilityDetail] = []
    for vuln_id in payload.vulnerability_ids:
        vuln = await service.get_by_id(vuln_id)
        if vuln is None:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability {vuln_id} not found",
            )
        vulnerabilities.append(vuln)

    # Call AI service for batch analysis
    try:
        result = await ai_client.analyze_vulnerabilities_batch(
            payload.provider,
            vulnerabilities,
            language=payload.language,
            additional_context=payload.additional_context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # Save batch analysis to database
    batch_id = await service.save_batch_analysis(
        vulnerability_ids=payload.vulnerability_ids,
        provider=payload.provider,
        language=result.language,
        summary=result.summary,
        individual_summaries=result.individual_summaries,
        additional_context=payload.additional_context,
    )

    # Audit logging
    client_ip = get_client_ip(request)
    metadata = {
        "label": "AI Batch-Analyse abgeschlossen",
        "clientIp": client_ip,
        "provider": payload.provider,
        "vulnerabilityCount": len(vulnerabilities),
        "batchId": batch_id,
    }
    metadata = {key: value for key, value in metadata.items() if value}
    result_payload = {
        "batchId": batch_id,
        "vulnerabilityIds": payload.vulnerability_ids,
        "language": result.language,
        "vulnerabilityCount": result.vulnerability_count,
    }
    await audit_service.record_event(
        "ai_batch_investigation",
        metadata=metadata or None,
        result=result_payload,
    )

    return result


@router.get("/ai-investigation/batch", response_model=dict[str, Any])
async def list_batch_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, Any]:
    """
    List recent batch AI analyses with pagination.
    """
    return await service.list_batch_analyses(limit=limit, offset=offset)


@router.get("/ai-investigation/batch/{batch_id}", response_model=dict[str, Any])
async def get_batch_analysis(
    batch_id: str,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, Any]:
    """
    Retrieve a specific batch AI analysis by ID.
    """
    result = await service.get_batch_analysis(batch_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Batch analysis not found")
    return result


@router.get("/ai-investigation/single", response_model=dict[str, Any])
async def list_single_ai_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, Any]:
    """
    List vulnerabilities with single AI analyses, sorted by most recent.
    """
    return await service.list_single_ai_analyses(limit=limit, offset=offset)
