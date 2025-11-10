from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.schemas.ai import (
    AIInvestigationRequest,
    AIInvestigationResponse,
    AIProviderInfo,
)
from app.schemas.vulnerability import (
    PagedVulnerabilityResponse,
    VulnerabilityDetail,
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
        exploitedOnly=exploited_only,
        aiAnalysedOnly=ai_analysed_only,
    )
    return await service.search_paginated(query, limit=limit, offset=offset)


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
