from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.core.config import settings
from app.schemas.ai import (
    AIBatchInvestigationRequest,
    AIBatchInvestigationResponse,
    AIBatchInvestigationSubmitResponse,
    AIInvestigationRequest,
    AIInvestigationResponse,
    AIInvestigationSubmitResponse,
    AIProviderInfo,
)
from app.schemas.attack_path import (
    AttackPathNarrative,
    AttackPathRequest,
    AttackPathResponse,
    AttackPathSubmitResponse,
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
from app.services.attack_path_service import AttackPathService, get_attack_path_service
from app.services.event_bus import publish_job_completed, publish_job_failed, publish_job_started
from app.services.inventory_service import InventoryService, get_inventory_service
from app.services.vulnerability_service import VulnerabilityService, get_vulnerability_service
from app.services.audit_service import AuditService, get_audit_service
from app.utils.request import get_client_ip

logger = structlog.get_logger()

router = APIRouter()


def _require_ai_analysis_password(
    ai_analysis_password: str | None = Header(default=None, alias="X-AI-Analysis-Password"),
) -> None:
    configured_password = settings.ai_analysis_password
    if not configured_password:
        return
    if ai_analysis_password != configured_password:
        raise HTTPException(status_code=401, detail="Invalid or missing AI analysis password.")


@router.post("/search", response_model=list[VulnerabilityPreview])
async def search_vulnerabilities(
    query: VulnerabilityQuery,
    tz: str | None = Query(default=None),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityPreview]:
    if tz and not query.tz:
        query = query.model_copy(update={"tz": tz})
    return await service.search(query)


@router.post(
    "/refresh",
    response_model=VulnerabilityRefreshResponse,
    status_code=202,
)
async def trigger_refresh(
    payload: VulnerabilityRefreshRequest,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityRefreshResponse:
    """Trigger a vulnerability feed refresh asynchronously.

    The request is enqueued as a background task and the response returns
    immediately with HTTP 202 so clients don't hit Cloudflare's 100s edge
    timeout on slow upstream sources (OSV.dev can take 90-150s per MAL-*
    record; deps.dev enrichment adds another few seconds). The final per-ID
    results are published on the SSE stream as a `job_completed` event with
    `jobName == f"vulnerability_refresh_{jobId}"` — clients subscribe and
    render the outcome when it arrives.
    """
    requested_ids = list(dict.fromkeys((payload.vuln_ids or []) + (payload.source_ids or [])))
    if not requested_ids:
        raise HTTPException(status_code=400, detail="No identifiers provided.")

    job_id = uuid.uuid4().hex[:16]
    job_name = f"vulnerability_refresh_{job_id}"
    started_at = datetime.now(UTC)

    publish_job_started(
        job_name,
        started_at,
        vulnerabilityIds=requested_ids,
        source=payload.source,
    )

    asyncio.create_task(
        _run_refresh_background(
            payload=payload,
            service=service,
            job_name=job_name,
            started_at=started_at,
        )
    )

    accepted_results = [
        {
            "identifier": identifier,
            "provider": payload.source,
            "status": "accepted",
            "message": "Queued — results will arrive via SSE.",
        }
        for identifier in requested_ids
    ]
    return VulnerabilityRefreshResponse.model_validate(
        {
            "requested": requested_ids,
            "results": accepted_results,
            "jobId": job_id,
        }
    )


async def _run_refresh_background(
    *,
    payload: VulnerabilityRefreshRequest,
    service: VulnerabilityService,
    job_name: str,
    started_at: datetime,
) -> None:
    """Execute the refresh and publish the result onto the SSE bus."""
    try:
        result = await service.trigger_refresh(payload)
    except Exception as exc:  # noqa: BLE001
        finished_at = datetime.now(UTC)
        logger.exception("vulnerability_refresh.background_failed", job_name=job_name, error=str(exc))
        publish_job_failed(job_name, started_at, finished_at, error=str(exc))
        return

    finished_at = datetime.now(UTC)
    try:
        result_payload = result.model_dump(by_alias=True, mode="json")
    except Exception:  # pragma: no cover - defensive
        result_payload = {"requested": payload.vuln_ids, "results": []}
    publish_job_completed(
        job_name,
        started_at,
        finished_at,
        **result_payload,
    )


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
    # Advanced filters
    severity: list[str] = Query(default_factory=list),
    epss_score_min: float | None = Query(default=None, alias="epssScoreMin"),
    epss_score_max: float | None = Query(default=None, alias="epssScoreMax"),
    assigner: list[str] = Query(default_factory=list),
    cwes: list[str] = Query(default_factory=list),
    sources: list[str] = Query(default_factory=list),
    cvss_version: str | None = Query(default=None, alias="cvssVersion"),
    cvss_score_min: float | None = Query(default=None, alias="cvssScoreMin"),
    cvss_score_max: float | None = Query(default=None, alias="cvssScoreMax"),
    attack_vector: list[str] = Query(default_factory=list, alias="attackVector"),
    attack_complexity: list[str] = Query(default_factory=list, alias="attackComplexity"),
    attack_requirements: list[str] = Query(default_factory=list, alias="attackRequirements"),
    privileges_required: list[str] = Query(default_factory=list, alias="privilegesRequired"),
    user_interaction: list[str] = Query(default_factory=list, alias="userInteraction"),
    scope: list[str] = Query(default_factory=list),
    confidentiality_impact: list[str] = Query(default_factory=list, alias="confidentialityImpact"),
    integrity_impact: list[str] = Query(default_factory=list, alias="integrityImpact"),
    availability_impact: list[str] = Query(default_factory=list, alias="availabilityImpact"),
    published_from: str | None = Query(default=None, alias="publishedFrom"),
    published_to: str | None = Query(default=None, alias="publishedTo"),
    tz: str | None = Query(
        default=None,
        description="IANA timezone applied to date-range clauses in DQL (e.g. 'Europe/Vienna').",
    ),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> PagedVulnerabilityResponse:
    max_window = settings.opensearch_index_max_result_window
    max_offset = max(0, max_window - limit)
    offset = min(offset, max_offset)

    query = VulnerabilityQuery(
        searchTerm=search,
        dqlQuery=dql,
        vendorFilters=vendorFilters,
        productFilters=productFilters,
        vendorSlugs=vendorSlugs,
        productSlugs=productSlugs,
        versionFilters=versionFilters,
        severity=severity,
        limit=limit,
        includeRejected=include_rejected,
        includeReserved=include_reserved,
        exploitedOnly=exploited_only,
        aiAnalysedOnly=ai_analysed_only,
        epssScoreMin=epss_score_min,
        epssScoreMax=epss_score_max,
        assigner=assigner,
        cwes=cwes,
        sources=sources,
        cvssVersion=cvss_version,
        cvssScoreMin=cvss_score_min,
        cvssScoreMax=cvss_score_max,
        attackVector=attack_vector,
        attackComplexity=attack_complexity,
        attackRequirements=attack_requirements,
        privilegesRequired=privileges_required,
        userInteraction=user_interaction,
        scope=scope,
        confidentialityImpact=confidentiality_impact,
        integrityImpact=integrity_impact,
        availabilityImpact=availability_impact,
        publishedFrom=published_from,
        publishedTo=published_to,
        tz=tz,
    )
    result = await service.search_paginated(query, limit=limit, offset=offset)
    result.max_offset = max_offset
    return result


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
async def list_ai_providers(
    ai_client: AIClient = Depends(get_ai_client),
) -> list[AIProviderInfo]:
    return ai_client.get_available_providers()


@router.get("/{identifier}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    identifier: str,
    service: VulnerabilityService = Depends(get_vulnerability_service),
    inventory_service: InventoryService = Depends(get_inventory_service),
) -> VulnerabilityDetail:
    """
    Retrieve a single vulnerability by its canonical identifier (CVE or source ID).
    """
    result = await service.get_by_id(identifier)
    if result is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    try:
        affected = await inventory_service.affected_inventory_for_vuln(result)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "inventory.affected_lookup_failed",
            vuln_id=identifier,
            error=str(exc),
        )
        affected = []
    if affected:
        result.affected_inventory = [a.model_dump(by_alias=True) for a in affected]
    return result


@router.post(
    "/{identifier}/ai-investigation",
    response_model=AIInvestigationSubmitResponse,
    status_code=202,
)
async def create_ai_investigation(
    identifier: str,
    payload: AIInvestigationRequest,
    request: Request,
    _: None = Depends(_require_ai_analysis_password),
    service: VulnerabilityService = Depends(get_vulnerability_service),
    ai_client: AIClient = Depends(get_ai_client),
    audit_service: AuditService = Depends(get_audit_service),
    inventory_service: InventoryService = Depends(get_inventory_service),
) -> AIInvestigationSubmitResponse:
    vulnerability = await service.get_by_id(identifier)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    try:
        affected = await inventory_service.affected_inventory_for_vuln(vulnerability)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "inventory.ai_lookup_failed",
            vuln_id=identifier,
            error=str(exc),
        )
        affected = []
    affected_inventory_payload = [a.model_dump(by_alias=True) for a in affected]

    # Validate provider before launching background task
    try:
        if payload.provider == "openai" and not settings.openai_api_key:
            raise ValueError("OpenAI provider is not configured.")
        if payload.provider == "anthropic" and not settings.anthropic_api_key:
            raise ValueError("Anthropic provider is not configured.")
        if payload.provider == "gemini" and not settings.google_gemini_api_key:
            raise ValueError("Google Gemini provider is not configured.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    client_ip = get_client_ip(request)

    asyncio.create_task(
        _run_ai_investigation_background(
            identifier=identifier,
            vulnerability=vulnerability,
            provider=payload.provider,
            language=payload.language,
            additional_context=payload.additional_context,
            triggered_by=payload.triggered_by,
            client_ip=client_ip,
            ai_client=ai_client,
            service=service,
            audit_service=audit_service,
            affected_inventory=affected_inventory_payload,
        )
    )

    return AIInvestigationSubmitResponse(status="running", vulnerabilityId=identifier)


async def _run_ai_investigation_background(
    *,
    identifier: str,
    vulnerability: VulnerabilityDetail,
    provider: str,
    language: str | None,
    additional_context: str | None,
    triggered_by: str | None,
    client_ip: str | None,
    ai_client: AIClient,
    service: VulnerabilityService,
    audit_service: AuditService,
    affected_inventory: list[dict[str, Any]] | None = None,
) -> None:
    job_name = f"ai_investigation_{identifier}"
    started_at = datetime.now(tz=UTC)
    publish_job_started(job_name, started_at, provider=provider, vulnerabilityId=identifier)

    try:
        result = await ai_client.analyze_vulnerability(
            provider,
            vulnerability,
            language=language,
            additional_context=additional_context,
            triggered_by=triggered_by,
            affected_inventory=affected_inventory,
        )

        assessment_payload = result.model_dump(by_alias=True)
        await service.save_ai_assessment(identifier, assessment_payload)

        metadata: dict[str, Any] = {
            "label": "AI-Analyse abgeschlossen",
            "clientIp": client_ip,
            "provider": provider,
        }
        metadata = {k: v for k, v in metadata.items() if v}
        result_payload: dict[str, Any] = {
            "vulnerabilityId": identifier,
            "language": result.language,
            "summary": result.summary,
        }
        if result.token_usage:
            result_payload["tokenUsage"] = result.token_usage
        await audit_service.record_event(
            "ai_investigation",
            metadata=metadata or None,
            result=result_payload,
        )

        finished_at = datetime.now(tz=UTC)
        publish_job_completed(job_name, started_at, finished_at, provider=provider, vulnerabilityId=identifier)
    except Exception as exc:
        finished_at = datetime.now(tz=UTC)
        logger.error("Background AI investigation failed", identifier=identifier, error=str(exc))
        publish_job_failed(job_name, started_at, finished_at, error=str(exc))


@router.post(
    "/ai-investigation/batch",
    response_model=AIBatchInvestigationSubmitResponse,
    status_code=202,
)
async def create_batch_ai_investigation(
    payload: AIBatchInvestigationRequest,
    request: Request,
    _: None = Depends(_require_ai_analysis_password),
    service: VulnerabilityService = Depends(get_vulnerability_service),
    ai_client: AIClient = Depends(get_ai_client),
    audit_service: AuditService = Depends(get_audit_service),
    inventory_service: InventoryService = Depends(get_inventory_service),
) -> AIBatchInvestigationSubmitResponse:
    """
    Analyze multiple vulnerabilities together for combined insights.
    Maximum 10 vulnerabilities per request.
    """
    # Fetch all vulnerabilities before launching background task
    vulnerabilities: list[VulnerabilityDetail] = []
    for vuln_id in payload.vulnerability_ids:
        vuln = await service.get_by_id(vuln_id)
        if vuln is None:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability {vuln_id} not found",
            )
        vulnerabilities.append(vuln)

    client_ip = get_client_ip(request)

    inventory_map: dict[str, list[dict[str, Any]]] = {}
    try:
        for vuln in vulnerabilities:
            affected = await inventory_service.affected_inventory_for_vuln(vuln)
            if affected:
                inventory_map[vuln.vuln_id] = [a.model_dump(by_alias=True) for a in affected]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "inventory.batch_lookup_failed",
            error=str(exc),
        )
        inventory_map = {}

    asyncio.create_task(
        _run_batch_ai_investigation_background(
            vulnerability_ids=payload.vulnerability_ids,
            vulnerabilities=vulnerabilities,
            provider=payload.provider,
            language=payload.language,
            additional_context=payload.additional_context,
            triggered_by=payload.triggered_by,
            client_ip=client_ip,
            ai_client=ai_client,
            service=service,
            audit_service=audit_service,
            affected_inventory_map=inventory_map,
        )
    )

    return AIBatchInvestigationSubmitResponse(
        status="running", vulnerabilityIds=payload.vulnerability_ids
    )


async def _run_batch_ai_investigation_background(
    *,
    vulnerability_ids: list[str],
    vulnerabilities: list[VulnerabilityDetail],
    provider: str,
    language: str | None,
    additional_context: str | None,
    triggered_by: str | None,
    client_ip: str | None,
    ai_client: AIClient,
    service: VulnerabilityService,
    audit_service: AuditService,
    affected_inventory_map: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    job_name = "ai_batch_investigation"
    started_at = datetime.now(tz=UTC)
    publish_job_started(job_name, started_at, provider=provider, vulnerabilityIds=vulnerability_ids)

    try:
        result = await ai_client.analyze_vulnerabilities_batch(
            provider,
            vulnerabilities,
            language=language,
            additional_context=additional_context,
            triggered_by=triggered_by,
            affected_inventory_map=affected_inventory_map,
        )

        batch_id = await service.save_batch_analysis(
            vulnerability_ids=vulnerability_ids,
            provider=provider,
            language=result.language,
            summary=result.summary,
            individual_summaries=result.individual_summaries,
            additional_context=additional_context,
            token_usage=result.token_usage,
            triggered_by=triggered_by,
        )

        metadata: dict[str, Any] = {
            "label": "AI Batch-Analyse abgeschlossen",
            "clientIp": client_ip,
            "provider": provider,
            "vulnerabilityCount": len(vulnerabilities),
            "batchId": batch_id,
        }
        metadata = {k: v for k, v in metadata.items() if v}
        result_payload: dict[str, Any] = {
            "batchId": batch_id,
            "vulnerabilityIds": vulnerability_ids,
            "language": result.language,
            "vulnerabilityCount": result.vulnerability_count,
        }
        if result.token_usage:
            result_payload["tokenUsage"] = result.token_usage
        await audit_service.record_event(
            "ai_batch_investigation",
            metadata=metadata or None,
            result=result_payload,
        )

        finished_at = datetime.now(tz=UTC)
        publish_job_completed(
            job_name, started_at, finished_at,
            provider=provider, batchId=batch_id, vulnerabilityIds=vulnerability_ids,
        )
    except Exception as exc:
        finished_at = datetime.now(tz=UTC)
        logger.error("Background batch AI investigation failed", error=str(exc))
        publish_job_failed(job_name, started_at, finished_at, error=str(exc))


@router.get("/ai-investigation/batch", response_model=dict[str, Any])
async def list_batch_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(_require_ai_analysis_password),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, Any]:
    """
    List recent batch AI analyses with pagination.
    """
    return await service.list_batch_analyses(limit=limit, offset=offset)


@router.get("/ai-investigation/batch/{batch_id}", response_model=dict[str, Any])
async def get_batch_analysis(
    batch_id: str,
    _: None = Depends(_require_ai_analysis_password),
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
    _: None = Depends(_require_ai_analysis_password),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, Any]:
    """
    List vulnerabilities with single AI analyses, sorted by most recent.
    """
    return await service.list_single_ai_analyses(limit=limit, offset=offset)


@router.get("/{identifier}/attack-path", response_model=AttackPathResponse)
async def get_attack_path(
    identifier: str,
    package: str | None = Query(default=None, description="Package name from a scan finding."),
    version: str | None = Query(default=None, description="Package version from a scan finding."),
    scan_id: str | None = Query(default=None, alias="scanId"),
    target_id: str | None = Query(default=None, alias="targetId"),
    language: str = Query(default="en", description="UI language (en/de) for graph labels."),
    service: VulnerabilityService = Depends(get_vulnerability_service),
    inventory_service: InventoryService = Depends(get_inventory_service),
    attack_path_service: AttackPathService = Depends(get_attack_path_service),
) -> AttackPathResponse:
    """Compute the deterministic attack-path graph for a vulnerability and return the
    persisted AI narrative (if any). The graph is always computed live from the latest
    catalog data; the narrative is read-only here (use POST to (re)generate it).

    The optional ``package``/``version``/``scanId``/``targetId`` query params enrich the
    graph with scan-finding context (entry node + package node) when called from the
    Scan Detail page; for the Vulnerability Detail tab they are omitted.
    """
    vulnerability = await service.get_by_id(identifier)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Hydrate inventory so the graph (and any business-impact label) reflects user assets.
    affected_inventory_payload: list[dict[str, Any]] = []
    try:
        affected = await inventory_service.affected_inventory_for_vuln(vulnerability)
        affected_inventory_payload = [a.model_dump(by_alias=True) for a in affected]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "attack_path.inventory_lookup_failed",
            vuln_id=identifier,
            error=str(exc),
        )

    scan_target = None
    if scan_id or target_id:
        scan_target = target_id or scan_id

    graph = await attack_path_service.build_graph(
        vulnerability,
        package_name=package,
        package_version=version,
        scan_target=scan_target,
        affected_inventory=affected_inventory_payload,
        language=language,
    )

    narrative_payload = vulnerability.attack_path
    narrative_obj: AttackPathNarrative | None = None
    if isinstance(narrative_payload, dict) and narrative_payload.get("summary"):
        try:
            narrative_obj = AttackPathNarrative.model_validate(narrative_payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "attack_path.narrative_validate_failed",
                vuln_id=identifier,
                error=str(exc),
            )

    return AttackPathResponse(
        vulnerabilityId=identifier,
        graph=graph,
        narrative=narrative_obj,
    )


@router.post(
    "/{identifier}/attack-path",
    response_model=AttackPathSubmitResponse,
    status_code=202,
)
async def create_attack_path_analysis(
    identifier: str,
    payload: AttackPathRequest,
    request: Request,
    _: None = Depends(_require_ai_analysis_password),
    service: VulnerabilityService = Depends(get_vulnerability_service),
    ai_client: AIClient = Depends(get_ai_client),
    audit_service: AuditService = Depends(get_audit_service),
    inventory_service: InventoryService = Depends(get_inventory_service),
    attack_path_service: AttackPathService = Depends(get_attack_path_service),
) -> AttackPathSubmitResponse:
    """Kick off AI generation of an attack-path narrative aligned with the deterministic
    graph. The narrative is appended to ``attack_paths[]`` and mirrored on
    ``attack_path``. Subscribe to SSE ``attack_path_{identifier}`` for completion.
    """
    vulnerability = await service.get_by_id(identifier)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Validate provider before launching background task (mirror create_ai_investigation).
    try:
        if payload.provider == "openai" and not settings.openai_api_key:
            raise ValueError("OpenAI provider is not configured.")
        if payload.provider == "anthropic" and not settings.anthropic_api_key:
            raise ValueError("Anthropic provider is not configured.")
        if payload.provider == "gemini" and not settings.google_gemini_api_key:
            raise ValueError("Google Gemini provider is not configured.")
        if payload.provider == "openai-compatible" and (
            not settings.openai_compatible_base_url or not settings.openai_compatible_model
        ):
            raise ValueError("OpenAI-compatible provider is not configured.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    affected_inventory_payload: list[dict[str, Any]] = []
    try:
        affected = await inventory_service.affected_inventory_for_vuln(vulnerability)
        affected_inventory_payload = [a.model_dump(by_alias=True) for a in affected]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "attack_path.inventory_lookup_failed",
            vuln_id=identifier,
            error=str(exc),
        )

    client_ip = get_client_ip(request)

    asyncio.create_task(
        _run_attack_path_background(
            identifier=identifier,
            vulnerability=vulnerability,
            provider=payload.provider,
            language=payload.language,
            additional_context=payload.additional_context,
            triggered_by=payload.triggered_by,
            client_ip=client_ip,
            ai_client=ai_client,
            service=service,
            audit_service=audit_service,
            attack_path_service=attack_path_service,
            affected_inventory=affected_inventory_payload,
        )
    )

    return AttackPathSubmitResponse(status="running", vulnerabilityId=identifier)


async def _run_attack_path_background(
    *,
    identifier: str,
    vulnerability: VulnerabilityDetail,
    provider: str,
    language: str | None,
    additional_context: str | None,
    triggered_by: str | None,
    client_ip: str | None,
    ai_client: AIClient,
    service: VulnerabilityService,
    audit_service: AuditService,
    attack_path_service: AttackPathService,
    affected_inventory: list[dict[str, Any]] | None = None,
) -> None:
    job_name = f"attack_path_{identifier}"
    started_at = datetime.now(tz=UTC)
    publish_job_started(job_name, started_at, provider=provider, vulnerabilityId=identifier)

    try:
        graph = await attack_path_service.build_graph(
            vulnerability,
            affected_inventory=affected_inventory,
            language=language or "en",
        )

        narrative = await ai_client.analyze_attack_path(
            provider,
            vulnerability,
            graph.model_dump(by_alias=True),
            language=language,
            additional_context=additional_context,
            triggered_by=triggered_by,
            affected_inventory=affected_inventory,
        )

        narrative_payload = narrative.model_dump(by_alias=True)
        await service.save_attack_path(identifier, narrative_payload)

        metadata: dict[str, Any] = {
            "label": "Attack Path narrative generated",
            "clientIp": client_ip,
            "provider": provider,
        }
        metadata = {k: v for k, v in metadata.items() if v}
        result_payload: dict[str, Any] = {
            "vulnerabilityId": identifier,
            "language": narrative.language,
            "summaryExcerpt": (narrative.summary or "")[:200],
        }
        if narrative.token_usage:
            result_payload["tokenUsage"] = narrative.token_usage
        await audit_service.record_event(
            "attack_path_analysis",
            metadata=metadata or None,
            result=result_payload,
        )

        finished_at = datetime.now(tz=UTC)
        publish_job_completed(
            job_name, started_at, finished_at, provider=provider, vulnerabilityId=identifier
        )
    except Exception as exc:
        finished_at = datetime.now(tz=UTC)
        logger.error("Background attack-path analysis failed", identifier=identifier, error=str(exc))
        publish_job_failed(job_name, started_at, finished_at, error=str(exc))
