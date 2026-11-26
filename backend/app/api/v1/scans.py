from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.api.openapi_docs import download
from app.core.config import settings
from app.core.passwords import hash_password
from app.repositories.license_policy_repository import LicensePolicyRepository
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.scan_sbom_repository import ScanSbomRepository
from app.schemas.license_policy import (
    LicenseComplianceResultResponse,
    LicenseOverviewItem,
    LicenseOverviewResponse,
)
from app.schemas.scan import (
    ConsolidatedAlertListResponse,
    ConsolidatedAlertResponse,
    ConsolidatedFindingListResponse,
    ConsolidatedFindingResponse,
    ConsolidatedSbomListResponse,
    ConsolidatedSbomResponse,
    ConsolidatedTargetSchema,
    ImportSbomRequest,
    SbomComponentListResponse,
    SbomComponentResponse,
    ScanComparisonChangedSchema,
    ScanComparisonFindingSchema,
    ScanComparisonResponse,
    ScanFindingListResponse,
    ScanFindingResponse,
    ScanHistoryEntrySchema,
    ScanHistoryResponse,
    ScanLayerAnalysisResponse,
    ScanLayerDetailSchema,
    ScanListResponse,
    ScanReleaseEntry,
    ScanReleaseListResponse,
    ScanReleaseRequest,
    ScanReleaseSchema,
    ScanResponse,
    ScanSummarySchema,
    ScanTargetCreateRequest,
    ScanTargetGroupListResponse,
    ScanTargetGroupSchema,
    ScanTargetListResponse,
    ScanTargetResponse,
    ScanTargetUpdateRequest,
    TargetExposure,
    TargetKind,
    SubmitScanRequest,
    SubmitScanResponse,
    SupplyChainSummarySchema,
    TargetSbomDiffResponse,
    TargetVexSourcesRequest,
    TargetWritePasswordRequest,
    TARGET_NAME_MAX_LENGTH,
    normalize_target_name,
)
from app.schemas.vex import (
    FindingsDismissRequest,
    VexBulkUpdateByIdsRequest,
    VexBulkUpdateRequest,
    VexBulkUpdateResponse,
    VexImportRequest,
    VexImportResponse,
    VexUpdateRequest,
    VexUpdateResponse,
)
from app.core.write_auth import (
    require_admin_write,
    require_ai_target_write_scan,
    require_editor_write,
    require_target_password_change,
    require_target_write_body_finding_ids,
    require_target_write_body_target,
    require_target_write_finding,
    require_target_write_manual_scan,
    require_target_write_path,
    require_target_write_scan,
    require_target_write_sbom_import,
    require_target_write_sbom_upload,
    resolve_target_id_path,
    verify_sca_api_key,
)
from app.schemas.ai import AIScanAnalysisRequest, AIScanAnalysisSubmitResponse
from app.schemas.scan_attack_chain import (
    ScanAttackChainRequest,
    ScanAttackChainResponse,
    ScanAttackChainSubmitResponse,
)
from app.services.ai_history import previous_scan_analyses
from app.services.ai_service import AIClient, get_ai_client
from app.services.event_bus import publish_job_completed, publish_job_failed, publish_job_started
from app.services.scan_attack_chain_service import (
    ScanAttackChainService,
    get_scan_attack_chain_service,
)
from app.services.license_compliance_service import LicenseComplianceService
from app.services.scan_checks import is_check_target
from app.services.scan_service import ScanService, get_scan_service
from app.services.vex_service import VexService
from app.services.vex_review import review_state

import asyncio

import structlog

_ai_scan_logger = structlog.get_logger()

router = APIRouter()


def _validate_source_archive_payload(source_archive_base64: str | None) -> None:
    if not source_archive_base64:
        return

    try:
        archive_bytes = base64.b64decode(source_archive_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="sourceArchiveBase64 is not valid base64")
    if len(archive_bytes) > settings.sca_source_archive_max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Archive too large (max {settings.sca_source_archive_max_bytes // (1024 * 1024)} MB)",
        )
    if not archive_bytes:
        raise HTTPException(status_code=400, detail="Uploaded archive is empty")


# --- Scan submission ---


@router.post("", response_model=SubmitScanResponse, status_code=201)
async def submit_scan(
    request: SubmitScanRequest,
    _auth: None = Depends(verify_sca_api_key),
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Submit a scan request. Triggers the scanner sidecar and returns results."""
    if not settings.sca_enabled:
        raise HTTPException(status_code=503, detail="SCA scanning is disabled")

    if request.type not in ("container_image", "source_repo"):
        raise HTTPException(status_code=400, detail="type must be 'container_image' or 'source_repo'")

    _validate_source_archive_payload(request.source_archive_base64)
    try:
        result = await service.submit_scan(
            target=request.target,
            target_type=request.type,
            scanners=request.scanners,
            source=request.source,
            commit_sha=request.commit_sha,
            branch=request.branch,
            pipeline_url=request.pipeline_url,
            source_archive_base64=request.source_archive_base64,
            one_time=request.is_check,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SubmitScanResponse(
        scan_id=result["scan_id"],
        target_id=result["target_id"],
        status=result["status"],
        findings_count=result["findings_count"],
        sbom_component_count=result["sbom_component_count"],
        summary=ScanSummarySchema(**result["summary"]),
        error=result.get("error"),
        check=result.get("check", False),
        expires_at=result.get("expires_at"),
    )


@router.post("/manual", response_model=SubmitScanResponse, status_code=201)
async def submit_manual_scan(
    request: SubmitScanRequest,
    _auth: None = Depends(require_target_write_manual_scan),
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Submit a manual scan from the UI (no API key required)."""
    if not settings.sca_enabled:
        raise HTTPException(status_code=503, detail="SCA scanning is disabled")

    if request.type not in ("container_image", "source_repo"):
        raise HTTPException(status_code=400, detail="type must be 'container_image' or 'source_repo'")

    _validate_source_archive_payload(request.source_archive_base64)

    try:
        result = await service.submit_scan(
            target=request.target,
            target_type=request.type,
            scanners=request.scanners,
            source="manual",
            source_archive_base64=request.source_archive_base64,
            one_time=request.is_check,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return SubmitScanResponse(
        scan_id=result["scan_id"],
        target_id=result["target_id"],
        status=result["status"],
        findings_count=result["findings_count"],
        sbom_component_count=result["sbom_component_count"],
        summary=ScanSummarySchema(**result["summary"]),
        error=result.get("error"),
        check=result.get("check", False),
        expires_at=result.get("expires_at"),
    )


# --- Scan targets ---


@router.get("/targets", response_model=ScanTargetListResponse)
async def list_targets(
    type: str | None = Query(default=None, description="Filter by type: container_image or source_repo"),
    group: str | None = Query(default=None, description="Filter by application/group name; empty string for ungrouped"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetListResponse:
    total, items = await service.list_targets(
        type_filter=type, group_filter=group, limit=limit, offset=offset,
    )
    return ScanTargetListResponse(
        total=total,
        items=[_map_target(item) for item in items],
    )


@router.get("/targets/groups", response_model=ScanTargetGroupListResponse)
async def list_target_groups(
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetGroupListResponse:
    """List distinct target groups (applications) with rolled-up severity totals."""
    items = await service.list_target_groups()
    return ScanTargetGroupListResponse(
        items=[
            ScanTargetGroupSchema(
                group=item.get("group"),
                target_count=item.get("target_count", 0),
                latest_summary=ScanSummarySchema(**item.get("latest_summary", {})),
            )
            for item in items
        ],
    )


@router.get("/targets/{target_id:path}/history", response_model=ScanHistoryResponse)
async def get_target_history(
    target_id: str = Depends(resolve_target_id_path),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, description="Skip this many of the most-recent scans (pagination)"),
    since: datetime | None = Query(default=None, description="Only return scans started after this ISO datetime"),
    service: ScanService = Depends(get_scan_service),
) -> ScanHistoryResponse:
    """Get scan history for a target (charts use the default page; the target
    detail table paginates with ``offset`` + the returned ``total``)."""
    items = await service.get_target_history(target_id, limit=limit, since=since, offset=offset)
    total = await service.count_target_history(target_id, since=since)
    return ScanHistoryResponse(
        target_id=target_id,
        total=total,
        items=[
            ScanHistoryEntrySchema(
                scan_id=str(item.get("_id", "")),
                started_at=item.get("started_at"),
                status=item.get("status", ""),
                summary=ScanSummarySchema(**(item.get("summary", {}))),
                duration_seconds=item.get("duration_seconds"),
                commit_sha=item.get("commit_sha"),
            )
            for item in items
        ],
    )


@router.get("/targets/{target_id:path}/shield")
async def get_target_shield(
    target_id: str = Depends(resolve_target_id_path),
    label: str = Query(default="findings", max_length=64),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    """shields.io endpoint badge for a target's latest completed scan."""
    latest = await service.scan_repo.get_latest_by_target(target_id)
    if not latest:
        return _shield_payload("hecate", "no scans", "lightgrey", is_error=True)
    scan = await service.get_scan(str(latest.get("_id")))
    if not scan:
        return _shield_payload("hecate", "no scans", "lightgrey", is_error=True)
    return _render_scan_shield(scan, label)


# Declared before the bare ``/targets/{target_id:path}`` GET so the greedy path
# converter doesn't capture ``/sbom-diff`` as part of the target id.
@router.get("/targets/{target_id:path}/sbom-diff", response_model=TargetSbomDiffResponse)
async def get_target_sbom_diff(
    target_id: str = Depends(resolve_target_id_path),
    service: ScanService = Depends(get_scan_service),
) -> TargetSbomDiffResponse:
    """SBOM delta (added/updated/removed components) for a target — always the
    most recent scan whose SBOM actually changed, even if trailing rescans
    since then had no dependency movement."""
    diff = await service.get_target_sbom_diff(target_id)
    return TargetSbomDiffResponse(**diff)


# Declared before the bare ``/targets/{target_id:path}`` GET (greedy path converter).
@router.get("/targets/{target_id:path}/releases", response_model=ScanReleaseListResponse)
async def list_target_releases(
    target_id: str = Depends(resolve_target_id_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanReleaseListResponse:
    """Scans of a target marked as releases, newest marker first."""
    from app.services.scan_release import list_releases

    items = []
    for doc in await list_releases(service.scan_repo, target_id):
        release = doc.get("release") or {}
        summary = doc.get("summary")
        items.append(ScanReleaseEntry(
            scan_id=str(doc.get("_id", "")),
            label=str(release.get("label") or ""),
            note=release.get("note"),
            marked_at=release.get("marked_at"),
            status=doc.get("status"),
            started_at=doc.get("started_at"),
            finished_at=doc.get("finished_at"),
            commit_sha=doc.get("commit_sha"),
            image_ref=doc.get("image_ref"),
            branch=doc.get("branch"),
            summary=ScanSummarySchema(**summary) if isinstance(summary, dict) else ScanSummarySchema(),
            sbom_component_count=doc.get("sbom_component_count"),
        ))
    return ScanReleaseListResponse(items=items)


# Write-password management: the admin, or the owner with the current target password. Declared before the
# bare ``/targets/{target_id:path}`` routes so the greedy path converter on the
# bare DELETE doesn't swallow ``/write-password`` as part of the target id.


@router.put("/targets/{target_id:path}/write-password", response_model=ScanTargetResponse)
async def set_target_write_password(
    request: TargetWritePasswordRequest,
    target_id: str = Depends(resolve_target_id_path),
    _auth: None = Depends(require_target_password_change),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Set or replace the per-target write password: the admin, or the owner with the current one."""
    target = await service.target_repo.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    await service.target_repo.set_write_password(target_id, hash_password(request.password))
    refreshed = await service.get_target(target_id)
    return _map_target(refreshed)


@router.delete("/targets/{target_id:path}/write-password", response_model=ScanTargetResponse)
async def clear_target_write_password(
    target_id: str = Depends(resolve_target_id_path),
    _auth: None = Depends(require_target_password_change),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Clear the per-target write password: the admin, or the owner with the current one."""
    target = await service.target_repo.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    await service.target_repo.set_write_password(target_id, None)
    refreshed = await service.get_target(target_id)
    return _map_target(refreshed)


@router.put("/targets/{target_id:path}/vex-sources", response_model=ScanTargetResponse)
async def set_target_vex_sources(
    request: TargetVexSourcesRequest,
    target_id: str = Depends(resolve_target_id_path),
    _auth: None = Depends(require_target_write_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Set the target's VEX source URLs and apply them to its findings right away."""
    from app.services.vex_source_service import normalize_vex_source_urls

    try:
        urls = normalize_vex_source_urls(request.urls)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not await service.target_repo.set_vex_sources(target_id, urls):
        raise HTTPException(status_code=404, detail="Scan target not found")
    if urls:
        await service.apply_vex_sources(target_id)
    else:
        # Without sources, the statuses they set have no owner any more.
        await service.finding_repo.clear_vex_source_statuses(target_id, [])
    return _map_target(await service.get_target(target_id))


@router.post("/targets/{target_id:path}/vex-sources/apply", response_model=ScanTargetResponse)
async def apply_target_vex_sources(
    target_id: str = Depends(resolve_target_id_path),
    _auth: None = Depends(require_target_write_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Fetch the target's VEX sources again and apply them now."""
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    if not target.get("vex_sources"):
        raise HTTPException(status_code=400, detail="This target has no VEX sources")
    await service.apply_vex_sources(target_id)
    return _map_target(await service.get_target(target_id))


@router.get("/targets/{target_id:path}", response_model=ScanTargetResponse)
async def get_target(
    target_id: str = Depends(resolve_target_id_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    return _map_target(target)


@router.post("/targets", response_model=ScanTargetResponse, status_code=201)
async def create_target(
    request: ScanTargetCreateRequest,
    # A new target: the system password, or a signed-in editor.
    _auth: None = Depends(require_editor_write),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Register a scan target manually."""
    from app.models.scan import ScanTargetDocument

    target_id = service._derive_target_id(request.target, request.type)
    name = request.name or service._derive_target_name(request.target)

    target_doc = ScanTargetDocument(
        target_id=target_id,
        type=request.type,
        name=name,
        registry=request.registry,
        repository_url=request.repository_url,
        description=request.description,
        tags=request.tags,
        group=(request.group.strip() or None) if isinstance(request.group, str) else None,
    )
    await service.target_repo.upsert(target_doc)
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=500, detail="Failed to create target")
    return _map_target(target)


@router.patch("/targets/{target_id:path}", response_model=ScanTargetResponse)
async def update_target(
    target_id: str = Depends(resolve_target_id_path),
    body: ScanTargetUpdateRequest | None = None,
    _auth: None = Depends(require_target_write_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Update target settings. Only the fields sent change; ``group`` and
    ``trufflehogVerification`` take null to clear."""
    sent = body.model_fields_set if body else set()
    if "name" in sent:
        name = normalize_target_name(body.name)
        if name is None:
            raise HTTPException(status_code=400, detail=f"name must be 1 to {TARGET_NAME_MAX_LENGTH} characters")
        if not await service.rename_target(target_id, name):
            raise HTTPException(status_code=404, detail="Scan target not found")
    if "auto_scan" in sent and body.auto_scan is not None:
        await service.update_target_auto_scan(target_id, body.auto_scan)
    if "scanners" in sent and body.scanners is not None:
        try:
            await service.update_target_scanners(target_id, body.scanners)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if "group" in sent:
        await service.update_target_group(target_id, body.group)
    if "trufflehog_verification" in sent:
        await service.update_target_trufflehog_verification(target_id, body.trufflehog_verification)
    if "no_external_lookups" in sent and body.no_external_lookups is not None:
        await service.update_target_no_external_lookups(target_id, body.no_external_lookups)
    classification = {field: getattr(body, field) for field in ("kind", "exposure") if field in sent}
    if classification:
        await service.target_repo.update_classification(target_id, classification)
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    return _map_target(target)


@router.delete("/targets/{target_id:path}", status_code=204)
async def delete_target(
    target_id: str = Depends(resolve_target_id_path),
    # Deleting takes the system password, not the target's: a target password
    # opens every other write on the target, but losing its whole history is
    # the admin's call.
    _auth: None = Depends(require_admin_write),
    service: ScanService = Depends(get_scan_service),
) -> None:
    deleted = await service.delete_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan target not found")


@router.post("/targets/{target_id:path}/check", response_model=ScanTargetResponse)
async def trigger_target_check(
    target_id: str = Depends(resolve_target_id_path),
    _auth: None = Depends(require_target_write_path),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Force an out-of-band ``/check`` probe and refresh diagnostics.

    Powers the clickable verdict pill on the SCA Scans → Scanner tab —
    runs the same code path as the auto-scan scheduler's per-target probe
    (``ScanService.check_target_changed``), persists the new
    ``last_check_*`` fields, and returns the refreshed target. **Does not
    submit a scan** even when the verdict is ``changed``: this is a
    diagnostics tool, not a scan trigger; the user can trigger a scan
    separately via the Targets-tab card.
    """
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    target_type = target.get("type", "container_image")
    await service.check_target_changed(target_id, target_type, target)
    refreshed = await service.get_target(target_id)
    if not refreshed:
        raise HTTPException(status_code=404, detail="Scan target not found")
    return _map_target(refreshed)


# --- Scans ---


@router.get("", response_model=ScanListResponse)
async def list_scans(
    target_id: str | None = Query(default=None, alias="targetId", description="Filter by target"),
    status: str | None = Query(default=None, description="Filter by status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ScanListResponse:
    total, items = await service.list_scans(
        target_id=target_id, status=status, limit=limit, offset=offset
    )
    return ScanListResponse(
        total=total,
        items=[_map_scan(item) for item in items],
    )


# Static paths MUST come before /{scan_id} to avoid being swallowed by the dynamic route


@router.get("/scanner/stats")
async def get_scanner_stats(
    service: ScanService = Depends(get_scan_service),
) -> dict:
    """Proxy to scanner sidecar /stats for resource monitoring."""
    return await service.get_scanner_stats()


@router.get("/compare", response_model=ScanComparisonResponse)
async def compare_scans(
    scan_a: str = Query(alias="scanA", description="First scan ID"),
    scan_b: str = Query(alias="scanB", description="Second scan ID"),
    service: ScanService = Depends(get_scan_service),
) -> ScanComparisonResponse:
    """Compare two scans and return added/removed findings."""
    result = await service.compare_scans(scan_a, scan_b)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    summary_a = result.get("summary_a", {})
    summary_b = result.get("summary_b", {})
    return ScanComparisonResponse(
        scan_id_a=result["scan_id_a"],
        scan_id_b=result["scan_id_b"],
        summary_a=ScanSummarySchema(**summary_a) if isinstance(summary_a, dict) else ScanSummarySchema(),
        summary_b=ScanSummarySchema(**summary_b) if isinstance(summary_b, dict) else ScanSummarySchema(),
        added=[ScanComparisonFindingSchema(**f) for f in result.get("added", [])],
        removed=[ScanComparisonFindingSchema(**f) for f in result.get("removed", [])],
        changed=[ScanComparisonChangedSchema(**c) for c in result.get("changed", [])],
        unchanged_count=result.get("unchanged_count", 0),
    )


@router.get("/findings/by-cve/{cve_id}", response_model=ScanFindingListResponse)
async def get_findings_by_cve(
    cve_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ScanFindingListResponse:
    """Cross-reference: find scan findings that match a specific CVE."""
    total, items = await service.find_by_cve(cve_id, limit=limit, offset=offset)
    return ScanFindingListResponse(
        total=total,
        items=[_map_finding(item) for item in items],
    )


@router.get("/findings", response_model=ConsolidatedFindingListResponse)
async def get_global_findings(
    search: str | None = Query(default=None, description="Search by CVE, package name, or title"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    target_id: str | None = Query(default=None, alias="targetId", description="Filter by target"),
    sort_by: str = Query(default="cvss_score", alias="sortBy", description="Sort field"),
    sort_order: str = Query(default="desc", alias="sortOrder", description="Sort order: asc or desc"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ConsolidatedFindingListResponse:
    """Get consolidated findings from the latest completed scan of each target."""
    total, items = await service.get_global_findings(
        search=search, severity=severity, target_id=target_id,
        sort_by=sort_by, sort_order=sort_order, limit=limit, offset=offset,
    )
    return ConsolidatedFindingListResponse(
        total=total,
        items=[_map_consolidated_finding(item) for item in items],
    )


@router.get("/alerts", response_model=ConsolidatedAlertListResponse)
async def get_global_alerts(
    search: str | None = Query(default=None, description="Search by package name, title, or description"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    category: str | None = Query(default=None, description="Filter by Hecate malware-detector category"),
    target_id: str | None = Query(default=None, alias="targetId", description="Filter by target"),
    sort_by: str = Query(default="severity", alias="sortBy", description="Sort field"),
    sort_order: str = Query(default="desc", alias="sortOrder", description="Sort order: asc or desc"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ConsolidatedAlertListResponse:
    """Get consolidated Security Alerts (malicious-indicator findings) from the latest completed scan of each target."""
    total, items = await service.get_global_alerts(
        search=search, severity=severity, category=category, target_id=target_id,
        sort_by=sort_by, sort_order=sort_order, limit=limit, offset=offset,
    )
    return ConsolidatedAlertListResponse(
        total=total,
        items=[_map_consolidated_alert(item) for item in items],
    )


@router.get("/sbom", response_model=ConsolidatedSbomListResponse)
async def get_global_sbom(
    search: str | None = Query(default=None, description="Search by name, type, purl, or license"),
    type: str | None = Query(default=None, description="Filter by component type"),
    target_id: str | None = Query(default=None, alias="targetId", description="Filter by target"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ConsolidatedSbomListResponse:
    """Get consolidated SBOM components from the latest completed scan of each target."""
    total, items = await service.get_global_sbom(
        search=search, type_filter=type, target_id=target_id, limit=limit, offset=offset
    )
    return ConsolidatedSbomListResponse(
        total=total,
        items=[_map_consolidated_sbom(item) for item in items],
    )


@router.get("/sbom/facets")
async def get_global_sbom_facets(
    target_id: str | None = Query(default=None, alias="targetId"),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, list[dict[str, Any]]]:
    """Aggregated ecosystem/license/type counts across all SBOM components."""
    facets = await service.get_sbom_facets(target_id=target_id)
    return {
        key: [{"name": name, "count": count} for name, count in items]
        for key, items in facets.items()
    }


@router.get("/coverage")
async def get_dashboard_coverage(
    service: ScanService = Depends(get_scan_service),
) -> dict[str, dict[str, str]]:
    """Compact cross-reference maps for the dashboard "Today" SCA highlight.

    ``{"cveScan": {cveId: scanId}, "scanTargets": {scanId: targetName}}`` —
    each ``cveScan`` value is the most-recent scan (across targets) with a
    finding for the CVE, from the latest completed scan of every target.
    Version-checked SBOM hits ride on the CVE rows (``sbomScanId``). Cached
    server-side.
    """
    return await service.get_dashboard_coverage()


@router.post("/import-sbom", response_model=SubmitScanResponse, status_code=201)
async def import_sbom(
    request: ImportSbomRequest,
    _auth: None = Depends(require_target_write_sbom_import),
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Import an external SBOM file (CycloneDX or SPDX JSON)."""
    try:
        result = await service.import_sbom(
            sbom_data=request.sbom,
            format=request.format,
            target_name=request.target_name,
            target_id=request.target_id,
            check=request.check,
            kind=request.kind,
            exposure=request.exposure,
        )
        summary = result.get("summary")
        return SubmitScanResponse(
            scan_id=result["scan_id"],
            target_id=result["target_id"],
            status=result["status"],
            findings_count=result.get("findings_count", 0),
            sbom_component_count=result.get("sbom_component_count", 0),
            summary=ScanSummarySchema(**summary.model_dump()) if hasattr(summary, "model_dump") else ScanSummarySchema(),
            check=result.get("check", False),
            expires_at=result.get("expires_at"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import-sbom/upload", response_model=SubmitScanResponse, status_code=201)
async def import_sbom_upload(
    file: UploadFile = File(...),
    target_name: str | None = Query(default=None, alias="targetName"),
    format: str | None = Query(default=None),
    check: bool = Query(default=False, description="Import as a check: no target, report only, expires"),
    kind: TargetKind | None = Query(default=None, description="host, kubernetes-node, container or other"),
    exposure: TargetExposure | None = Query(default=None, description="internet or internal"),
    _auth: None = Depends(require_target_write_sbom_upload),
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Import an external SBOM file via multipart file upload."""

    limit = settings.sca_source_archive_max_bytes
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(status_code=413, detail=f"SBOM too large (max {limit // (1024 * 1024)} MB)")
    try:
        sbom_data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    try:
        result = await service.import_sbom(
            sbom_data=sbom_data,
            format=format,
            target_name=target_name,
            check=check,
            kind=kind,
            exposure=exposure,
        )
        summary = result.get("summary")
        return SubmitScanResponse(
            scan_id=result["scan_id"],
            target_id=result["target_id"],
            status=result["status"],
            findings_count=result.get("findings_count", 0),
            sbom_component_count=result.get("sbom_component_count", 0),
            summary=ScanSummarySchema(**summary.model_dump()) if hasattr(summary, "model_dump") else ScanSummarySchema(),
            check=result.get("check", False),
            expires_at=result.get("expires_at"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/badge-counts")
async def get_badge_counts(
    service: ScanService = Depends(get_scan_service),
) -> dict[str, int]:
    """Lightweight counts for tab badges (findings, SBOM, licenses)."""
    return await service.get_badge_counts()


@router.get("/license-overview", response_model=LicenseOverviewResponse)
async def get_license_overview(
    service: ScanService = Depends(get_scan_service),
) -> LicenseOverviewResponse:
    """Get aggregated license usage across the latest completed scan of each target."""
    scan_ids = await service.get_latest_completed_scan_ids()
    policy_repo = await LicensePolicyRepository.create()
    sbom_repo = await ScanSbomRepository.create()
    compliance_svc = LicenseComplianceService(policy_repo, sbom_repo)
    items = await compliance_svc.get_license_overview(scan_ids)
    return LicenseOverviewResponse(
        items=[LicenseOverviewItem(**item) for item in items],
        total=len(items),
    )


# --- VEX endpoints (static routes before dynamic) ---


@router.put("/vex/findings/{finding_id}", response_model=VexUpdateResponse)
async def update_finding_vex(
    finding_id: str,
    request: VexUpdateRequest,
    _auth: None = Depends(require_target_write_finding),
) -> VexUpdateResponse:
    """Update VEX status on a single finding. Pass null to clear."""
    valid_statuses = {"not_affected", "affected", "fixed", "under_investigation"}
    if request.vex_status is not None and request.vex_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid VEX status. Must be one of: {valid_statuses}")

    finding_repo = await ScanFindingRepository.create()
    success = await finding_repo.update_vex_status(
        finding_id=finding_id,
        vex_status=request.vex_status,
        vex_justification=request.vex_justification if request.vex_status else None,
        vex_detail=request.vex_detail if request.vex_status else None,
        vex_response=request.vex_response if request.vex_status else None,
        vex_review_due=request.vex_review_due if request.vex_status else None,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    return VexUpdateResponse(success=True, findingId=finding_id)


@router.post("/vex/bulk-update", response_model=VexBulkUpdateResponse)
async def bulk_update_vex(
    request: VexBulkUpdateRequest,
    _auth: None = Depends(require_target_write_body_target),
) -> VexBulkUpdateResponse:
    """Bulk-apply VEX status to all findings matching vulnerability + target."""
    valid_statuses = {"not_affected", "affected", "fixed", "under_investigation"}
    if request.vex_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid VEX status. Must be one of: {valid_statuses}")

    finding_repo = await ScanFindingRepository.create()
    count = await finding_repo.bulk_update_vex_by_vulnerability(
        target_id=request.target_id,
        vulnerability_id=request.vulnerability_id,
        vex_status=request.vex_status,
        vex_justification=request.vex_justification,
    )
    return VexBulkUpdateResponse(updated=count)


@router.post("/vex/bulk-update-by-ids", response_model=VexBulkUpdateResponse)
async def bulk_update_vex_by_ids(
    request: VexBulkUpdateByIdsRequest,
    _auth: None = Depends(require_target_write_body_finding_ids),
) -> VexBulkUpdateResponse:
    """Apply VEX status to a specific list of finding IDs (for multi-select bulk edit)."""
    valid_statuses = {"not_affected", "affected", "fixed", "under_investigation"}
    if request.vex_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid VEX status. Must be one of: {valid_statuses}")
    if not request.finding_ids:
        return VexBulkUpdateResponse(updated=0)

    finding_repo = await ScanFindingRepository.create()
    count = await finding_repo.bulk_update_vex_by_ids(
        finding_ids=request.finding_ids,
        vex_status=request.vex_status,
        vex_justification=request.vex_justification,
        vex_detail=request.vex_detail,
        vex_review_due=request.vex_review_due,
    )
    return VexBulkUpdateResponse(updated=count)


@router.post("/findings/dismiss", response_model=VexBulkUpdateResponse)
async def dismiss_findings(
    request: FindingsDismissRequest,
    _auth: None = Depends(require_target_write_body_finding_ids),
) -> VexBulkUpdateResponse:
    """Mark/unmark a list of findings as dismissed (personal-view filter, not VEX)."""
    if not request.finding_ids:
        return VexBulkUpdateResponse(updated=0)
    finding_repo = await ScanFindingRepository.create()
    count = await finding_repo.bulk_update_dismissed(
        finding_ids=request.finding_ids,
        dismissed=request.dismissed,
        reason=request.reason,
    )
    return VexBulkUpdateResponse(updated=count)


@router.post("/vex/import", response_model=VexImportResponse)
async def import_vex(
    request: VexImportRequest,
    _auth: None = Depends(require_target_write_body_target),
) -> VexImportResponse:
    """Import a CycloneDX VEX or OpenVEX document and apply it to matching findings."""
    finding_repo = await ScanFindingRepository.create()
    scan_repo = await ScanRepository.create()
    vex_service = VexService(finding_repo, scan_repo)
    try:
        result = await vex_service.import_vex_document(request.vex_document, request.target_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return VexImportResponse(**result)


# --- Dynamic scan routes ---


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    _auth: None = Depends(require_target_write_scan),
    service: ScanService = Depends(get_scan_service),
) -> dict:
    """Cancel a running scan."""
    cancelled = await service.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="No running scan found")
    return {"status": "cancelled", "scanId": scan_id}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: str,
    # Like deleting a target: system password only (see delete_target).
    _auth: None = Depends(require_admin_write),
    service: ScanService = Depends(get_scan_service),
) -> None:
    scan = await service.get_scan(scan_id)
    if scan and scan.get("release"):
        # Release evidence is kept until someone removes the marker on purpose.
        raise HTTPException(
            status_code=409,
            detail="This scan is marked as a release. Remove the release marker before deleting it.",
        )
    deleted = await service.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/ai-analyses")
async def list_scan_ai_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    """List scans that have at least one AI analysis, newest first."""
    return await service.list_scan_ai_analyses(limit=limit, offset=offset)


def _shield_payload(label: str, message: str, color: str, *, is_error: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": color,
        "cacheSeconds": 300,
    }
    if is_error:
        payload["isError"] = True
    return payload


def _render_scan_shield(scan: dict[str, Any], label: str) -> dict[str, Any]:
    status = scan.get("status")
    if status == "pending":
        return _shield_payload(label, "pending", "lightgrey")
    if status == "running":
        return _shield_payload(label, "scanning", "blue")
    if status == "failed":
        return _shield_payload(label, "scan failed", "red", is_error=True)

    s = scan.get("summary") or {}
    critical = int(s.get("critical") or 0)
    high = int(s.get("high") or 0)
    medium = int(s.get("medium") or 0)
    low = int(s.get("low") or 0)

    parts: list[str] = []
    if critical:
        parts.append(f"{critical}C")
    if high:
        parts.append(f"{high}H")
    if medium:
        parts.append(f"{medium}M")
    if low:
        parts.append(f"{low}L")
    message = " ".join(parts) if parts else "0 findings"

    if critical:
        color = "red"
    elif high:
        color = "orange"
    elif medium:
        color = "yellow"
    elif low:
        color = "yellowgreen"
    else:
        color = "brightgreen"

    return _shield_payload(label, message, color)


@router.get("/{scan_id}/shield")
async def get_scan_shield(
    scan_id: str,
    label: str = Query(default="findings", max_length=64),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    """shields.io endpoint badge for a scan. See https://shields.io/endpoint."""
    scan = await service.get_scan(scan_id)
    if not scan:
        return _shield_payload("hecate", "scan not found", "lightgrey", is_error=True)
    return _render_scan_shield(scan, label)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _map_scan(scan)


@router.post(
    "/{scan_id}/ai-analysis",
    response_model=AIScanAnalysisSubmitResponse,
    status_code=202,
)
async def create_scan_ai_analysis(
    scan_id: str,
    payload: AIScanAnalysisRequest,
    _write: None = Depends(require_ai_target_write_scan),
    service: ScanService = Depends(get_scan_service),
    ai_client: AIClient = Depends(get_ai_client),
) -> AIScanAnalysisSubmitResponse:
    """Run an AI risk-triage analysis against a completed scan. Runs in the background."""
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if payload.provider == "openai" and not settings.openai_api_key:
        raise HTTPException(status_code=400, detail="OpenAI provider is not configured.")
    if payload.provider == "anthropic" and not settings.anthropic_api_key:
        raise HTTPException(status_code=400, detail="Anthropic provider is not configured.")
    if payload.provider == "gemini" and not settings.google_gemini_api_key:
        raise HTTPException(status_code=400, detail="Gemini provider is not configured.")
    if payload.provider == "openai-compatible" and (
        not settings.openai_compatible_base_url or not settings.openai_compatible_model
    ):
        raise HTTPException(status_code=400, detail="OpenAI-compatible provider is not configured.")

    _, findings = await service.finding_repo.list_by_scan(scan_id, limit=500, include_dismissed=False)
    previous = await previous_scan_analyses(service.scan_repo, scan_id, scan)
    run_id = uuid.uuid4().hex

    task = asyncio.create_task(
        _run_scan_ai_analysis_background(
            scan_id=scan_id,
            run_id=run_id,
            scan=scan,
            findings=findings,
            provider=payload.provider,
            language=payload.language,
            additional_context=payload.additional_context,
            triggered_by=payload.triggered_by,
            ai_client=ai_client,
            service=service,
            previous_analyses=previous,
        )
    )
    # Keep a reference on the task set to prevent GC
    _scan_ai_tasks.add(task)
    task.add_done_callback(_scan_ai_tasks.discard)

    return AIScanAnalysisSubmitResponse(status="running", scanId=scan_id, runId=run_id)


_scan_ai_tasks: set[asyncio.Task[Any]] = set()


async def _run_scan_ai_analysis_background(
    *,
    scan_id: str,
    run_id: str,
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    provider: str,
    language: str | None,
    additional_context: str | None,
    triggered_by: str | None,
    ai_client: AIClient,
    service: ScanService,
    previous_analyses: list[dict[str, Any]] | None = None,
) -> None:
    # Like the vulnerability AI jobs: the sidebar dot and the scan page follow
    # these events, and a failure reaches the page instead of a silent timeout.
    job_name = f"ai_scan_analysis_{scan_id}"
    started_at = datetime.now(tz=UTC)
    publish_job_started(job_name, started_at, provider=provider, scanId=scan_id, runId=run_id)
    try:
        result = await ai_client.analyze_scan(
            provider,  # type: ignore[arg-type]
            {**scan, "_id": scan_id},
            findings,
            language=language,
            additional_context=additional_context,
            triggered_by=triggered_by,
            previous_analyses=previous_analyses,
        )
        await service.save_scan_ai_analysis(scan_id, result.model_dump(by_alias=True))
        publish_job_completed(job_name, started_at, datetime.now(tz=UTC), scanId=scan_id, runId=run_id)
    except Exception as exc:
        _ai_scan_logger.error("scan_ai_analysis_failed", scan_id=scan_id, error=str(exc))
        publish_job_failed(job_name, started_at, datetime.now(tz=UTC), error=str(exc)[:500], scanId=scan_id, runId=run_id)


_scan_attack_chain_tasks: set[asyncio.Task[Any]] = set()


@router.get("/{scan_id}/attack-chain", response_model=ScanAttackChainResponse)
async def get_scan_attack_chain(
    scan_id: str,
    language: str = Query(default="en", description="UI language (en/de) for stage labels."),
    service: ScanService = Depends(get_scan_service),
    chain_service: ScanAttackChainService = Depends(get_scan_attack_chain_service),
) -> ScanAttackChainResponse:
    """Compute the deterministic Cross-CVE Attack Chain for a scan and return the
    persisted AI narrative (if any). The graph is always computed live; the
    narrative is read-only here (use POST to (re)generate it).
    """
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    _, findings = await service.finding_repo.list_by_scan(
        scan_id, limit=2000, include_dismissed=False
    )
    graph, stages = await chain_service.build_chain(
        {**scan, "_id": scan_id}, findings, language=language
    )

    narrative_payload = scan.get("attack_chain")
    narrative_obj = None
    if isinstance(narrative_payload, dict) and narrative_payload.get("summary"):
        try:
            from app.schemas.scan_attack_chain import ScanAttackChainNarrative

            narrative_obj = ScanAttackChainNarrative.model_validate(narrative_payload)
        except Exception as exc:  # pragma: no cover - defensive
            _ai_scan_logger.warning(
                "scan_attack_chain.narrative_validate_failed",
                scan_id=scan_id,
                error=str(exc),
            )

    return ScanAttackChainResponse(
        scanId=scan_id,
        graph=graph,
        stages=stages,
        narrative=narrative_obj,
    )


@router.post(
    "/{scan_id}/attack-chain",
    response_model=ScanAttackChainSubmitResponse,
    status_code=202,
)
async def create_scan_attack_chain_analysis(
    scan_id: str,
    payload: ScanAttackChainRequest,
    _write: None = Depends(require_ai_target_write_scan),
    service: ScanService = Depends(get_scan_service),
    ai_client: AIClient = Depends(get_ai_client),
    chain_service: ScanAttackChainService = Depends(get_scan_attack_chain_service),
) -> ScanAttackChainSubmitResponse:
    """Kick off AI-narrative generation for the Cross-CVE Attack Chain. HTTP 202.
    Mirrors `create_scan_ai_analysis`: SSE `scan_attack_chain_{scanId}` with the returned runId."""
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if payload.provider == "openai" and not settings.openai_api_key:
        raise HTTPException(status_code=400, detail="OpenAI provider is not configured.")
    if payload.provider == "anthropic" and not settings.anthropic_api_key:
        raise HTTPException(status_code=400, detail="Anthropic provider is not configured.")
    if payload.provider == "gemini" and not settings.google_gemini_api_key:
        raise HTTPException(status_code=400, detail="Gemini provider is not configured.")
    if payload.provider == "openai-compatible" and (
        not settings.openai_compatible_base_url or not settings.openai_compatible_model
    ):
        raise HTTPException(status_code=400, detail="OpenAI-compatible provider is not configured.")

    _, findings = await service.finding_repo.list_by_scan(
        scan_id, limit=2000, include_dismissed=False
    )
    run_id = uuid.uuid4().hex

    task = asyncio.create_task(
        _run_scan_attack_chain_background(
            scan_id=scan_id,
            run_id=run_id,
            scan=scan,
            findings=findings,
            provider=payload.provider,
            language=payload.language,
            additional_context=payload.additional_context,
            triggered_by=payload.triggered_by,
            ai_client=ai_client,
            service=service,
            chain_service=chain_service,
        )
    )
    _scan_attack_chain_tasks.add(task)
    task.add_done_callback(_scan_attack_chain_tasks.discard)

    return ScanAttackChainSubmitResponse(status="running", scanId=scan_id, runId=run_id)


async def _run_scan_attack_chain_background(
    *,
    scan_id: str,
    run_id: str,
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    provider: str,
    language: str | None,
    additional_context: str | None,
    triggered_by: str | None,
    ai_client: AIClient,
    service: ScanService,
    chain_service: ScanAttackChainService,
) -> None:
    job_name = f"scan_attack_chain_{scan_id}"
    started_at = datetime.now(tz=UTC)
    publish_job_started(job_name, started_at, provider=provider, scanId=scan_id, runId=run_id)
    try:
        graph, stages = await chain_service.build_chain(
            {**scan, "_id": scan_id}, findings, language=language or "en"
        )
        narrative = await ai_client.analyze_scan_attack_chain(
            provider,  # type: ignore[arg-type]
            {**scan, "_id": scan_id},
            [s.model_dump(by_alias=True) for s in stages],
            graph.model_dump(by_alias=True),
            language=language,
            additional_context=additional_context,
            triggered_by=triggered_by,
        )
        await service.save_attack_chain(scan_id, narrative.model_dump(by_alias=True))
        publish_job_completed(job_name, started_at, datetime.now(tz=UTC), scanId=scan_id, runId=run_id)
    except Exception as exc:
        _ai_scan_logger.error("scan_attack_chain_failed", scan_id=scan_id, error=str(exc))
        publish_job_failed(job_name, started_at, datetime.now(tz=UTC), error=str(exc)[:500], scanId=scan_id, runId=run_id)


@router.get("/{scan_id}/findings", response_model=ScanFindingListResponse)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    include_dismissed: bool = Query(default=False, alias="includeDismissed"),
    service: ScanService = Depends(get_scan_service),
) -> ScanFindingListResponse:
    total, items = await service.get_scan_findings(
        scan_id, severity=severity, limit=limit, offset=offset, include_dismissed=include_dismissed
    )
    return ScanFindingListResponse(
        total=total,
        items=[_map_finding(item) for item in items],
    )


@router.get("/{scan_id}/sbom", response_model=SbomComponentListResponse)
async def get_scan_sbom(
    scan_id: str,
    search: str | None = Query(default=None, description="Search by component name"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> SbomComponentListResponse:
    total, items = await service.get_scan_sbom(
        scan_id, search=search, limit=limit, offset=offset
    )
    return SbomComponentListResponse(
        total=total,
        items=[_map_sbom_component(item) for item in items],
    )


@router.get(
    "/{scan_id}/sbom/export",
    response_class=Response,
    responses=download("application/json", "CycloneDX 1.5 or SPDX 2.3 JSON document of the scan's SBOM."),
)
async def export_scan_sbom(
    scan_id: str,
    format: str = Query(
        default="cyclonedx-json",
        alias="format",
        pattern=r"^(cyclonedx-json|spdx-json)$",
        description="Export format: cyclonedx-json or spdx-json",
    ),
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """Export SBOM in CycloneDX 1.5 or SPDX 2.3 JSON format."""
    try:
        doc, filename = await service.export_sbom(scan_id, format)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(
        content=json.dumps(doc, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/layers", response_model=ScanLayerAnalysisResponse)
async def get_scan_layers(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanLayerAnalysisResponse:
    """Get Dive layer analysis for a scan."""
    data = await service.get_layer_analysis(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="No layer analysis available for this scan")
    return ScanLayerAnalysisResponse(
        scan_id=data.get("scan_id", scan_id),
        efficiency=data.get("efficiency", 0.0),
        wasted_bytes=data.get("wasted_bytes", 0),
        user_wasted_percent=data.get("user_wasted_percent", 0.0),
        total_image_size=data.get("total_image_size", 0),
        layers=[
            ScanLayerDetailSchema(
                index=layer.get("index", i),
                digest=layer.get("digest", ""),
                size_bytes=layer.get("size_bytes", 0),
                command=layer.get("command", ""),
            )
            for i, layer in enumerate(data.get("layers", []))
        ],
        pass_threshold=data.get("pass_threshold", True),
    )


@router.get("/{scan_id}/license-compliance", response_model=LicenseComplianceResultResponse)
async def get_scan_license_compliance(
    scan_id: str,
    policy_id: str | None = Query(default=None, alias="policyId"),
    service: ScanService = Depends(get_scan_service),
) -> LicenseComplianceResultResponse:
    """Evaluate SBOM components of a scan against a license policy."""
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    policy_repo = await LicensePolicyRepository.create()
    sbom_repo = await ScanSbomRepository.create()
    compliance_svc = LicenseComplianceService(policy_repo, sbom_repo)
    result = await compliance_svc.evaluate_scan(scan_id, policy_id)
    return LicenseComplianceResultResponse(**result)


@router.put("/{scan_id}/release", response_model=ScanResponse)
async def mark_scan_release(
    scan_id: str,
    body: ScanReleaseRequest,
    _auth: None = Depends(require_target_write_scan),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """Mark a completed scan as a release (version label + optional note)."""
    from app.services.scan_release import ReleaseError, mark_release

    try:
        scan = await mark_release(service.scan_repo, scan_id, body.label, body.note)
    except ReleaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return _map_scan(scan)


@router.delete("/{scan_id}/release", response_model=ScanResponse)
async def clear_scan_release(
    scan_id: str,
    _auth: None = Depends(require_target_write_scan),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """Remove the release marker of a scan."""
    from app.services.scan_release import ReleaseError, clear_release

    try:
        scan = await clear_release(service.scan_repo, scan_id)
    except ReleaseError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return _map_scan(scan)


@router.get(
    "/{scan_id}/evidence-bundle",
    response_class=Response,
    responses=download(
        "application/zip",
        "ZIP with the SBOMs, the VEX documents, a findings summary, manifest.json and SHA256SUMS.",
        binary=True,
    ),
)
async def download_evidence_bundle(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """ZIP with SBOM (CycloneDX + SPDX), VEX (CycloneDX, OpenVEX, CSAF), a findings
    summary and a manifest with the SHA-256 of every file."""
    from app.services.evidence_bundle import BundleTooLarge, build_evidence_bundle

    try:
        result = await build_evidence_bundle(service, scan_id)
    except BundleTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    data, filename = result
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{scan_id}/vex/export",
    response_class=Response,
    responses=download("application/json", "CycloneDX VEX, OpenVEX 0.2.0 or CSAF 2.0 (VEX profile) document."),
)
async def export_vex(
    scan_id: str,
    format: str = Query(
        default="cyclonedx",
        alias="format",
        pattern=r"^(cyclonedx|openvex|csaf)$",
        description="cyclonedx (CycloneDX 1.5 VEX, default), openvex (OpenVEX 0.2.0) or csaf (CSAF 2.0 VEX)",
    ),
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """Export the VEX statements of a scan.

    CycloneDX lists the findings that carry a VEX status; OpenVEX and CSAF list
    every vulnerability finding, unassessed ones as under investigation.
    """
    from app.services.vex_export import export_vex_document

    result = await export_vex_document(service, scan_id, format)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    vex_doc, filename = result
    if not vex_doc:
        raise HTTPException(status_code=404, detail="No VEX data available for this scan")

    return Response(
        content=json.dumps(vex_doc, default=str, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get(
    "/{scan_id}/findings/export",
    response_class=Response,
    responses=download("application/json", "Findings as SonarQube external issues."),
)
async def export_scan_findings(
    scan_id: str,
    format: str = Query(
        default="sonarqube",
        alias="format",
        pattern=r"^(sonarqube)$",
        description="Export format: sonarqube",
    ),
    file_path_prefix: str = Query(
        default="",
        alias="filePathPrefix",
        description="Prefix prepended to file paths (e.g. 'backend' so Dockerfile becomes backend/Dockerfile)",
    ),
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """Export scan findings in external tool formats (SonarQube external issues)."""
    try:
        doc, filename = await service.export_findings_sonarqube(scan_id, file_path_prefix=file_path_prefix)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(
        content=json.dumps(doc, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Mapping helpers ---


def _map_target(doc: dict[str, Any]) -> ScanTargetResponse:
    latest_summary = doc.get("latest_summary")
    return ScanTargetResponse(
        id=doc.get("target_id", doc.get("_id", "")),
        type=doc.get("type", ""),
        name=doc.get("name", ""),
        registry=doc.get("registry"),
        repository_url=doc.get("repository_url"),
        description=doc.get("description"),
        tags=doc.get("tags", []),
        group=doc.get("group"),
        created_at=doc.get("created_at"),
        updated_at=doc.get("updated_at"),
        last_scan_at=doc.get("last_scan_at"),
        scan_count=doc.get("scan_count", 0),
        latest_summary=ScanSummarySchema(**latest_summary) if latest_summary else None,
        latest_scan_id=doc.get("latest_scan_id"),
        has_running_scan=doc.get("has_running_scan", False),
        running_scan_id=doc.get("running_scan_id"),
        running_scan_status=doc.get("running_scan_status"),
        auto_scan=doc.get("auto_scan", True),
        scanners=doc.get("scanners", []),
        last_check_at=doc.get("last_check_at"),
        last_check_verdict=doc.get("last_check_verdict"),
        last_check_current_fingerprint=doc.get("last_check_current_fingerprint"),
        last_check_error=doc.get("last_check_error"),
        last_image_digest=doc.get("last_image_digest"),
        last_commit_sha=doc.get("last_commit_sha"),
        write_password_set=bool(doc.get("write_password_hash")),
        vex_sources=doc.get("vex_sources") or [],
        vex_source_status=doc.get("vex_source_status") or None,
        trufflehog_verification=doc.get("trufflehog_verification"),
        no_external_lookups=bool(doc.get("no_external_lookups")),
        kind=doc.get("kind"),
        exposure=doc.get("exposure"),
    )


def _map_scan(doc: dict[str, Any]) -> ScanResponse:
    summary = doc.get("summary", {})
    return ScanResponse(
        id=str(doc.get("_id", "")),
        target_id=doc.get("target_id", ""),
        target_name=doc.get("target_name"),
        check=bool(doc.get("check")) or is_check_target(doc.get("target_id")),
        no_external_lookups=bool(doc.get("no_external_lookups")),
        expires_at=doc.get("expires_at"),
        scanners=doc.get("scanners", []),
        status=doc.get("status", ""),
        source=doc.get("source", ""),
        image_ref=doc.get("image_ref"),
        commit_sha=doc.get("commit_sha"),
        branch=doc.get("branch"),
        pipeline_url=doc.get("pipeline_url"),
        started_at=doc.get("started_at"),
        finished_at=doc.get("finished_at"),
        duration_seconds=doc.get("duration_seconds"),
        summary=ScanSummarySchema(**summary) if isinstance(summary, dict) else ScanSummarySchema(),
        sbom_component_count=doc.get("sbom_component_count"),
        error=doc.get("error"),
        compliance_summary=doc.get("compliance_summary"),
        license_compliance_summary=doc.get("license_compliance_summary"),
        layer_analysis_available=doc.get("layer_analysis_available", False),
        ai_analysis=doc.get("ai_analysis"),
        ai_analyses=doc.get("ai_analyses"),
        scanner_breakdown=doc.get("scanner_breakdown"),
        release=_map_release(doc.get("release")),
        supply_chain_summary=_map_supply_chain_summary(doc.get("supply_chain_summary")),
    )


def _map_supply_chain_summary(raw: Any) -> SupplyChainSummarySchema | None:
    if not isinstance(raw, dict) or not raw.get("state"):
        return None
    return SupplyChainSummarySchema(
        state=str(raw["state"]),
        checked=int(raw.get("checked") or 0),
        fresh_release=int(raw.get("fresh_release") or 0),
        unmaintained=int(raw.get("unmaintained") or 0),
        publisher_changed=int(raw.get("publisher_changed") or 0),
        finished_at=raw.get("finished_at"),
    )


def _map_release(raw: Any) -> ScanReleaseSchema | None:
    if not isinstance(raw, dict) or not raw.get("label"):
        return None
    return ScanReleaseSchema(label=str(raw["label"]), note=raw.get("note"), marked_at=raw.get("marked_at"))


def _map_finding(doc: dict[str, Any]) -> ScanFindingResponse:
    needs_review, review_reason = review_state(doc)
    return ScanFindingResponse(
        id=str(doc.get("_id", "")),
        scan_id=str(doc.get("scan_id", "")),
        target_id=doc.get("target_id", ""),
        vulnerability_id=doc.get("vulnerability_id"),
        matched_from=doc.get("matched_from"),
        scanner=doc.get("scanner", ""),
        package_name=doc.get("package_name", ""),
        package_version=doc.get("package_version", ""),
        package_type=doc.get("package_type", ""),
        package_path=doc.get("package_path"),
        severity=doc.get("severity", "unknown"),
        title=doc.get("title"),
        description=doc.get("description"),
        fix_version=doc.get("fix_version"),
        fix_state=doc.get("fix_state", "unknown"),
        advisory_fix_versions=doc.get("advisory_fix_versions", []),
        data_source=doc.get("data_source"),
        urls=doc.get("urls", []),
        cvss_score=doc.get("cvss_score"),
        cvss_vector=doc.get("cvss_vector"),
        vex_status=doc.get("vex_status"),
        vex_justification=doc.get("vex_justification"),
        vex_detail=doc.get("vex_detail"),
        vex_updated_at=doc.get("vex_updated_at"),
        vex_updated_by=doc.get("vex_updated_by"),
        vex_assessed_version=doc.get("vex_assessed_version"),
        vex_review_due=doc.get("vex_review_due"),
        vex_needs_review=needs_review,
        vex_review_reason=review_reason,
        dependency_scope=doc.get("dependency_scope"),
        dismissed=bool(doc.get("dismissed", False)),
        dismissed_reason=doc.get("dismissed_reason"),
        dismissed_at=doc.get("dismissed_at"),
        dismissed_by=doc.get("dismissed_by"),
    )


def _map_sbom_component(doc: dict[str, Any]) -> SbomComponentResponse:
    name = doc.get("name", "")
    version = doc.get("version", "")
    # Consolidated rows don't have a mongo _id; synthesize a stable react key.
    raw_id = doc.get("_id")
    row_id = str(raw_id) if raw_id else f"{name}::{version}"
    # Consolidated rows carry `file_paths` (list); raw rows carry `file_path` (str).
    file_path = doc.get("file_path")
    if not file_path:
        file_paths = doc.get("file_paths") or []
        if file_paths:
            file_path = file_paths[0]
    return SbomComponentResponse(
        id=row_id,
        scan_id=str(doc.get("scan_id", "")),
        target_id=doc.get("target_id", ""),
        name=name,
        version=version,
        type=doc.get("type", ""),
        purl=doc.get("purl"),
        cpe=doc.get("cpe"),
        licenses=doc.get("licenses", []),
        supplier=doc.get("supplier"),
        file_path=file_path,
        provenance_verified=doc.get("provenance_verified"),
        provenance_source_repo=doc.get("provenance_source_repo"),
        provenance_build_system=doc.get("provenance_build_system"),
        provenance_attestation_type=doc.get("provenance_attestation_type"),
        scope=doc.get("scope"),
        published_at=doc.get("published_at"),
        latest_version=doc.get("latest_version"),
        latest_published_at=doc.get("latest_published_at"),
        publisher=doc.get("publisher"),
        previous_publishers=doc.get("previous_publishers"),
        new_maintainers=doc.get("new_maintainers"),
        fresh_release=doc.get("fresh_release"),
        unmaintained=doc.get("unmaintained"),
        publisher_changed=doc.get("publisher_changed"),
        bundled_in=doc.get("bundled_in"),
    )


def _map_consolidated_finding(doc: dict[str, Any]) -> ConsolidatedFindingResponse:
    return ConsolidatedFindingResponse(
        vulnerability_id=doc.get("vulnerability_id"),
        package_name=doc.get("package_name", ""),
        package_version=doc.get("package_version", ""),
        severity=doc.get("severity", "unknown"),
        fix_version=doc.get("fix_version"),
        fix_state=doc.get("fix_state", "unknown"),
        title=doc.get("title"),
        scanners=doc.get("scanners", []),
        targets=[
            ConsolidatedTargetSchema(target_id=t["target_id"], scan_id=t["scan_id"])
            for t in doc.get("targets", [])
        ],
        cvss_score=doc.get("cvss_score"),
        urls=doc.get("urls", []),
        package_type=doc.get("package_type"),
        package_path=doc.get("package_path"),
        dependency_scope=doc.get("dependency_scope"),
    )


def _map_consolidated_alert(doc: dict[str, Any]) -> ConsolidatedAlertResponse:
    return ConsolidatedAlertResponse(
        title=doc.get("title"),
        package_name=doc.get("package_name", ""),
        package_version=doc.get("package_version", ""),
        severity=doc.get("severity") or "unknown",
        description=doc.get("description"),
        category=doc.get("category"),
        package_path=doc.get("package_path"),
        targets=[
            ConsolidatedTargetSchema(target_id=t["target_id"], scan_id=t["scan_id"])
            for t in doc.get("targets", [])
        ],
    )


def _map_consolidated_sbom(doc: dict[str, Any]) -> ConsolidatedSbomResponse:
    return ConsolidatedSbomResponse(
        name=doc.get("name", ""),
        version=doc.get("version", ""),
        type=doc.get("type", ""),
        purl=doc.get("purl"),
        licenses=doc.get("licenses", []),
        provenance_verified=doc.get("provenance_verified"),
        scope=doc.get("scope"),
        targets=[
            ConsolidatedTargetSchema(target_id=t["target_id"], scan_id=t["scan_id"])
            for t in doc.get("targets", [])
        ],
    )
