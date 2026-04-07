from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.core.config import settings
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
    ConsolidatedFindingListResponse,
    ConsolidatedFindingResponse,
    ConsolidatedSbomListResponse,
    ConsolidatedSbomResponse,
    ConsolidatedTargetSchema,
    ImportSbomRequest,
    SbomComponentListResponse,
    SbomComponentResponse,
    ScanComparisonFindingSchema,
    ScanComparisonResponse,
    ScanFindingListResponse,
    ScanFindingResponse,
    ScanHistoryEntrySchema,
    ScanHistoryResponse,
    ScanLayerAnalysisResponse,
    ScanLayerDetailSchema,
    ScanListResponse,
    ScanResponse,
    ScanSummarySchema,
    ScanTargetCreateRequest,
    ScanTargetListResponse,
    ScanTargetResponse,
    SubmitScanRequest,
    SubmitScanResponse,
)
from app.schemas.vex import (
    VexBulkUpdateRequest,
    VexBulkUpdateResponse,
    VexImportRequest,
    VexImportResponse,
    VexUpdateRequest,
    VexUpdateResponse,
)
from app.services.license_compliance_service import LicenseComplianceService
from app.services.scan_service import ScanService, get_scan_service
from app.services.vex_service import VexService

router = APIRouter()


async def verify_sca_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """Verify the SCA API key for write endpoints."""
    if not settings.sca_api_key:
        raise HTTPException(status_code=503, detail="SCA API key not configured on server")
    if x_api_key != settings.sca_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


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
            one_time=request.one_time or bool(request.source_archive_base64),
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
    )


@router.post("/manual", response_model=SubmitScanResponse, status_code=201)
async def submit_manual_scan(
    request: SubmitScanRequest,
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
            one_time=request.one_time or bool(request.source_archive_base64),
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
    )


# --- Scan targets ---


@router.get("/targets", response_model=ScanTargetListResponse)
async def list_targets(
    type: str | None = Query(default=None, description="Filter by type: container_image or source_repo"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetListResponse:
    total, items = await service.list_targets(type_filter=type, limit=limit, offset=offset)
    return ScanTargetListResponse(
        total=total,
        items=[_map_target(item) for item in items],
    )


@router.get("/targets/{target_id:path}/history", response_model=ScanHistoryResponse)
async def get_target_history(
    target_id: str,
    limit: int = Query(default=30, ge=1, le=100),
    service: ScanService = Depends(get_scan_service),
) -> ScanHistoryResponse:
    """Get scan history for a target (for charts)."""
    items = await service.get_target_history(target_id, limit=limit)
    return ScanHistoryResponse(
        target_id=target_id,
        items=[
            ScanHistoryEntrySchema(
                scan_id=str(item.get("_id", "")),
                started_at=item.get("started_at"),
                status=item.get("status", ""),
                summary=ScanSummarySchema(**(item.get("summary", {}))),
                duration_seconds=item.get("duration_seconds"),
            )
            for item in items
        ],
    )


@router.get("/targets/{target_id:path}", response_model=ScanTargetResponse)
async def get_target(
    target_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    return _map_target(target)


@router.post("/targets", response_model=ScanTargetResponse, status_code=201)
async def create_target(
    request: ScanTargetCreateRequest,
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
    )
    await service.target_repo.upsert(target_doc)
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=500, detail="Failed to create target")
    return _map_target(target)


@router.patch("/targets/{target_id:path}", response_model=ScanTargetResponse)
async def update_target(
    target_id: str,
    body: dict[str, Any] = None,
    service: ScanService = Depends(get_scan_service),
) -> ScanTargetResponse:
    """Update target settings (e.g., auto_scan, scanners)."""
    if body and "autoScan" in body:
        await service.update_target_auto_scan(target_id, bool(body["autoScan"]))
    if body and "scanners" in body:
        try:
            await service.update_target_scanners(target_id, body["scanners"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scan target not found")
    return _map_target(target)


@router.delete("/targets/{target_id:path}", status_code=204)
async def delete_target(
    target_id: str,
    service: ScanService = Depends(get_scan_service),
) -> None:
    deleted = await service.delete_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan target not found")


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


@router.post("/import-sbom", response_model=SubmitScanResponse, status_code=201)
async def import_sbom(
    request: ImportSbomRequest,
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Import an external SBOM file (CycloneDX or SPDX JSON)."""
    try:
        result = await service.import_sbom(
            sbom_data=request.sbom,
            format=request.format,
            target_name=request.target_name,
            target_id=request.target_id,
        )
        summary = result.get("summary")
        return SubmitScanResponse(
            scan_id=result["scan_id"],
            target_id=result["target_id"],
            status=result["status"],
            findings_count=result.get("findings_count", 0),
            sbom_component_count=result.get("sbom_component_count", 0),
            summary=ScanSummarySchema(**summary.model_dump()) if hasattr(summary, "model_dump") else ScanSummarySchema(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import-sbom/upload", response_model=SubmitScanResponse, status_code=201)
async def import_sbom_upload(
    file: UploadFile = File(...),
    target_name: str | None = Query(default=None, alias="targetName"),
    format: str | None = Query(default=None),
    service: ScanService = Depends(get_scan_service),
) -> SubmitScanResponse:
    """Import an external SBOM file via multipart file upload."""

    content = await file.read()
    try:
        sbom_data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    try:
        result = await service.import_sbom(
            sbom_data=sbom_data,
            format=format,
            target_name=target_name,
        )
        summary = result.get("summary")
        return SubmitScanResponse(
            scan_id=result["scan_id"],
            target_id=result["target_id"],
            status=result["status"],
            findings_count=result.get("findings_count", 0),
            sbom_component_count=result.get("sbom_component_count", 0),
            summary=ScanSummarySchema(**summary.model_dump()) if hasattr(summary, "model_dump") else ScanSummarySchema(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
    )
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    return VexUpdateResponse(success=True, findingId=finding_id)


@router.post("/vex/bulk-update", response_model=VexBulkUpdateResponse)
async def bulk_update_vex(
    request: VexBulkUpdateRequest,
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


@router.post("/vex/import", response_model=VexImportResponse)
async def import_vex(
    request: VexImportRequest,
) -> VexImportResponse:
    """Import a CycloneDX VEX document and apply to matching findings."""
    finding_repo = await ScanFindingRepository.create()
    scan_repo = await ScanRepository.create()
    vex_service = VexService(finding_repo, scan_repo)
    result = await vex_service.import_cyclonedx_vex(request.vex_document, request.target_id)
    return VexImportResponse(**result)


# --- Dynamic scan routes ---


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
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
    service: ScanService = Depends(get_scan_service),
) -> None:
    deleted = await service.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _map_scan(scan)


@router.get("/{scan_id}/findings", response_model=ScanFindingListResponse)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(get_scan_service),
) -> ScanFindingListResponse:
    total, items = await service.get_scan_findings(
        scan_id, severity=severity, limit=limit, offset=offset
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


@router.get("/{scan_id}/sbom/export")
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


@router.get("/{scan_id}/vex/export")
async def export_vex(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """Export CycloneDX VEX document for a scan."""
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_repo = await ScanFindingRepository.create()
    scan_repo = await ScanRepository.create()
    vex_service = VexService(finding_repo, scan_repo)
    vex_doc = await vex_service.export_cyclonedx_vex(scan_id)
    if not vex_doc:
        raise HTTPException(status_code=404, detail="No VEX data available for this scan")

    return Response(
        content=json.dumps(vex_doc, default=str, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=vex-{scan_id}.cdx.json"},
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
        created_at=doc.get("created_at"),
        updated_at=doc.get("updated_at"),
        last_scan_at=doc.get("last_scan_at"),
        scan_count=doc.get("scan_count", 0),
        latest_summary=ScanSummarySchema(**latest_summary) if latest_summary else None,
        latest_scan_id=doc.get("latest_scan_id"),
        has_running_scan=doc.get("has_running_scan", False),
        running_scan_id=doc.get("running_scan_id"),
        auto_scan=doc.get("auto_scan", True),
        scanners=doc.get("scanners", []),
    )


def _map_scan(doc: dict[str, Any]) -> ScanResponse:
    summary = doc.get("summary", {})
    return ScanResponse(
        id=str(doc.get("_id", "")),
        target_id=doc.get("target_id", ""),
        target_name=doc.get("target_name"),
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
    )


def _map_finding(doc: dict[str, Any]) -> ScanFindingResponse:
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
        data_source=doc.get("data_source"),
        urls=doc.get("urls", []),
        cvss_score=doc.get("cvss_score"),
        cvss_vector=doc.get("cvss_vector"),
        vex_status=doc.get("vex_status"),
        vex_justification=doc.get("vex_justification"),
        vex_updated_at=doc.get("vex_updated_at"),
    )


def _map_sbom_component(doc: dict[str, Any]) -> SbomComponentResponse:
    return SbomComponentResponse(
        id=str(doc.get("_id", "")),
        scan_id=str(doc.get("scan_id", "")),
        target_id=doc.get("target_id", ""),
        name=doc.get("name", ""),
        version=doc.get("version", ""),
        type=doc.get("type", ""),
        purl=doc.get("purl"),
        cpe=doc.get("cpe"),
        licenses=doc.get("licenses", []),
        supplier=doc.get("supplier"),
        file_path=doc.get("file_path"),
        provenance_verified=doc.get("provenance_verified"),
        provenance_source_repo=doc.get("provenance_source_repo"),
        provenance_build_system=doc.get("provenance_build_system"),
        provenance_attestation_type=doc.get("provenance_attestation_type"),
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
    )


def _map_consolidated_sbom(doc: dict[str, Any]) -> ConsolidatedSbomResponse:
    return ConsolidatedSbomResponse(
        name=doc.get("name", ""),
        version=doc.get("version", ""),
        type=doc.get("type", ""),
        purl=doc.get("purl"),
        licenses=doc.get("licenses", []),
        provenance_verified=doc.get("provenance_verified"),
        targets=[
            ConsolidatedTargetSchema(target_id=t["target_id"], scan_id=t["scan_id"])
            for t in doc.get("targets", [])
        ],
    )
