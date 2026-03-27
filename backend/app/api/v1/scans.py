from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import Response

from app.core.config import settings
from app.schemas.scan import (
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
from app.services.scan_service import ScanService, get_scan_service

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
    """Update target settings (e.g., auto_scan)."""
    if body and "autoScan" in body:
        await service.update_target_auto_scan(target_id, bool(body["autoScan"]))
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


# --- Dynamic scan routes ---


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
    )
