from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanSummarySchema(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0
    total: int = 0


# --- Request schemas ---


class ScanTargetCreateRequest(BaseModel):
    """Request to register a scan target manually."""

    target: str = Field(description="Image reference or repo URL")
    type: str = Field(description="container_image or source_repo")
    name: str | None = Field(default=None, description="Display name (derived from target if omitted)")
    registry: str | None = None
    repository_url: str | None = Field(
        default=None, alias="repositoryUrl", serialization_alias="repositoryUrl"
    )
    description: str | None = None
    tags: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class SubmitScanRequest(BaseModel):
    """Request to submit a scan (from CI/CD or manual trigger)."""

    target: str = Field(description="Container image reference or source repo URL")
    type: str = Field(description="container_image or source_repo")
    scanners: list[str] | None = Field(
        default=None, description="Scanner tools to run. Uses defaults if omitted."
    )
    commit_sha: str | None = Field(
        default=None, alias="commitSha", serialization_alias="commitSha"
    )
    branch: str | None = None
    pipeline_url: str | None = Field(
        default=None, alias="pipelineUrl", serialization_alias="pipelineUrl"
    )
    source: str = Field(default="manual", description="ci_cd or manual")
    source_archive_base64: str | None = Field(
        default=None, alias="sourceArchiveBase64", serialization_alias="sourceArchiveBase64"
    )
    one_time: bool = Field(default=False, alias="oneTime", serialization_alias="oneTime")

    model_config = {"populate_by_name": True}


class ImportSbomRequest(BaseModel):
    """Request to import an external SBOM file."""

    sbom: dict[str, Any] = Field(description="The SBOM document (CycloneDX or SPDX JSON)")
    format: str | None = Field(
        default=None,
        description="cyclonedx-json or spdx-json (auto-detected if omitted)",
    )
    target_name: str | None = Field(
        default=None, alias="targetName", serialization_alias="targetName",
        description="Display name for the import target",
    )
    target_id: str | None = Field(
        default=None, alias="targetId", serialization_alias="targetId",
        description="Reuse existing target ID",
    )

    model_config = {"populate_by_name": True}


# --- Response schemas ---


class ScanTargetResponse(BaseModel):
    """Scan target detail."""

    id: str
    type: str
    name: str
    registry: str | None = None
    repository_url: str | None = Field(
        default=None, alias="repositoryUrl", serialization_alias="repositoryUrl"
    )
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt", serialization_alias="updatedAt")
    last_scan_at: datetime | None = Field(
        default=None, alias="lastScanAt", serialization_alias="lastScanAt"
    )
    scan_count: int = Field(default=0, alias="scanCount", serialization_alias="scanCount")
    latest_summary: ScanSummarySchema | None = Field(
        default=None, alias="latestSummary", serialization_alias="latestSummary"
    )
    latest_scan_id: str | None = Field(
        default=None, alias="latestScanId", serialization_alias="latestScanId"
    )
    has_running_scan: bool = Field(
        default=False, alias="hasRunningScan", serialization_alias="hasRunningScan"
    )
    running_scan_id: str | None = Field(
        default=None, alias="runningScanId", serialization_alias="runningScanId"
    )
    running_scan_status: str | None = Field(
        default=None, alias="runningScanStatus", serialization_alias="runningScanStatus"
    )
    auto_scan: bool = Field(
        default=True, alias="autoScan", serialization_alias="autoScan"
    )
    scanners: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ScanTargetListResponse(BaseModel):
    total: int
    items: list[ScanTargetResponse]


class ScanResponse(BaseModel):
    """Scan detail."""

    id: str
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    target_name: str | None = Field(
        default=None, alias="targetName", serialization_alias="targetName"
    )
    scanners: list[str] = Field(default_factory=list)
    status: str
    source: str
    image_ref: str | None = Field(
        default=None, alias="imageRef", serialization_alias="imageRef"
    )
    commit_sha: str | None = Field(
        default=None, alias="commitSha", serialization_alias="commitSha"
    )
    branch: str | None = None
    pipeline_url: str | None = Field(
        default=None, alias="pipelineUrl", serialization_alias="pipelineUrl"
    )
    started_at: datetime = Field(alias="startedAt", serialization_alias="startedAt")
    finished_at: datetime | None = Field(
        default=None, alias="finishedAt", serialization_alias="finishedAt"
    )
    duration_seconds: float | None = Field(
        default=None, alias="durationSeconds", serialization_alias="durationSeconds"
    )
    summary: ScanSummarySchema = Field(default_factory=ScanSummarySchema)
    sbom_component_count: int | None = Field(
        default=None, alias="sbomComponentCount", serialization_alias="sbomComponentCount"
    )
    error: str | None = None
    compliance_summary: dict[str, int] | None = Field(
        default=None, alias="complianceSummary", serialization_alias="complianceSummary"
    )
    license_compliance_summary: dict[str, int] | None = Field(
        default=None,
        alias="licenseComplianceSummary",
        serialization_alias="licenseComplianceSummary",
    )
    layer_analysis_available: bool = Field(
        default=False, alias="layerAnalysisAvailable", serialization_alias="layerAnalysisAvailable"
    )

    model_config = {"populate_by_name": True}


class ScanListResponse(BaseModel):
    total: int
    items: list[ScanResponse]


class ScanFindingResponse(BaseModel):
    """Individual vulnerability finding."""

    id: str
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    vulnerability_id: str | None = Field(
        default=None, alias="vulnerabilityId", serialization_alias="vulnerabilityId"
    )
    matched_from: str | None = Field(
        default=None, alias="matchedFrom", serialization_alias="matchedFrom"
    )
    scanner: str
    package_name: str = Field(alias="packageName", serialization_alias="packageName")
    package_version: str = Field(
        default="", alias="packageVersion", serialization_alias="packageVersion"
    )
    package_type: str = Field(
        default="", alias="packageType", serialization_alias="packageType"
    )
    package_path: str | None = Field(
        default=None, alias="packagePath", serialization_alias="packagePath"
    )
    severity: str = "unknown"
    title: str | None = None
    description: str | None = None
    fix_version: str | None = Field(
        default=None, alias="fixVersion", serialization_alias="fixVersion"
    )
    fix_state: str = Field(
        default="unknown", alias="fixState", serialization_alias="fixState"
    )
    data_source: str | None = Field(
        default=None, alias="dataSource", serialization_alias="dataSource"
    )
    urls: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(
        default=None, alias="cvssScore", serialization_alias="cvssScore"
    )
    cvss_vector: str | None = Field(
        default=None, alias="cvssVector", serialization_alias="cvssVector"
    )
    vex_status: str | None = Field(
        default=None, alias="vexStatus", serialization_alias="vexStatus"
    )
    vex_justification: str | None = Field(
        default=None, alias="vexJustification", serialization_alias="vexJustification"
    )
    vex_updated_at: datetime | None = Field(
        default=None, alias="vexUpdatedAt", serialization_alias="vexUpdatedAt"
    )

    model_config = {"populate_by_name": True}


class ScanFindingListResponse(BaseModel):
    total: int
    items: list[ScanFindingResponse]


class SbomComponentResponse(BaseModel):
    """SBOM component."""

    id: str
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    name: str
    version: str = ""
    type: str = ""
    purl: str | None = None
    cpe: str | None = None
    licenses: list[str] = Field(default_factory=list)
    supplier: str | None = None
    file_path: str | None = Field(
        default=None, alias="filePath", serialization_alias="filePath"
    )
    provenance_verified: bool | None = Field(
        default=None, alias="provenanceVerified", serialization_alias="provenanceVerified"
    )
    provenance_source_repo: str | None = Field(
        default=None, alias="provenanceSourceRepo", serialization_alias="provenanceSourceRepo"
    )
    provenance_build_system: str | None = Field(
        default=None, alias="provenanceBuildSystem", serialization_alias="provenanceBuildSystem"
    )
    provenance_attestation_type: str | None = Field(
        default=None, alias="provenanceAttestationType", serialization_alias="provenanceAttestationType"
    )

    model_config = {"populate_by_name": True}


class SbomComponentListResponse(BaseModel):
    total: int
    items: list[SbomComponentResponse]


class ConsolidatedTargetSchema(BaseModel):
    """A target+scan reference inside a consolidated finding/component."""

    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")

    model_config = {"populate_by_name": True}


class ConsolidatedFindingResponse(BaseModel):
    """Findings grouped by vulnerability + package + version."""

    vulnerability_id: str | None = Field(
        default=None, alias="vulnerabilityId", serialization_alias="vulnerabilityId"
    )
    package_name: str = Field(alias="packageName", serialization_alias="packageName")
    package_version: str = Field(
        alias="packageVersion", serialization_alias="packageVersion"
    )
    severity: str
    fix_version: str | None = Field(
        default=None, alias="fixVersion", serialization_alias="fixVersion"
    )
    fix_state: str = Field(
        default="unknown", alias="fixState", serialization_alias="fixState"
    )
    title: str | None = None
    scanners: list[str] = Field(default_factory=list)
    targets: list[ConsolidatedTargetSchema] = Field(default_factory=list)
    cvss_score: float | None = Field(
        default=None, alias="cvssScore", serialization_alias="cvssScore"
    )
    urls: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ConsolidatedFindingListResponse(BaseModel):
    total: int
    items: list[ConsolidatedFindingResponse]


class ConsolidatedSbomResponse(BaseModel):
    """SBOM components grouped by name + version."""

    name: str
    version: str = ""
    type: str = ""
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)
    provenance_verified: bool | None = Field(
        default=None, alias="provenanceVerified", serialization_alias="provenanceVerified"
    )
    targets: list[ConsolidatedTargetSchema] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ConsolidatedSbomListResponse(BaseModel):
    total: int
    items: list[ConsolidatedSbomResponse]


class SubmitScanResponse(BaseModel):
    """Response after submitting a scan."""

    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    status: str
    findings_count: int = Field(
        default=0, alias="findingsCount", serialization_alias="findingsCount"
    )
    sbom_component_count: int = Field(
        default=0, alias="sbomComponentCount", serialization_alias="sbomComponentCount"
    )
    summary: ScanSummarySchema = Field(default_factory=ScanSummarySchema)
    error: str | None = None

    model_config = {"populate_by_name": True}


# --- History & comparison ---


class ScanHistoryEntrySchema(BaseModel):
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    started_at: datetime = Field(alias="startedAt", serialization_alias="startedAt")
    status: str
    summary: ScanSummarySchema = Field(default_factory=ScanSummarySchema)
    duration_seconds: float | None = Field(
        default=None, alias="durationSeconds", serialization_alias="durationSeconds"
    )
    commit_sha: str | None = Field(
        default=None, alias="commitSha", serialization_alias="commitSha"
    )

    model_config = {"populate_by_name": True}


class ScanHistoryResponse(BaseModel):
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    items: list[ScanHistoryEntrySchema]

    model_config = {"populate_by_name": True}


class ScanComparisonFindingSchema(BaseModel):
    vulnerability_id: str | None = Field(
        default=None, alias="vulnerabilityId", serialization_alias="vulnerabilityId"
    )
    package_name: str = Field(alias="packageName", serialization_alias="packageName")
    package_version: str = Field(
        default="", alias="packageVersion", serialization_alias="packageVersion"
    )
    severity: str = "unknown"
    fix_version: str | None = Field(
        default=None, alias="fixVersion", serialization_alias="fixVersion"
    )

    model_config = {"populate_by_name": True}


class ScanComparisonChangedSchema(BaseModel):
    before: ScanComparisonFindingSchema
    after: ScanComparisonFindingSchema

    model_config = {"populate_by_name": True}


class ScanComparisonResponse(BaseModel):
    scan_id_a: str = Field(alias="scanIdA", serialization_alias="scanIdA")
    scan_id_b: str = Field(alias="scanIdB", serialization_alias="scanIdB")
    summary_a: ScanSummarySchema = Field(alias="summaryA", serialization_alias="summaryA")
    summary_b: ScanSummarySchema = Field(alias="summaryB", serialization_alias="summaryB")
    added: list[ScanComparisonFindingSchema]
    removed: list[ScanComparisonFindingSchema]
    changed: list[ScanComparisonChangedSchema] = []
    unchanged_count: int = Field(
        default=0, alias="unchangedCount", serialization_alias="unchangedCount"
    )

    model_config = {"populate_by_name": True}


# --- Layer analysis (Dive) ---


class ScanLayerDetailSchema(BaseModel):
    index: int
    digest: str = ""
    size_bytes: int = Field(default=0, alias="sizeBytes", serialization_alias="sizeBytes")
    command: str = ""

    model_config = {"populate_by_name": True}


class ScanLayerAnalysisResponse(BaseModel):
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    efficiency: float = 0.0
    wasted_bytes: int = Field(default=0, alias="wastedBytes", serialization_alias="wastedBytes")
    user_wasted_percent: float = Field(
        default=0.0, alias="userWastedPercent", serialization_alias="userWastedPercent"
    )
    total_image_size: int = Field(
        default=0, alias="totalImageSize", serialization_alias="totalImageSize"
    )
    layers: list[ScanLayerDetailSchema] = Field(default_factory=list)
    pass_threshold: bool = Field(
        default=True, alias="passThreshold", serialization_alias="passThreshold"
    )

    model_config = {"populate_by_name": True}
