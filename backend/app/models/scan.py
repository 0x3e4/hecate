from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0
    total: int = 0


class ScanTargetDocument(BaseModel):
    """Represents a scannable entity — a container image or source repo."""

    target_id: str = Field(description="Slug, e.g. 'git.nohub.lol/rk/hecate-backend' or repo URL")
    type: str = Field(description="container_image or source_repo")
    name: str = Field(description="Human-readable name")
    registry: str | None = Field(default=None, description="Registry host for container images")
    repository_url: str | None = Field(default=None, description="URL for source repos")
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    group: str | None = Field(default=None, description="Application/group name this target belongs to")
    scanners: list[str] = Field(default_factory=list, description="Scanners used for this target")
    auto_scan: bool = Field(default=True, description="Include in auto-scan scheduling")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_scan_at: datetime | None = None
    scan_count: int = 0
    last_image_digest: str | None = Field(default=None, description="Image digest from most recent scan")
    last_commit_sha: str | None = Field(default=None, description="Commit SHA from most recent scan")
    # Last auto-scan change-detection probe. Captured for every call to
    # ``ScanService.check_target_changed`` so the SCA Scans → Scanner tab can
    # surface a per-target diagnostics table when a target seemingly fails to
    # auto-scan despite the toggle being on.
    last_check_at: datetime | None = Field(
        default=None, description="When the scanner /check probe last ran for this target"
    )
    last_check_verdict: str | None = Field(
        default=None,
        description=(
            "One of: 'changed' | 'unchanged' | 'first_scan' | "
            "'check_failed_skipped' | 'check_failed_scanned'. The first three "
            "use a successful /check response; the last two cover the /check "
            "failure paths in ``check_target_changed`` (skipped when a "
            "previous fingerprint exists, scanned otherwise)."
        ),
    )
    last_check_current_fingerprint: str | None = Field(
        default=None,
        description="Fingerprint returned by the most recent /check (digest or commit SHA)",
    )
    last_check_error: str | None = Field(
        default=None,
        description="Error message from the most recent /check call when it failed (None on success)",
    )
    # Denormalized scan state (updated at scan lifecycle events)
    latest_summary: dict[str, int] | None = Field(default=None)
    latest_scan_id: str | None = Field(default=None)
    has_running_scan: bool = Field(default=False)
    running_scan_id: str | None = Field(default=None)
    running_scan_status: str | None = Field(default=None)


class ScanDocument(BaseModel):
    """An individual scan run linked to a target."""

    target_id: str
    target_name: str | None = None
    scanners: list[str] = Field(default_factory=list)
    status: str = Field(default="pending", description="pending, running, completed, failed")
    source: str = Field(default="manual", description="ci_cd or manual")
    image_ref: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    pipeline_url: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    sbom_component_count: int | None = None
    error: str | None = None
    scanner_version: str | None = None
    compliance_summary: dict[str, int] | None = None
    license_compliance_summary: dict[str, int] | None = None
    layer_analysis_available: bool = False
    ai_analyses: list[dict[str, Any]] = Field(
        default_factory=list, description="Full history of AI analyses for this scan (most recent last)"
    )
    ai_analysis: dict[str, Any] | None = Field(
        default=None, description="Latest AI analysis (mirror of ai_analyses[-1] for convenience)"
    )
    attack_chains: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Full history of Cross-CVE Attack Chain narratives for this scan",
    )
    attack_chain: dict[str, Any] | None = Field(
        default=None,
        description="Latest Cross-CVE Attack Chain narrative (mirror of attack_chains[-1])",
    )


class ScanFindingDocument(BaseModel):
    """An individual vulnerability finding from a scan."""

    scan_id: str
    target_id: str
    vulnerability_id: str | None = Field(default=None, description="CVE ID — links to vulnerabilities collection")
    matched_from: str | None = Field(default=None, description="Set to 'auto' if CVE was auto-matched from local DB")
    scanner: str
    package_name: str
    package_version: str = ""
    package_type: str = ""
    package_path: str | None = None
    severity: str = "unknown"
    title: str | None = None
    description: str | None = None
    fix_version: str | None = None
    fix_state: str = "unknown"
    data_source: str | None = None
    urls: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    vex_status: str | None = Field(
        default=None, description="VEX status: not_affected, affected, fixed, under_investigation"
    )
    vex_justification: str | None = None
    vex_detail: str | None = None
    vex_response: list[str] | None = Field(default=None, description="e.g. will_not_fix, workaround_available")
    vex_updated_at: datetime | None = None
    vex_updated_by: str | None = Field(default=None, description="user or vex-import")
    dismissed: bool = Field(default=False, description="Hide finding from default view (personal filter, not VEX)")
    dismissed_reason: str | None = None
    dismissed_at: datetime | None = None
    dismissed_by: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanLayerDetail(BaseModel):
    """Individual layer in a Dive analysis."""

    index: int
    digest: str = ""
    size_bytes: int = 0
    command: str = ""


class ScanLayerAnalysisDocument(BaseModel):
    """Dive layer analysis results for a container image scan."""

    scan_id: str
    target_id: str
    efficiency: float = 0.0
    wasted_bytes: int = 0
    user_wasted_percent: float = 0.0
    total_image_size: int = 0
    layers: list[ScanLayerDetail] = Field(default_factory=list)
    pass_threshold: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanSbomComponentDocument(BaseModel):
    """An SBOM component extracted from a scan."""

    scan_id: str
    target_id: str
    name: str
    version: str = ""
    type: str = ""
    purl: str | None = None
    cpe: str | None = None
    licenses: list[str] = Field(default_factory=list)
    supplier: str | None = None
    file_path: str | None = None
    provenance_verified: bool | None = None
    provenance_source_repo: str | None = None
    provenance_build_system: str | None = None
    provenance_attestation_type: str | None = None
