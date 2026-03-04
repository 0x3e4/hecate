from __future__ import annotations

from datetime import datetime
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
    auto_scan: bool = Field(default=True, description="Include in auto-scan scheduling")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_scan_at: datetime | None = None
    scan_count: int = 0


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
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    sbom_component_count: int | None = None
    error: str | None = None
    scanner_version: str | None = None


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
    created_at: datetime = Field(default_factory=datetime.utcnow)


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
