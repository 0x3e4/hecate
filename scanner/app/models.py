from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(description="Container image reference or source repo URL")
    type: str = Field(description="container_image or source_repo")
    scanners: list[str] = Field(
        default_factory=lambda: ["trivy", "grype", "syft"],
        description="List of scanners to run",
    )
    source_archive_base64: str | None = Field(
        default=None, alias="sourceArchiveBase64", serialization_alias="sourceArchiveBase64"
    )

    model_config = {"populate_by_name": True}


class ScannerResult(BaseModel):
    scanner: str
    format: str
    report: dict[str, Any] | list[Any]
    error: str | None = None


class ScanMetadata(BaseModel):
    commit_sha: str | None = None
    image_digest: str | None = None


class ScanResponse(BaseModel):
    target: str
    type: str
    results: list[ScannerResult]
    metadata: ScanMetadata | None = None


class StatsResponse(BaseModel):
    memory_used_bytes: int = 0
    memory_limit_bytes: int = 0
    tmp_disk_total_bytes: int = 0
    tmp_disk_used_bytes: int = 0
    tmp_disk_free_bytes: int = 0
    active_scans: int = 0


class CheckRequest(BaseModel):
    target: str = Field(description="Container image reference or source repo URL")
    type: str = Field(description="container_image or source_repo")


class CheckResponse(BaseModel):
    target: str
    type: str
    current_digest: str | None = None
    current_commit_sha: str | None = None


class MalwareFeedEntry(BaseModel):
    """One merged entry from the static + dynamic malware feed."""

    source: str  # "static" | "dynamic"
    ecosystem: str
    name: str
    versions: list[str] = Field(default_factory=list)
    all_versions: bool = Field(
        default=False, alias="allVersions", serialization_alias="allVersions"
    )
    description: str = ""
    origin: str | None = None  # e.g. "LiteLLM v1.82.7"
    static_index: int | None = Field(
        default=None, alias="staticIndex", serialization_alias="staticIndex"
    )

    model_config = {"populate_by_name": True}


class MalwareFeedResponse(BaseModel):
    total: int
    entries: list[MalwareFeedEntry]
