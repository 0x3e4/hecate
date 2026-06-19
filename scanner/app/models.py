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
    # Token for a checkout prepared once via POST /prepare-source and shared
    # across all scanners of a scan (avoids cloning the same repo per scanner).
    # Mutually exclusive with sourceArchiveBase64; the /scan handler checks the
    # archive first, then the token.
    source_token: str | None = Field(
        default=None, alias="sourceToken", serialization_alias="sourceToken"
    )

    model_config = {"populate_by_name": True}


class PrepareSourceRequest(BaseModel):
    target: str = Field(description="Source repo URL to clone once for a scan")
    type: str = Field(description="Must be source_repo")

    model_config = {"populate_by_name": True}


class PrepareSourceResponse(BaseModel):
    source_token: str | None = Field(
        default=None, alias="sourceToken", serialization_alias="sourceToken"
    )
    error: str | None = None

    model_config = {"populate_by_name": True}


class CleanupSourceRequest(BaseModel):
    source_token: str = Field(alias="sourceToken", serialization_alias="sourceToken")

    model_config = {"populate_by_name": True}


class CleanupSourceResponse(BaseModel):
    removed: bool = False


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
    error: str | None = None


