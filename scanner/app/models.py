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


class ScanResponse(BaseModel):
    target: str
    type: str
    results: list[ScannerResult]
