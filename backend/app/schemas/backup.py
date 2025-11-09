from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class BackupMetadata(BaseModel):
    dataset: Literal["vulnerabilities", "cpe"]
    exported_at: datetime = Field(serialization_alias="exportedAt")
    item_count: int = Field(serialization_alias="itemCount")

    model_config = {"populate_by_name": True}


class VulnerabilityBackupMetadata(BackupMetadata):
    dataset: Literal["vulnerabilities"] = "vulnerabilities"
    source: Literal["NVD", "EUVD", "ALL"] = "ALL"


class VulnerabilityBackupPayload(BaseModel):
    metadata: VulnerabilityBackupMetadata
    items: list[dict[str, Any]]


class CPEBackupMetadata(BackupMetadata):
    dataset: Literal["cpe"] = "cpe"


class CPEBackupPayload(BaseModel):
    metadata: CPEBackupMetadata
    items: list[dict[str, Any]]


class BackupRestoreSummary(BaseModel):
    dataset: Literal["vulnerabilities", "cpe"]
    source: str | None = None
    inserted: int
    updated: int
    skipped: int
    total: int
