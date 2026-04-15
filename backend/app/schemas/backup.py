from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


class BackupMetadata(BaseModel):
    dataset: Literal["vulnerabilities", "saved_searches", "inventory"]
    exported_at: UtcDatetime = Field(alias="exportedAt")
    item_count: int = Field(alias="itemCount")

    model_config = {"populate_by_name": True}


class VulnerabilityBackupMetadata(BackupMetadata):
    dataset: Literal["vulnerabilities"] = "vulnerabilities"
    source: Literal["NVD", "EUVD", "ALL"] = "ALL"


class VulnerabilityBackupPayload(BaseModel):
    metadata: VulnerabilityBackupMetadata
    items: list[dict[str, Any]]


class SavedSearchBackupMetadata(BackupMetadata):
    dataset: Literal["saved_searches"] = "saved_searches"


class SavedSearchBackupPayload(BaseModel):
    metadata: SavedSearchBackupMetadata
    items: list[dict[str, Any]]


class InventoryBackupMetadata(BackupMetadata):
    dataset: Literal["inventory"] = "inventory"


class InventoryBackupPayload(BaseModel):
    metadata: InventoryBackupMetadata
    items: list[dict[str, Any]]


class BackupRestoreSummary(BaseModel):
    dataset: Literal["vulnerabilities", "saved_searches", "inventory"]
    source: str | None = None
    inserted: int
    updated: int
    skipped: int
    total: int
