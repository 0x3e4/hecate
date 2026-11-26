"""Systems in the inventory: servers, VMs, Kubernetes nodes and other things you run.

A system is the place; what runs on it is evidence attached to it: the
packages of its latest SBOM or scanner report (an SBOM-import scan target,
``targetId``) and the inventory products linked to it (``systemIds`` on the
item). See app/services/inventory_system_service.py.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas._utc import UtcDatetime
from app.schemas.scan import ScanSummarySchema, TargetExposure, TargetKind

# reporting: an SBOM or report arrived within the stale window; stale: the last
# one is older; never: nothing has arrived (no linked target, or no scan yet).
ReportStatus = Literal["reporting", "stale", "never"]
SystemSource = Literal["manual", "sbom-import", "list"]
ListMode = Literal["merge", "replace"]
ListFormat = Literal["csv", "text", "ansible-ini", "ansible-yaml", "ansible-json", "json"]
_SOURCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$"

_MAX_GROUPS = 20


def _clean_groups(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    out: list[str] = []
    for value in values:
        text = value.strip()[:60] if isinstance(value, str) else ""
        if text and text.casefold() not in {g.casefold() for g in out}:
            out.append(text)
    return out[:_MAX_GROUPS]


class InventorySystemCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200, description="Host name or FQDN; unique, case-insensitive")
    kind: TargetKind | None = Field(default=None, description="host, kubernetes-node, container or other")
    exposure: TargetExposure | None = Field(default=None, description="internet or internal")
    environment: str | None = Field(default=None, max_length=50)
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)
    groups: list[str] = Field(default_factory=list, description="Free labels: cluster, site, team")

    model_config = {"populate_by_name": True}

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("groups")
    @classmethod
    def _groups(cls, value: list[str]) -> list[str]:
        return _clean_groups(value) or []


class InventorySystemUpdateRequest(BaseModel):
    """Partial update. ``null`` clears kind, exposure, environment, owner and notes."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    kind: TargetKind | None = None
    exposure: TargetExposure | None = None
    environment: str | None = Field(default=None, max_length=50)
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)
    groups: list[str] | None = None

    model_config = {"populate_by_name": True}

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("groups")
    @classmethod
    def _groups(cls, value: list[str] | None) -> list[str] | None:
        return _clean_groups(value)


class InventorySystemProduct(BaseModel):
    id: str
    name: str
    version: str


class InventorySystemResponse(BaseModel):
    id: str
    name: str
    kind: TargetKind | None = None
    exposure: TargetExposure | None = None
    environment: str | None = None
    owner: str | None = None
    notes: str | None = None
    groups: list[str] = Field(default_factory=list)
    source: SystemSource = "manual"
    target_id: str | None = Field(
        default=None, alias="targetId", serialization_alias="targetId",
        description="The SBOM-import target holding the system's package list, findings and history",
    )
    last_report_at: UtcDatetime | None = Field(
        default=None, alias="lastReportAt", serialization_alias="lastReportAt",
        description="When the last SBOM or scanner report arrived",
    )
    report_status: ReportStatus = Field(default="never", alias="reportStatus", serialization_alias="reportStatus")
    latest_scan_id: str | None = Field(default=None, alias="latestScanId", serialization_alias="latestScanId")
    latest_summary: ScanSummarySchema | None = Field(
        default=None, alias="latestSummary", serialization_alias="latestSummary",
    )
    products: list[InventorySystemProduct] = Field(
        default_factory=list, description="Inventory products linked to this system",
    )
    list_sources: list[str] = Field(
        default_factory=list, alias="listSources", serialization_alias="listSources",
        description="The server lists that name this system (import source names)",
    )
    retired_at: UtcDatetime | None = Field(
        default=None, alias="retiredAt", serialization_alias="retiredAt",
        description="Set when the last list naming the system dropped it; cleared when a list or a push names it again",
    )
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}


class InventorySystemListResponse(BaseModel):
    total: int
    stale_after_days: int = Field(alias="staleAfterDays", serialization_alias="staleAfterDays")
    items: list[InventorySystemResponse]

    model_config = {"populate_by_name": True}


class InventorySystemImportRequest(BaseModel):
    """A server list to apply (``POST /inventory/systems/import``)."""

    content: str = Field(min_length=1, max_length=5 * 1024 * 1024, description="The list as text")
    format: ListFormat | None = Field(default=None, description="Detected when omitted")
    source: str = Field(
        default="upload", pattern=_SOURCE_PATTERN,
        description="Name of the list (e.g. ansible-prod); replace mode only retires systems this source named",
    )
    mode: ListMode = Field(
        default="merge",
        description="merge adds and updates; replace also retires the systems this source named before and no longer does",
    )
    dry_run: bool = Field(default=False, alias="dryRun", serialization_alias="dryRun", description="Report, change nothing")
    force: bool = Field(
        default=False, description="Allow a replace that retires more than half of the source's systems",
    )

    model_config = {"populate_by_name": True}


class ListSkip(BaseModel):
    where: str
    reason: str


class InventorySystemImportResponse(BaseModel):
    format: ListFormat
    source: str
    mode: ListMode
    dry_run: bool = Field(alias="dryRun", serialization_alias="dryRun")
    listed: int = Field(description="Distinct systems the list names")
    created: list[str] = Field(description="Names of systems added (at most 200 listed)")
    updated: list[str] = Field(description="Names of systems whose fields or groups changed (at most 200)")
    retired: list[str] = Field(description="Names of systems retired: named by this source before, not now (at most 200)")
    restored: list[str] = Field(description="Names of retired systems the list names again (at most 200)")
    created_count: int = Field(alias="createdCount", serialization_alias="createdCount")
    updated_count: int = Field(alias="updatedCount", serialization_alias="updatedCount")
    unchanged_count: int = Field(alias="unchangedCount", serialization_alias="unchangedCount")
    retired_count: int = Field(alias="retiredCount", serialization_alias="retiredCount")
    restored_count: int = Field(alias="restoredCount", serialization_alias="restoredCount")
    skipped: list[ListSkip] = Field(description="Lines or values that were left out, and why (at most 200)")

    model_config = {"populate_by_name": True}
