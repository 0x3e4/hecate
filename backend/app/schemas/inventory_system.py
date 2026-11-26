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
SystemSource = Literal["manual", "sbom-import"]

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
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}


class InventorySystemListResponse(BaseModel):
    total: int
    stale_after_days: int = Field(alias="staleAfterDays", serialization_alias="staleAfterDays")
    items: list[InventorySystemResponse]

    model_config = {"populate_by_name": True}
