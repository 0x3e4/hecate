from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class VexUpdateRequest(BaseModel):
    """Update VEX status on a single finding."""

    vex_status: str | None = Field(
        default=None,
        alias="vexStatus",
        serialization_alias="vexStatus",
        description="not_affected, affected, fixed, under_investigation, or null to clear",
    )
    vex_justification: str | None = Field(
        default=None, alias="vexJustification", serialization_alias="vexJustification"
    )
    vex_detail: str | None = Field(
        default=None, alias="vexDetail", serialization_alias="vexDetail"
    )
    vex_response: list[str] | None = Field(
        default=None, alias="vexResponse", serialization_alias="vexResponse"
    )

    model_config = {"populate_by_name": True}


class VexBulkUpdateRequest(BaseModel):
    """Bulk-apply VEX status by vulnerability + target."""

    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    vulnerability_id: str = Field(alias="vulnerabilityId", serialization_alias="vulnerabilityId")
    vex_status: str = Field(
        alias="vexStatus",
        serialization_alias="vexStatus",
        description="not_affected, affected, fixed, under_investigation",
    )
    vex_justification: str | None = Field(
        default=None, alias="vexJustification", serialization_alias="vexJustification"
    )

    model_config = {"populate_by_name": True}


class VexBulkUpdateByIdsRequest(BaseModel):
    """Bulk-apply VEX status to a specific list of finding IDs."""

    finding_ids: list[str] = Field(alias="findingIds", serialization_alias="findingIds")
    vex_status: str = Field(
        alias="vexStatus",
        serialization_alias="vexStatus",
        description="not_affected, affected, fixed, under_investigation",
    )
    vex_justification: str | None = Field(
        default=None, alias="vexJustification", serialization_alias="vexJustification"
    )
    vex_detail: str | None = Field(
        default=None, alias="vexDetail", serialization_alias="vexDetail"
    )

    model_config = {"populate_by_name": True}


class FindingsDismissRequest(BaseModel):
    """Mark/unmark a list of findings as dismissed (personal-view filter)."""

    finding_ids: list[str] = Field(alias="findingIds", serialization_alias="findingIds")
    dismissed: bool = True
    reason: str | None = None

    model_config = {"populate_by_name": True}


class VexImportRequest(BaseModel):
    """Import a CycloneDX VEX document."""

    vex_document: dict[str, Any] = Field(alias="vexDocument", serialization_alias="vexDocument")
    target_id: str = Field(alias="targetId", serialization_alias="targetId")
    format: str = Field(default="cyclonedx-vex")

    model_config = {"populate_by_name": True}


class VexUpdateResponse(BaseModel):
    success: bool
    finding_id: str = Field(alias="findingId", serialization_alias="findingId")

    model_config = {"populate_by_name": True}


class VexBulkUpdateResponse(BaseModel):
    updated: int


class VexImportResponse(BaseModel):
    applied: int
    skipped: int
    not_found: int = Field(alias="notFound", serialization_alias="notFound")

    model_config = {"populate_by_name": True}
