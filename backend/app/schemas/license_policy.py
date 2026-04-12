from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


# --- Request schemas ---


class LicensePolicyCreateRequest(BaseModel):
    """Payload for creating a license policy."""

    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    allowed: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)
    reviewed: list[str] = Field(default_factory=list)
    default_action: str = Field(
        default="warn",
        alias="defaultAction",
        serialization_alias="defaultAction",
        description="allow | warn | deny",
    )
    is_default: bool = Field(
        default=False,
        alias="isDefault",
        serialization_alias="isDefault",
    )

    model_config = {"populate_by_name": True}


class LicensePolicyUpdateRequest(BaseModel):
    """Payload for updating a license policy."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    allowed: list[str] | None = None
    denied: list[str] | None = None
    reviewed: list[str] | None = None
    default_action: str | None = Field(
        default=None,
        alias="defaultAction",
        serialization_alias="defaultAction",
    )
    is_default: bool | None = Field(
        default=None,
        alias="isDefault",
        serialization_alias="isDefault",
    )

    model_config = {"populate_by_name": True}


# --- Response schemas ---


class LicensePolicyResponse(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    name: str
    description: str | None = None
    allowed: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)
    reviewed: list[str] = Field(default_factory=list)
    default_action: str = Field(alias="defaultAction", serialization_alias="defaultAction")
    is_default: bool = Field(alias="isDefault", serialization_alias="isDefault")
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}


class LicensePolicyListResponse(BaseModel):
    items: list[LicensePolicyResponse]
    total: int


class LicenseGroupsResponse(BaseModel):
    """Built-in SPDX license groups for quick policy creation."""

    permissive: list[str]
    weak_copyleft: list[str] = Field(alias="weakCopyleft", serialization_alias="weakCopyleft")
    copyleft: list[str]

    model_config = {"populate_by_name": True}


# --- Compliance evaluation response ---


class EvaluatedLicenseItem(BaseModel):
    license_id: str = Field(alias="licenseId", serialization_alias="licenseId")
    status: str

    model_config = {"populate_by_name": True}


class LicenseViolationItem(BaseModel):
    name: str
    version: str
    type: str
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)
    status: str
    evaluated_licenses: list[EvaluatedLicenseItem] = Field(
        default_factory=list,
        alias="evaluatedLicenses",
        serialization_alias="evaluatedLicenses",
    )

    model_config = {"populate_by_name": True}


class LicenseComplianceSummary(BaseModel):
    allowed: int = 0
    denied: int = 0
    warned: int = 0
    unknown: int = 0


class LicenseComplianceResultResponse(BaseModel):
    policy_id: str | None = Field(alias="policyId", serialization_alias="policyId")
    policy_name: str | None = Field(alias="policyName", serialization_alias="policyName")
    summary: LicenseComplianceSummary
    violations: list[LicenseViolationItem] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


# --- License overview ---


class LicenseOverviewComponentItem(BaseModel):
    name: str
    version: str


class LicenseOverviewItem(BaseModel):
    license_id: str = Field(alias="licenseId", serialization_alias="licenseId")
    component_count: int = Field(alias="componentCount", serialization_alias="componentCount")
    components: list[LicenseOverviewComponentItem] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class LicenseOverviewResponse(BaseModel):
    items: list[LicenseOverviewItem]
    total: int
