from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


Deployment = Literal["onprem", "cloud", "hybrid"]


# --- Request schemas ---


class InventoryItemCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    vendor_slug: str = Field(
        min_length=1,
        max_length=200,
        alias="vendorSlug",
        serialization_alias="vendorSlug",
    )
    product_slug: str = Field(
        min_length=1,
        max_length=200,
        alias="productSlug",
        serialization_alias="productSlug",
    )
    vendor_name: str | None = Field(
        default=None,
        alias="vendorName",
        serialization_alias="vendorName",
    )
    product_name: str | None = Field(
        default=None,
        alias="productName",
        serialization_alias="productName",
    )
    version: str = Field(min_length=1, max_length=100)
    deployment: Deployment = Field(default="onprem")
    environment: str = Field(default="prod", min_length=1, max_length=50)
    instance_count: int = Field(
        default=1,
        ge=1,
        le=100000,
        alias="instanceCount",
        serialization_alias="instanceCount",
    )
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)
    eol_product: str | None = Field(
        default=None,
        max_length=200,
        alias="eolProduct",
        serialization_alias="eolProduct",
    )

    model_config = {"populate_by_name": True}


class InventoryItemUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    vendor_slug: str | None = Field(
        default=None,
        alias="vendorSlug",
        serialization_alias="vendorSlug",
    )
    product_slug: str | None = Field(
        default=None,
        alias="productSlug",
        serialization_alias="productSlug",
    )
    vendor_name: str | None = Field(
        default=None,
        alias="vendorName",
        serialization_alias="vendorName",
    )
    product_name: str | None = Field(
        default=None,
        alias="productName",
        serialization_alias="productName",
    )
    version: str | None = Field(default=None, min_length=1, max_length=100)
    deployment: Deployment | None = None
    environment: str | None = Field(default=None, min_length=1, max_length=50)
    instance_count: int | None = Field(
        default=None,
        ge=1,
        le=100000,
        alias="instanceCount",
        serialization_alias="instanceCount",
    )
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)
    eol_product: str | None = Field(
        default=None,
        max_length=200,
        alias="eolProduct",
        serialization_alias="eolProduct",
    )

    model_config = {"populate_by_name": True}


# --- Response schemas ---


class InventoryItemResponse(BaseModel):
    id: str
    name: str
    vendor_slug: str = Field(alias="vendorSlug", serialization_alias="vendorSlug")
    product_slug: str = Field(alias="productSlug", serialization_alias="productSlug")
    vendor_name: str | None = Field(
        default=None,
        alias="vendorName",
        serialization_alias="vendorName",
    )
    product_name: str | None = Field(
        default=None,
        alias="productName",
        serialization_alias="productName",
    )
    version: str
    deployment: Deployment
    environment: str
    instance_count: int = Field(alias="instanceCount", serialization_alias="instanceCount")
    owner: str | None = None
    notes: str | None = None
    eol_product: str | None = Field(
        default=None,
        alias="eolProduct",
        serialization_alias="eolProduct",
    )
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")
    affected_vuln_count: int | None = Field(
        default=None,
        alias="affectedVulnCount",
        serialization_alias="affectedVulnCount",
        description="Number of vulnerabilities currently affecting this item (optional, populated on list).",
    )

    model_config = {"populate_by_name": True}


class InventoryItemListResponse(BaseModel):
    items: list[InventoryItemResponse]
    total: int


class AffectedInventoryItem(BaseModel):
    """Compact representation of an affected inventory item shown on CVE detail pages."""

    id: str
    name: str
    vendor_name: str | None = Field(
        default=None,
        alias="vendorName",
        serialization_alias="vendorName",
    )
    product_name: str | None = Field(
        default=None,
        alias="productName",
        serialization_alias="productName",
    )
    version: str
    deployment: Deployment
    environment: str
    instance_count: int = Field(alias="instanceCount", serialization_alias="instanceCount")
    owner: str | None = None

    model_config = {"populate_by_name": True}


class AffectedVulnerabilityItem(BaseModel):
    """Compact representation of a vulnerability that affects an inventory item."""

    vuln_id: str = Field(alias="vulnId", serialization_alias="vulnId")
    title: str | None = None
    severity: str | None = None
    cvss_score: float | None = Field(
        default=None, alias="cvssScore", serialization_alias="cvssScore"
    )
    epss_score: float | None = Field(
        default=None, alias="epssScore", serialization_alias="epssScore"
    )
    exploited: bool | None = None
    published: UtcDatetime | None = None

    model_config = {"populate_by_name": True}


class AffectedVulnerabilitiesResponse(BaseModel):
    item_id: str = Field(alias="itemId", serialization_alias="itemId")
    total: int
    vulnerabilities: list[AffectedVulnerabilityItem]

    model_config = {"populate_by_name": True}


# --- endoflife.date enrichment ---


class EolProductOption(BaseModel):
    """A single endoflife.date product, for the manual-link picker."""

    name: str
    label: str
    category: str | None = None
    aliases: list[str] = Field(default_factory=list)


class EolProductListResponse(BaseModel):
    products: list[EolProductOption]
    total: int


class EolStatusResponse(BaseModel):
    """Resolved endoflife.date support status for an inventory item."""

    linked: bool = Field(description="True when the item is linked to an endoflife.date product")
    product: str | None = None
    product_label: str | None = Field(
        default=None, alias="productLabel", serialization_alias="productLabel"
    )
    product_link: str | None = Field(
        default=None, alias="productLink", serialization_alias="productLink"
    )
    matched_cycle: str | None = Field(
        default=None, alias="matchedCycle", serialization_alias="matchedCycle"
    )
    # "active" | "security" | "eol" | "unknown"
    status: str = "unknown"
    status_label: str = Field(
        default="Unknown", alias="statusLabel", serialization_alias="statusLabel"
    )
    release_date: str | None = Field(
        default=None, alias="releaseDate", serialization_alias="releaseDate"
    )
    eoas_date: str | None = Field(
        default=None, alias="eoasDate", serialization_alias="eoasDate"
    )
    eol_date: str | None = Field(
        default=None, alias="eolDate", serialization_alias="eolDate"
    )
    is_lts: bool = Field(default=False, alias="isLts", serialization_alias="isLts")
    lts_from: str | None = Field(
        default=None, alias="ltsFrom", serialization_alias="ltsFrom"
    )
    latest_version: str | None = Field(
        default=None, alias="latestVersion", serialization_alias="latestVersion"
    )
    latest_release_date: str | None = Field(
        default=None, alias="latestReleaseDate", serialization_alias="latestReleaseDate"
    )
    latest_link: str | None = Field(
        default=None, alias="latestLink", serialization_alias="latestLink"
    )
    is_outdated: bool = Field(
        default=False, alias="isOutdated", serialization_alias="isOutdated"
    )
    # The newest release line of the product (e.g. "26"), the line immediately
    # newer than the matched one (the "next major"), and whether the item is
    # already on the newest line.
    latest_cycle: str | None = Field(
        default=None, alias="latestCycle", serialization_alias="latestCycle"
    )
    next_cycle: str | None = Field(
        default=None, alias="nextCycle", serialization_alias="nextCycle"
    )
    is_latest_cycle: bool = Field(
        default=False, alias="isLatestCycle", serialization_alias="isLatestCycle"
    )

    model_config = {"populate_by_name": True}
