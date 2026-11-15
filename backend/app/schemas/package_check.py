"""Pre-install package check (``GET /api/v1/packages/check``, MCP ``check_package``)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PackageCheckReason(BaseModel):
    level: str = Field(description="block, warn or info")
    code: str = Field(
        description=(
            "malicious, malicious_versions, kev, critical, vulnerable, fresh_release, fresh_release_fix, "
            "publisher_changed, new_maintainers, unmaintained, deprecated, unknown_package, unknown_version"
        )
    )
    message: str


class PackageCheckMalicious(BaseModel):
    id: str
    summary: str = ""
    whole_package: bool = Field(alias="wholePackage", serialization_alias="wholePackage")
    covers_version: bool | None = Field(default=None, alias="coversVersion", serialization_alias="coversVersion")
    versions: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class PackageCheckVulnerability(BaseModel):
    id: str
    aliases: list[str] = Field(default_factory=list)
    title: str = ""
    severity: str = "unknown"
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    fixed_versions: list[str] = Field(default_factory=list, alias="fixedVersions", serialization_alias="fixedVersions")

    model_config = {"populate_by_name": True}


class PackageCheckRelease(BaseModel):
    package_found: bool = Field(alias="packageFound", serialization_alias="packageFound")
    version_found: bool = Field(alias="versionFound", serialization_alias="versionFound")
    published_at: str | None = Field(default=None, alias="publishedAt", serialization_alias="publishedAt")
    age_days: float | None = Field(default=None, alias="ageDays", serialization_alias="ageDays")
    latest_version: str | None = Field(default=None, alias="latestVersion", serialization_alias="latestVersion")
    latest_published_at: str | None = Field(
        default=None, alias="latestPublishedAt", serialization_alias="latestPublishedAt"
    )
    deprecated: bool | None = None
    publisher: str | None = None
    previous_publishers: list[str] = Field(
        default_factory=list, alias="previousPublishers", serialization_alias="previousPublishers"
    )
    new_maintainers: list[str] = Field(default_factory=list, alias="newMaintainers", serialization_alias="newMaintainers")
    fresh_release: bool | None = Field(default=None, alias="freshRelease", serialization_alias="freshRelease")
    unmaintained: bool | None = None
    publisher_changed: bool | None = Field(default=None, alias="publisherChanged", serialization_alias="publisherChanged")

    model_config = {"populate_by_name": True}


class PackageCheckResponse(BaseModel):
    ecosystem: str
    name: str
    version: str | None = None
    version_source: str = Field(
        alias="versionSource", serialization_alias="versionSource",
        description="requested, or latest when no version was given",
    )
    purl: str
    verdict: str = Field(description="block, warn or ok")
    reasons: list[PackageCheckReason] = Field(default_factory=list)
    malicious: list[PackageCheckMalicious] = Field(default_factory=list)
    vulnerabilities: list[PackageCheckVulnerability] = Field(default_factory=list)
    vulnerability_count: int = Field(default=0, alias="vulnerabilityCount", serialization_alias="vulnerabilityCount")
    advisories_for_package: int = Field(
        default=0, alias="advisoriesForPackage", serialization_alias="advisoriesForPackage"
    )
    release: PackageCheckRelease | None = None
    recommended_version: str | None = Field(
        default=None, alias="recommendedVersion", serialization_alias="recommendedVersion",
        description="Lowest named fix (or the latest release) no matched advisory covers",
    )
    checked_at: str = Field(alias="checkedAt", serialization_alias="checkedAt")

    model_config = {"populate_by_name": True}
