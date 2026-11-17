"""Automatic VEX triage rules ("auto-VEX")."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas._utc import UtcDatetime

VexStatusLiteral = Literal["not_affected", "affected", "fixed", "under_investigation"]
ScopeLiteral = Literal["runtime", "dev", "optional", "unknown"]
TargetTypeLiteral = Literal["container_image", "source_repo", "sbom-import"]
SeverityLiteral = Literal["critical", "high", "medium", "low", "negligible"]
# fix_state values a distribution sets when it ships no fix (Trivy `Status`, Grype `fix.state`).
NoFixStateLiteral = Literal["wont_fix", "fix_deferred", "end_of_life"]

# CycloneDX analysis.justification and OpenVEX justification values; the
# rule's justification is written as-is into exports, so it stays in these.
VEX_JUSTIFICATIONS: tuple[str, ...] = (
    # CycloneDX
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
    # OpenVEX
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

_CWE_RE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)
_ECOSYSTEM_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,31}$")


def normalize_cwe(value: str) -> str | None:
    m = _CWE_RE.match((value or "").strip())
    return f"CWE-{int(m.group(1))}" if m else None


class VexRuleConditions(BaseModel):
    """All set conditions must hold (AND); an unset one matches everything."""

    target_pattern: str | None = Field(
        default=None, alias="targetPattern", serialization_alias="targetPattern", max_length=300,
        description="Wildcard (*, ?) on the target id or name, case-insensitive",
    )
    target_group: str | None = Field(
        default=None, alias="targetGroup", serialization_alias="targetGroup", max_length=200,
    )
    target_types: list[TargetTypeLiteral] = Field(
        default_factory=list, alias="targetTypes", serialization_alias="targetTypes",
    )
    dependency_scopes: list[ScopeLiteral] = Field(
        default_factory=list, alias="dependencyScopes", serialization_alias="dependencyScopes",
    )
    cwe_ids: list[str] = Field(
        default_factory=list, alias="cweIds", serialization_alias="cweIds", max_length=100,
        description="Any of these CWEs on the vulnerability (from the vulnerability database)",
    )
    package_pattern: str | None = Field(
        default=None, alias="packagePattern", serialization_alias="packagePattern", max_length=300,
        description="Wildcard (*, ?) on the package name, case-insensitive; several separated by commas",
    )
    ecosystems: list[str] = Field(
        default_factory=list, max_length=30,
        description="purl types, e.g. npm, pypi, maven, golang, deb",
    )
    max_severity: SeverityLiteral | None = Field(
        default=None, alias="maxSeverity", serialization_alias="maxSeverity",
        description="Severity at or below this one; unknown severity never matches",
    )
    platform_mismatch: bool = Field(
        default=False, alias="platformMismatch", serialization_alias="platformMismatch",
        description=(
            "Every vulnerable configuration of the vulnerability needs Windows or an Apple OS, "
            "and the target is a Linux container image"
        ),
    )

    vulnerability_rejected: bool = Field(
        default=False, alias="vulnerabilityRejected", serialization_alias="vulnerabilityRejected",
        description="The vulnerability record is REJECTED by its CNA (from the vulnerability database)",
    )
    fix_states: list[NoFixStateLiteral] = Field(
        default_factory=list, alias="fixStates", serialization_alias="fixStates",
        description="The distribution ships no fix: will not fix, fix deferred, or the release is end of life",
    )

    model_config = {"populate_by_name": True}

    @field_validator("target_pattern", "target_group", "package_pattern")
    @classmethod
    def _blank_is_unset(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        return value or None

    @field_validator("cwe_ids")
    @classmethod
    def _cwes(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for raw in values:
            cwe = normalize_cwe(raw)
            if not cwe:
                raise ValueError(f"Not a CWE id: {raw!r}")
            if cwe not in out:
                out.append(cwe)
        return out

    @field_validator("ecosystems")
    @classmethod
    def _ecosystems(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for raw in values:
            eco = (raw or "").strip().lower()
            if not _ECOSYSTEM_RE.match(eco):
                raise ValueError(f"Not a purl type: {raw!r}")
            if eco not in out:
                out.append(eco)
        return out

    @field_validator("target_types", "dependency_scopes", "fix_states")
    @classmethod
    def _dedupe(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    def is_empty(self) -> bool:
        return not (
            self.target_pattern or self.target_group or self.target_types or self.dependency_scopes
            or self.cwe_ids or self.package_pattern or self.ecosystems or self.max_severity
            or self.platform_mismatch or self.vulnerability_rejected or self.fix_states
        )

    def package_patterns(self) -> list[str]:
        """The package wildcards; ``package_pattern`` holds them separated by commas."""
        return [p.strip() for p in (self.package_pattern or "").split(",") if p.strip()]


class VexRuleAction(BaseModel):
    vex_status: VexStatusLiteral = Field(alias="vexStatus", serialization_alias="vexStatus")
    vex_justification: str | None = Field(
        default=None, alias="vexJustification", serialization_alias="vexJustification",
    )
    vex_detail: str | None = Field(
        default=None, alias="vexDetail", serialization_alias="vexDetail", max_length=2000,
    )
    dismiss: bool = Field(default=False, description="Also hide the finding from the default view")

    model_config = {"populate_by_name": True}

    @field_validator("vex_justification")
    @classmethod
    def _justification(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        if value not in VEX_JUSTIFICATIONS:
            raise ValueError(f"Unknown justification {value!r}")
        return value

    @field_validator("vex_detail")
    @classmethod
    def _detail(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        return value or None


class VexRuleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool = False
    priority: int = Field(default=100, ge=0, le=1000, description="Lower runs first; the first match wins")
    conditions: VexRuleConditions
    action: VexRuleAction
    preset: str | None = Field(default=None, max_length=60)

    model_config = {"populate_by_name": True}

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Name must not be blank")
        return value


class VexRuleResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    enabled: bool
    priority: int
    conditions: VexRuleConditions
    action: VexRuleAction
    preset: str | None = None
    finding_count: int = Field(
        default=0, alias="findingCount", serialization_alias="findingCount",
        description="Findings whose VEX status this rule set",
    )
    created_at: UtcDatetime | None = Field(default=None, alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime | None = Field(default=None, alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}


class VexRuleListResponse(BaseModel):
    items: list[VexRuleResponse]
    total: int


class VexRulePreset(BaseModel):
    key: str
    name: str
    description: str
    priority: int = 100
    conditions: VexRuleConditions
    action: VexRuleAction

    model_config = {"populate_by_name": True}


class VexRulePresetListResponse(BaseModel):
    items: list[VexRulePreset]
    justifications: list[str] = Field(default_factory=lambda: list(VEX_JUSTIFICATIONS))


class VexRuleApplyResponse(BaseModel):
    targets: int = 0
    scans: int = 0
    applied: int = 0
    cleared: int = 0
