"""Schemas for the Cross-CVE Attack Chain feature on the Scan Detail page.

The chain layers ATT&CK kill-chain stages over the existing per-CVE
``AttackPathGraph`` shape so the same Mermaid renderer on the frontend can
draw it without modification. The structural layer is fully deterministic;
the optional AI narrative is generated on demand and persisted on the scan
document (mirroring ``ai_analyses[]`` / ``ai_analysis``).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.ai import AIProviderLiteral
from app.schemas.attack_path import AttackPathGraph

AttackStage = Literal[
    "foothold",
    "credential_access",
    "priv_escalation",
    "lateral_movement",
    "impact",
]


class ChainFindingRef(BaseModel):
    vulnerability_id: str = Field(alias="vulnerabilityId", serialization_alias="vulnerabilityId")
    package_name: str = Field(alias="packageName", serialization_alias="packageName")
    package_version: str | None = Field(
        default=None, alias="packageVersion", serialization_alias="packageVersion"
    )
    severity: str | None = None
    cvss_score: float | None = Field(
        default=None, alias="cvssScore", serialization_alias="cvssScore"
    )
    primary_cwe: str | None = Field(
        default=None, alias="primaryCwe", serialization_alias="primaryCwe"
    )
    title: str | None = None

    model_config = {"populate_by_name": True}


class ScanAttackChainStage(BaseModel):
    stage: AttackStage
    label: str
    findings: list[ChainFindingRef] = Field(default_factory=list)
    capec_techniques: list[str] = Field(
        default_factory=list,
        alias="capecTechniques",
        serialization_alias="capecTechniques",
        description="CAPEC IDs (e.g. CAPEC-242) representing the attack patterns this stage enables.",
    )

    model_config = {"populate_by_name": True}


class ScanAttackChainNarrative(BaseModel):
    provider: AIProviderLiteral | str
    language: str
    summary: str
    generated_at: str = Field(alias="generatedAt", serialization_alias="generatedAt")
    token_usage: dict[str, int] | None = Field(
        default=None, alias="tokenUsage", serialization_alias="tokenUsage"
    )
    triggered_by: str | None = Field(
        default=None, alias="triggeredBy", serialization_alias="triggeredBy"
    )

    model_config = {"populate_by_name": True}


class ScanAttackChainResponse(BaseModel):
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")
    graph: AttackPathGraph
    stages: list[ScanAttackChainStage] = Field(default_factory=list)
    narrative: ScanAttackChainNarrative | None = None

    model_config = {"populate_by_name": True}


class ScanAttackChainRequest(BaseModel):
    """POST body for kicking off AI narrative generation."""

    provider: AIProviderLiteral
    language: str | None = None
    additional_context: str | None = Field(default=None, alias="additionalContext")
    triggered_by: str | None = Field(default=None, alias="triggeredBy")

    model_config = {"populate_by_name": True}


class ScanAttackChainSubmitResponse(BaseModel):
    status: str
    scan_id: str = Field(alias="scanId", serialization_alias="scanId")

    model_config = {"populate_by_name": True}
