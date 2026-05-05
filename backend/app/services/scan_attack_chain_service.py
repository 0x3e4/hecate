"""Cross-CVE Attack Chain builder.

Synthesises a single multi-step attacker narrative across all findings of one
SCA scan by bucketing each finding into an ATT&CK kill-chain stage and laying
out the resulting graph left-to-right. The structural layer is deterministic
(no AI in the loop); the prose narrative is generated on demand by
``AIClient.analyze_scan_attack_chain``.

Reuses the existing per-CVE ``AttackPathGraph`` node/edge schema so the same
``<AttackPathGraphView>`` Mermaid renderer can draw the chain without
modification.
"""
from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Iterable

import structlog

from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.attack_path import (
    AttackPathEdge,
    AttackPathGraph,
    AttackPathLabels,
    AttackPathNode,
)
from app.schemas.scan_attack_chain import (
    AttackStage,
    ChainFindingRef,
    ScanAttackChainStage,
)
from app.services.attack_chain_stages import (
    STAGE_ORDER,
    categorize_cve,
    stage_label,
)
from app.services.capec_service import CAPECDescription, get_capec_service

log = structlog.get_logger()

# Per-stage caps keep the graph readable; the most useful CVEs are the ones
# with the highest CVSS, so the dedupe-then-sort keeps the chain focused on
# the most pressing items first.
_MAX_CVES_PER_STAGE = 5
_MAX_CAPECS_PER_STAGE = 2

DISCLAIMER_EN = (
    "Plausible chained attack scenario assembled from the findings of this "
    "scan. Stages reflect known weakness classes; not proof of exploitability "
    "unless reachability is confirmed."
)
DISCLAIMER_DE = (
    "Plausibles verkettetes Angriffsszenario aus den Findings dieses Scans. "
    "Stufen spiegeln bekannte Schwachstellenklassen wider; kein Beweis der "
    "Ausnutzbarkeit, solange die Erreichbarkeit nicht bestätigt ist."
)


class ScanAttackChainService:
    """Builds the per-scan attack-chain graph + stage breakdown."""

    async def build_chain(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        *,
        language: str = "en",
    ) -> tuple[AttackPathGraph, list[ScanAttackChainStage]]:
        """Compose the deterministic chain. Pure-ish: catalog reads only."""
        # 1. Filter and dedupe findings.
        candidate_findings = [
            f
            for f in findings
            if f.get("vulnerability_id")
            and not f.get("dismissed")
            and (f.get("package_type") in (None, "library", "container", "")
                 or f.get("vulnerability_id", "").startswith(("CVE-", "GHSA-")))
        ]

        seen: set[tuple[str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for f in candidate_findings:
            key = (str(f.get("vulnerability_id")), str(f.get("package_name") or ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        if not deduped:
            return self._empty_graph(language), []

        # 2. Bulk-fetch CWEs from the vulnerability documents.
        vuln_ids = list({f["vulnerability_id"] for f in deduped})
        cwe_index = await self._fetch_cwes(vuln_ids)

        # 3. Bucket findings by stage.
        per_stage: dict[AttackStage, list[tuple[dict[str, Any], list[str]]]] = {
            stage: [] for stage in STAGE_ORDER
        }
        for f in deduped:
            cwes = cwe_index.get(str(f["vulnerability_id"])) or []
            stage = categorize_cve(cwes, str(f.get("severity") or ""))
            per_stage[stage].append((f, cwes))

        # 4. Sort + cap each stage by CVSS desc.
        capec_service = get_capec_service()
        chain_stages: list[ScanAttackChainStage] = []
        for stage in STAGE_ORDER:
            entries = per_stage[stage]
            if not entries:
                continue
            entries.sort(
                key=lambda item: (
                    -(float(item[0].get("cvss_score") or 0.0)),
                    str(item[0].get("vulnerability_id") or ""),
                )
            )
            entries = entries[:_MAX_CVES_PER_STAGE]

            stage_cwes = self._unique_cwes([cwes for _, cwes in entries])
            capec_ids = await self._fetch_capec_ids(capec_service, stage_cwes)

            chain_stages.append(
                ScanAttackChainStage(
                    stage=stage,
                    label=stage_label(stage, language),
                    findings=[self._to_chain_ref(f, cwes) for f, cwes in entries],
                    capecTechniques=[f"CAPEC-{cid}" for cid in capec_ids],
                )
            )

        # 5. Render to AttackPathGraph (nodes + edges).
        graph = self._render_graph(chain_stages, scan=scan, language=language)
        return graph, chain_stages

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _fetch_cwes(self, vuln_ids: list[str]) -> dict[str, list[str]]:
        if not vuln_ids:
            return {}
        try:
            repo = await VulnerabilityRepository.create()
            cursor = repo.collection.find(
                {"_id": {"$in": vuln_ids}},
                {"_id": 1, "cwes": 1, "severity": 1},
            )
            out: dict[str, list[str]] = {}
            async for doc in cursor:
                cwes = doc.get("cwes") or []
                if isinstance(cwes, list):
                    out[str(doc["_id"])] = [str(c) for c in cwes]
            return out
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("scan_attack_chain.cwe_lookup_failed", error=str(exc))
            return {}

    async def _fetch_capec_ids(
        self, capec_service: Any, cwes: list[str]
    ) -> list[str]:
        if not cwes:
            return []
        try:
            capecs: dict[str, CAPECDescription] = await capec_service.get_capecs_for_cwes(cwes)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("scan_attack_chain.capec_lookup_failed", error=str(exc))
            return []
        # Sort by severity (Very High first), keep top N IDs only.
        items = sorted(
            capecs.items(),
            key=lambda kv: (
                self._capec_severity_rank(kv[1]),
                int(kv[0]) if kv[0].isdigit() else 9999,
            ),
        )
        return [cid for cid, _ in items[:_MAX_CAPECS_PER_STAGE]]

    @staticmethod
    def _capec_severity_rank(capec: CAPECDescription) -> int:
        return {"very high": 0, "high": 1, "medium": 2, "low": 3}.get(
            (capec.severity or "").lower(), 4
        )

    @staticmethod
    def _unique_cwes(cwe_lists: Iterable[list[str]]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for cwes in cwe_lists:
            for cwe in cwes:
                normalized = str(cwe).upper().replace("CWE-", "").strip()
                if not normalized or normalized in seen or not normalized.isdigit():
                    continue
                seen.add(normalized)
                out.append(normalized)
        return out

    @staticmethod
    def _to_chain_ref(finding: dict[str, Any], cwes: list[str]) -> ChainFindingRef:
        primary = None
        if cwes:
            normalized = str(cwes[0]).upper().replace("CWE-", "").strip()
            if normalized.isdigit():
                primary = f"CWE-{normalized}"
        return ChainFindingRef(
            vulnerabilityId=str(finding.get("vulnerability_id") or ""),
            packageName=str(finding.get("package_name") or ""),
            packageVersion=(finding.get("package_version") or None),
            severity=(finding.get("severity") or None),
            cvssScore=(
                float(finding["cvss_score"])
                if finding.get("cvss_score") is not None
                else None
            ),
            primaryCwe=primary,
            title=(finding.get("title") or None),
        )

    def _render_graph(
        self,
        stages: list[ScanAttackChainStage],
        *,
        scan: dict[str, Any],
        language: str,
    ) -> AttackPathGraph:
        nodes: list[AttackPathNode] = []
        edges: list[AttackPathEdge] = []

        target_label = (
            scan.get("target_name") or scan.get("targetName") or scan.get("target_id") or "scan target"
        )
        entry_node = AttackPathNode(
            id="entry",
            type="entry",
            label=f"Attacker → {target_label}",
            description="Untrusted input or network reach into the scan target.",
            metadata={"scanId": str(scan.get("_id") or scan.get("scan_id") or "")},
        )
        nodes.append(entry_node)

        previous_anchor_id = entry_node.id

        for chain_stage in stages:
            anchor_id = f"stage-{chain_stage.stage}"
            anchor_node = AttackPathNode(
                id=anchor_id,
                # Reuse "capec" so the existing renderer picks the purple stage color.
                type="capec",
                label=chain_stage.label,
                description=self._stage_blurb(chain_stage),
                metadata={"stage": chain_stage.stage, "findingCount": len(chain_stage.findings)},
            )
            nodes.append(anchor_node)
            edges.append(
                AttackPathEdge(source=previous_anchor_id, target=anchor_id, label="enables")
            )

            for idx, ref in enumerate(chain_stage.findings):
                cve_id = f"{chain_stage.stage}-{idx}-{self._safe_id(ref.vulnerability_id)}"
                cve_label = ref.vulnerability_id
                if ref.package_name:
                    suffix = ref.package_name
                    if ref.package_version:
                        suffix = f"{suffix} {ref.package_version}"
                    cve_label = f"{ref.vulnerability_id}\\n{suffix}"
                nodes.append(
                    AttackPathNode(
                        id=cve_id,
                        type="cve",
                        label=cve_label,
                        description=(ref.title or None),
                        severity=ref.severity,
                        metadata={
                            "cvssScore": ref.cvss_score,
                            "vulnerabilityId": ref.vulnerability_id,
                            "primaryCwe": ref.primary_cwe,
                        },
                    )
                )
                edges.append(AttackPathEdge(source=anchor_id, target=cve_id))

            previous_anchor_id = anchor_id

        labels = self._aggregate_labels(stages)
        disclaimer = DISCLAIMER_DE if (language or "").lower().startswith("de") else DISCLAIMER_EN

        return AttackPathGraph(
            nodes=nodes,
            edges=edges,
            labels=labels,
            disclaimer=disclaimer,
            generatedAt=_isoformat_utc_now(),
        )

    @staticmethod
    def _stage_blurb(stage: ScanAttackChainStage) -> str | None:
        if stage.capec_techniques:
            joined = ", ".join(stage.capec_techniques)
            return f"{len(stage.findings)} CVEs · {joined}"
        return f"{len(stage.findings)} CVEs"

    @staticmethod
    def _aggregate_labels(stages: list[ScanAttackChainStage]) -> AttackPathLabels:
        # Pick the worst CVSS across all chain findings as a rough overall
        # likelihood / business-impact signal. Kept conservative: we never
        # claim "confirmed reachability" at the chain level.
        max_cvss = 0.0
        critical_count = 0
        total = 0
        for stage in stages:
            for ref in stage.findings:
                total += 1
                if ref.cvss_score and ref.cvss_score > max_cvss:
                    max_cvss = float(ref.cvss_score)
                if (ref.severity or "").lower() == "critical":
                    critical_count += 1

        if max_cvss >= 9.0:
            likelihood = "very_high"
        elif max_cvss >= 7.0:
            likelihood = "high"
        elif max_cvss >= 4.0:
            likelihood = "medium"
        elif total > 0:
            likelihood = "low"
        else:
            likelihood = "unknown"

        if critical_count >= 1:
            business_impact = "high"
        elif total >= 3:
            business_impact = "medium"
        elif total > 0:
            business_impact = "low"
        else:
            business_impact = None

        return AttackPathLabels(
            likelihood=likelihood,
            exploitMaturity="unknown",
            reachability="unknown",
            privilegesRequired=None,
            userInteraction=None,
            businessImpact=business_impact,
        )

    def _empty_graph(self, language: str) -> AttackPathGraph:
        disclaimer = DISCLAIMER_DE if (language or "").lower().startswith("de") else DISCLAIMER_EN
        return AttackPathGraph(
            nodes=[],
            edges=[],
            labels=AttackPathLabels(
                likelihood="unknown",
                exploitMaturity="unknown",
                reachability="unknown",
            ),
            disclaimer=disclaimer,
            generatedAt=_isoformat_utc_now(),
        )

    @staticmethod
    def _safe_id(value: str) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in (value or ""))[:60]


def _isoformat_utc_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


@lru_cache(maxsize=1)
def get_scan_attack_chain_service() -> ScanAttackChainService:
    return ScanAttackChainService()
