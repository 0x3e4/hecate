"""Attack Path Graph builder.

Deterministically composes a per-vulnerability attack chain from data already populated
on the vulnerability document and adjacent catalogs (CWE, CAPEC, EPSS, KEV, inventory).
No AI is involved in producing the graph itself; the AI narrative (if any) is layered
in by the API layer.
"""
from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Iterable

import structlog

from app.schemas.attack_path import (
    AttackPathEdge,
    AttackPathGraph,
    AttackPathLabels,
    AttackPathNode,
    ExploitMaturity,
    LikelihoodLevel,
    Reachability,
)
from app.schemas.vulnerability import VulnerabilityDetail
from app.services.capec_service import CAPECDescription, get_capec_service
from app.services.cwe_service import CWEDescription, get_cwe_service
from app.services.inventory_service import InventoryService

log = structlog.get_logger()

# Hard caps mirror the existing AI prompt limits so the graph stays readable.
_MAX_CWES = 3
_MAX_CAPECS_PER_CWE = 2
_MAX_TOTAL_CAPECS = 4

DISCLAIMER_EN = (
    "Plausible attack scenarios based on known weakness classes and available "
    "context. Not proof of exploitability unless reachability is confirmed."
)
DISCLAIMER_DE = (
    "Plausible Angriffsszenarien basierend auf bekannten Schwachstellenklassen "
    "und vorhandenem Kontext. Kein Beweis der Ausnutzbarkeit, solange die "
    "Erreichbarkeit nicht bestätigt ist."
)


class AttackPathService:
    """Composes the deterministic attack-chain graph for a single vulnerability."""

    def __init__(
        self,
        inventory_service: InventoryService | None = None,
    ) -> None:
        self._inventory_service = inventory_service

    async def build_graph(
        self,
        vuln: VulnerabilityDetail,
        *,
        package_name: str | None = None,
        package_version: str | None = None,
        scan_target: str | None = None,
        affected_inventory: list[dict[str, Any]] | None = None,
        language: str = "en",
    ) -> AttackPathGraph:
        """Build the structural graph. Pure-ish: no DB writes, only catalog reads."""
        cwe_ids = self._normalize_cwes(vuln.cwes)

        cwe_service = get_cwe_service()
        cwe_data: dict[str, CWEDescription] = {}
        if cwe_ids:
            try:
                cwe_data = await cwe_service.get_bulk_cwe_data(cwe_ids[:_MAX_CWES])
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("attack_path.cwe_lookup_failed", vuln_id=vuln.vuln_id, error=str(exc))

        capec_service = get_capec_service()
        capec_map: dict[str, CAPECDescription] = {}
        if cwe_ids:
            try:
                capec_map = await capec_service.get_capecs_for_cwes(cwe_ids[:_MAX_CWES])
            except Exception as exc:  # pragma: no cover - defensive
                log.warning(
                    "attack_path.capec_lookup_failed", vuln_id=vuln.vuln_id, error=str(exc)
                )

        if affected_inventory is None:
            affected_inventory = self._inventory_payload(vuln)

        nodes: list[AttackPathNode] = []
        edges: list[AttackPathEdge] = []

        entry_node = self._build_entry_node(vuln, scan_target=scan_target)
        nodes.append(entry_node)

        asset_nodes = self._build_asset_nodes(affected_inventory)
        nodes.extend(asset_nodes)
        for asset in asset_nodes:
            edges.append(AttackPathEdge(source=entry_node.id, target=asset.id))

        package_node = self._build_package_node(
            vuln, package_name=package_name, package_version=package_version
        )
        if package_node is not None:
            nodes.append(package_node)
            previous = asset_nodes if asset_nodes else [entry_node]
            for prev in previous:
                edges.append(AttackPathEdge(source=prev.id, target=package_node.id, label="uses"))

        cve_node = self._build_cve_node(vuln)
        nodes.append(cve_node)
        prev_id = package_node.id if package_node else (
            asset_nodes[0].id if asset_nodes else entry_node.id
        )
        edges.append(AttackPathEdge(source=prev_id, target=cve_node.id, label="vulnerable to"))

        cwe_nodes: list[AttackPathNode] = []
        for cwe_id in cwe_ids[:_MAX_CWES]:
            normalized = cwe_id.upper().replace("CWE-", "").strip()
            data = cwe_data.get(normalized)
            cwe_node = AttackPathNode(
                id=f"cwe-{normalized}",
                type="cwe",
                label=f"CWE-{normalized}: {data.name if data else 'Weakness'}",
                description=(data.description[:300] if data and data.description else None),
                metadata={"cweId": f"CWE-{normalized}"},
            )
            cwe_nodes.append(cwe_node)
            nodes.append(cwe_node)
            edges.append(AttackPathEdge(source=cve_node.id, target=cwe_node.id, label="weakness"))

        capec_nodes_added = 0
        capec_to_cwe: dict[str, str] = {}
        if capec_map and cwe_nodes:
            ordered_capecs = list(capec_map.items())[:_MAX_TOTAL_CAPECS]
            for capec_id, capec in ordered_capecs:
                # Pick the first CWE node whose ID overlaps with capec.related_cwes;
                # fall back to the first CWE node when the catalog mapping is missing.
                target_cwe_node = cwe_nodes[0]
                for cwe_node in cwe_nodes:
                    cwe_num = cwe_node.id.replace("cwe-", "")
                    if any(
                        rel.upper().replace("CWE-", "").strip() == cwe_num
                        for rel in capec.related_cwes
                    ):
                        target_cwe_node = cwe_node
                        break
                capec_node = AttackPathNode(
                    id=f"capec-{capec_id}",
                    type="capec",
                    label=f"CAPEC-{capec_id}: {capec.name}",
                    description=(capec.description[:300] if capec.description else None),
                    metadata={
                        "capecId": f"CAPEC-{capec_id}",
                        "severity": capec.severity or None,
                        "likelihood": capec.likelihood or None,
                    },
                )
                nodes.append(capec_node)
                edges.append(
                    AttackPathEdge(source=target_cwe_node.id, target=capec_node.id, label="enables")
                )
                capec_to_cwe[capec_node.id] = target_cwe_node.id
                capec_nodes_added += 1

        # If the CWE/CAPEC data was missing entirely, drop a placeholder so the chain
        # still hangs together visually.
        attack_origin_ids = [n.id for n in nodes if n.type == "capec"] or [
            n.id for n in cwe_nodes
        ] or [cve_node.id]

        exploit_node = AttackPathNode(
            id="exploit",
            type="exploit",
            label=self._exploit_label(vuln, capec_map, language),
            description=self._exploit_description(vuln, capec_map),
            severity=(vuln.severity or None),
        )
        nodes.append(exploit_node)
        for origin in attack_origin_ids:
            edges.append(AttackPathEdge(source=origin, target=exploit_node.id, label="exploit"))

        impact_node = AttackPathNode(
            id="impact",
            type="impact",
            label=self._impact_label(vuln, cwe_data, language),
            description=self._impact_description(vuln, cwe_data),
            severity=(vuln.severity or None),
        )
        nodes.append(impact_node)
        edges.append(AttackPathEdge(source=exploit_node.id, target=impact_node.id))

        fix_node = AttackPathNode(
            id="fix",
            type="fix",
            label=self._fix_label(vuln, language),
            description=self._fix_description(vuln),
        )
        nodes.append(fix_node)
        edges.append(AttackPathEdge(source=impact_node.id, target=fix_node.id, label="remediate"))

        labels = self.derive_labels(vuln, affected_inventory=affected_inventory)
        disclaimer = DISCLAIMER_DE if (language or "").lower().startswith("de") else DISCLAIMER_EN

        return AttackPathGraph(
            nodes=nodes,
            edges=edges,
            labels=labels,
            disclaimer=disclaimer,
            generatedAt=_isoformat_utc_now(),
        )

    # ------------------------------------------------------------------
    # Label derivation
    # ------------------------------------------------------------------

    def derive_labels(
        self,
        vuln: VulnerabilityDetail,
        *,
        affected_inventory: list[dict[str, Any]] | None = None,
    ) -> AttackPathLabels:
        return AttackPathLabels(
            likelihood=self._likelihood(vuln),
            exploitMaturity=self._exploit_maturity(vuln),
            reachability=self._reachability(vuln),
            privilegesRequired=self._cvss_metric(vuln, ("PR", "privilegesRequired")),
            userInteraction=self._cvss_metric(vuln, ("UI", "userInteraction")),
            businessImpact=self._business_impact(vuln, affected_inventory),
        )

    @staticmethod
    def _likelihood(vuln: VulnerabilityDetail) -> LikelihoodLevel:
        # KEV trumps EPSS as ground truth.
        if vuln.exploited or vuln.exploitation is not None:
            return "very_high"
        epss = vuln.epss_score
        if epss is None:
            return "unknown"
        if epss >= 0.9:
            return "very_high"
        if epss >= 0.5:
            return "high"
        if epss >= 0.1:
            return "medium"
        if epss >= 0.01:
            return "low"
        return "very_low"

    @staticmethod
    def _exploit_maturity(vuln: VulnerabilityDetail) -> ExploitMaturity:
        if vuln.exploitation is not None or vuln.exploited:
            return "high"
        # Heuristic: explicit references to GHSA / exploit-db / packetstorm hint at PoC.
        for ref in vuln.references or []:
            ref_lower = ref.lower()
            if "exploit-db.com" in ref_lower or "packetstormsecurity" in ref_lower:
                return "functional"
            if "/security/advisories/ghsa-" in ref_lower or "github.com/advisories/ghsa-" in ref_lower:
                return "poc"
        if (vuln.epss_score or 0.0) >= 0.5:
            return "poc"
        return "unknown"

    @staticmethod
    def _reachability(vuln: VulnerabilityDetail) -> Reachability:
        # MVP: reachability stays unknown. Phase 2 will set this from scanner data.
        _ = vuln
        return "unknown"

    @staticmethod
    def _cvss_metric(
        vuln: VulnerabilityDetail, keys: Iterable[str]
    ) -> str | None:
        metrics = getattr(vuln, "cvss_metrics", None) or {}
        if not isinstance(metrics, dict):
            return None
        # cvss_metrics is keyed by version; check 4.0 first then 3.1 / 3.0.
        for version_key in ("4.0", "3.1", "3.0"):
            block = metrics.get(version_key) or metrics.get(version_key.replace(".", "_"))
            if not isinstance(block, dict):
                continue
            for key in keys:
                value = block.get(key)
                if isinstance(value, str) and value.strip():
                    return value
        # Fallback: try parsing the vector string on vuln.cvss
        cvss = getattr(vuln, "cvss", None)
        vector = getattr(cvss, "vector", None) if cvss else None
        if isinstance(vector, str):
            for token in vector.split("/"):
                if not token or ":" not in token:
                    continue
                k, v = token.split(":", 1)
                if k in keys:
                    return v
        return None

    @staticmethod
    def _business_impact(
        vuln: VulnerabilityDetail, inventory: list[dict[str, Any]] | None
    ) -> str | None:
        severity = (vuln.severity or "").lower()
        if not inventory:
            if severity in ("critical", "high"):
                return "high"
            if severity == "medium":
                return "medium"
            return None
        total = 0
        for item in inventory:
            if not isinstance(item, dict):
                continue
            try:
                total += int(item.get("instanceCount") or item.get("instance_count") or 1)
            except (TypeError, ValueError):
                total += 1
        if severity in ("critical", "high") and total > 0:
            return "high"
        if severity == "medium" and total > 0:
            return "medium"
        return "low" if total > 0 else None

    # ------------------------------------------------------------------
    # Node builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_entry_node(
        vuln: VulnerabilityDetail, *, scan_target: str | None
    ) -> AttackPathNode:
        if scan_target:
            return AttackPathNode(
                id="entry",
                type="entry",
                label=f"Attacker → {scan_target}",
                description="Untrusted input or network reach into the scan target.",
                metadata={"scanTarget": scan_target},
            )
        # Heuristic: when KEV is known-exploited the entry is implicitly "internet attacker".
        if vuln.exploited or vuln.exploitation is not None:
            return AttackPathNode(
                id="entry",
                type="entry",
                label="External attacker",
                description="Internet-facing exposure has been observed in the wild.",
            )
        return AttackPathNode(
            id="entry",
            type="entry",
            label="Untrusted input",
            description="Any code path that accepts attacker-controllable data.",
        )

    @staticmethod
    def _build_asset_nodes(
        inventory: list[dict[str, Any]] | None,
    ) -> list[AttackPathNode]:
        if not inventory:
            return []
        nodes: list[AttackPathNode] = []
        for idx, item in enumerate(inventory[:3]):
            if not isinstance(item, dict):
                continue
            name = (
                item.get("name")
                or item.get("productName")
                or item.get("product_name")
                or "Asset"
            )
            version = item.get("version") or ""
            deployment = item.get("deployment") or ""
            environment = item.get("environment") or ""
            try:
                count = int(item.get("instanceCount") or item.get("instance_count") or 1)
            except (TypeError, ValueError):
                count = 1
            descr_bits: list[str] = []
            if version:
                descr_bits.append(f"v{version}")
            if deployment:
                descr_bits.append(str(deployment))
            if environment:
                descr_bits.append(str(environment))
            if count > 1:
                descr_bits.append(f"{count} instances")
            nodes.append(
                AttackPathNode(
                    id=f"asset-{idx}",
                    type="asset",
                    label=str(name),
                    description=" / ".join(descr_bits) or None,
                    metadata={
                        "version": version or None,
                        "deployment": deployment or None,
                        "environment": environment or None,
                        "instanceCount": count,
                    },
                )
            )
        return nodes

    @staticmethod
    def _build_package_node(
        vuln: VulnerabilityDetail,
        *,
        package_name: str | None,
        package_version: str | None,
    ) -> AttackPathNode | None:
        # Prefer the scan-finding context when present; fall back to the first
        # impacted product on the vulnerability.
        if package_name:
            label = package_name
            if package_version:
                label = f"{package_name} {package_version}"
            return AttackPathNode(
                id="package",
                type="package",
                label=label,
                description=None,
                metadata={"name": package_name, "version": package_version or None},
            )
        impacted = list(vuln.impacted_products or [])
        if not impacted:
            return None
        first = impacted[0]
        vendor = first.vendor.name if first.vendor else None
        product = first.product.name if first.product else None
        if not product and not vendor:
            return None
        label_bits: list[str] = []
        if vendor and product:
            label_bits.append(f"{vendor} {product}")
        elif product:
            label_bits.append(product)
        elif vendor:
            label_bits.append(vendor)
        version_str: str | None = None
        if first.versions:
            version_str = first.versions[0]
            label_bits.append(version_str)
        return AttackPathNode(
            id="package",
            type="package",
            label=" — ".join(label_bits) or "Affected component",
            metadata={
                "vendor": vendor,
                "product": product,
                "version": version_str,
            },
        )

    @staticmethod
    def _build_cve_node(vuln: VulnerabilityDetail) -> AttackPathNode:
        title = vuln.title or vuln.vuln_id
        cvss = getattr(vuln, "cvss", None)
        score = getattr(cvss, "base_score", None) if cvss else None
        return AttackPathNode(
            id="cve",
            type="cve",
            label=vuln.vuln_id,
            description=title[:300] if title else None,
            severity=vuln.severity or None,
            metadata={
                "cvssScore": score,
                "epssScore": vuln.epss_score,
                "exploited": bool(vuln.exploited or vuln.exploitation),
            },
        )

    @staticmethod
    def _exploit_label(
        vuln: VulnerabilityDetail,
        capec_map: dict[str, CAPECDescription],
        language: str,
    ) -> str:
        de = (language or "").lower().startswith("de")
        if capec_map:
            first = next(iter(capec_map.values()))
            return first.name
        # Fallback heuristic: derive from severity / CVSS impact metrics.
        severity = (vuln.severity or "").lower()
        if severity == "critical":
            return "Code execution / system takeover" if not de else "Codeausführung / Systemübernahme"
        if severity == "high":
            return "Privilege escalation or data access" if not de else "Privilegienerweiterung oder Datenzugriff"
        if severity == "medium":
            return "Information disclosure or denial of service" if not de else "Informationsoffenlegung oder Dienstausfall"
        return "Exploit primitive" if not de else "Exploit-Primitive"

    @staticmethod
    def _exploit_description(
        vuln: VulnerabilityDetail, capec_map: dict[str, CAPECDescription]
    ) -> str | None:
        if capec_map:
            first = next(iter(capec_map.values()))
            return (first.description or "")[:300] or None
        return None

    @staticmethod
    def _impact_label(
        vuln: VulnerabilityDetail,
        cwe_data: dict[str, CWEDescription],
        language: str,
    ) -> str:
        de = (language or "").lower().startswith("de")
        # Use first CWE consequence string if available.
        for desc in cwe_data.values():
            if desc.consequences:
                return desc.consequences[0][:140]
        severity = (vuln.severity or "").lower()
        if severity == "critical":
            return "Server compromise" if not de else "Server-Kompromittierung"
        if severity == "high":
            return "Sensitive data access" if not de else "Zugriff auf sensible Daten"
        if severity == "medium":
            return "Limited information disclosure" if not de else "Eingeschränkte Informationsoffenlegung"
        return "Confidentiality / integrity / availability impact" if not de else "Auswirkung auf Vertraulichkeit / Integrität / Verfügbarkeit"

    @staticmethod
    def _impact_description(
        vuln: VulnerabilityDetail, cwe_data: dict[str, CWEDescription]
    ) -> str | None:
        joined = "; ".join(
            consequence[:120]
            for desc in cwe_data.values()
            for consequence in desc.consequences[:2]
        )
        return joined or None

    @staticmethod
    def _fix_label(vuln: VulnerabilityDetail, language: str) -> str:
        de = (language or "").lower().startswith("de")
        # Try to extract a fixed/patched version from impacted_products versions.
        for impacted in vuln.impacted_products or []:
            if impacted.versions and len(impacted.versions) > 0:
                # Heuristic — first listed version is often the fix in EUVD/NVD payloads.
                return (
                    f"Upgrade to {impacted.versions[0]} (verify against advisory)"
                    if not de
                    else f"Aktualisieren auf {impacted.versions[0]} (gegen Advisory verifizieren)"
                )
        return "Apply vendor patch" if not de else "Hersteller-Patch einspielen"

    @staticmethod
    def _fix_description(vuln: VulnerabilityDetail) -> str | None:
        # Pick the first official advisory link if any.
        for ref in vuln.references or []:
            ref_lower = ref.lower()
            if any(
                pattern in ref_lower
                for pattern in (
                    "/security/advisories/ghsa-",
                    "github.com/advisories/ghsa-",
                    "/security-advisories/",
                    "msrc.microsoft.com",
                    "access.redhat.com/security",
                )
            ):
                return ref
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_cwes(cwes: list[str] | None) -> list[str]:
        if not cwes:
            return []
        seen: set[str] = set()
        out: list[str] = []
        for cwe in cwes:
            normalized = str(cwe).upper().replace("CWE-", "").strip()
            if not normalized or not normalized.isdigit():
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        return out

    @staticmethod
    def _inventory_payload(vuln: VulnerabilityDetail) -> list[dict[str, Any]]:
        payload = getattr(vuln, "affected_inventory", None) or []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]


def _isoformat_utc_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


@lru_cache(maxsize=1)
def get_attack_path_service() -> AttackPathService:
    return AttackPathService()
