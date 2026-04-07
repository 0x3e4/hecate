from __future__ import annotations

import re
from typing import Any

import structlog

from app.repositories.license_policy_repository import LicensePolicyRepository
from app.repositories.scan_sbom_repository import ScanSbomRepository

log = structlog.get_logger()

# Well-known SPDX license groups for quick policy creation
PERMISSIVE_LICENSES: set[str] = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD",
    "Unlicense", "CC0-1.0", "Zlib", "BSL-1.0", "PostgreSQL", "X11",
    "MIT-0", "BlueOak-1.0.0",
}

WEAK_COPYLEFT_LICENSES: set[str] = {
    "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1", "CPL-1.0",
}

COPYLEFT_LICENSES: set[str] = {
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "OSL-3.0",
    "EUPL-1.1", "EUPL-1.2",
}

# Regex to split SPDX expressions into individual identifiers
_SPDX_SPLIT_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+", re.IGNORECASE)


def split_spdx_expression(expression: str) -> list[str]:
    """Split an SPDX license expression into individual license IDs."""
    parts = _SPDX_SPLIT_RE.split(expression.strip())
    result: list[str] = []
    for part in parts:
        cleaned = part.strip().strip("()")
        if cleaned:
            result.append(cleaned)
    return result


def evaluate_license(license_id: str, policy: dict[str, Any]) -> str:
    """Evaluate a single SPDX license ID against a policy.

    Returns: "allowed", "denied", "warned", or "unknown".
    """
    allowed: list[str] = policy.get("allowed", [])
    denied: list[str] = policy.get("denied", [])
    reviewed: list[str] = policy.get("reviewed", [])
    default_action: str = policy.get("default_action", "warn")

    if license_id in denied:
        return "denied"
    if license_id in allowed or license_id in reviewed:
        return "allowed"

    # Unlisted license — use default action
    if default_action == "allow":
        return "allowed"
    if default_action == "deny":
        return "denied"
    return "warned"


def evaluate_component_licenses(licenses: list[str], policy: dict[str, Any]) -> str:
    """Evaluate all licenses for a component. Returns the worst status.

    Priority: denied > warned > unknown > allowed.
    """
    if not licenses:
        return "unknown"

    statuses: set[str] = set()
    for lic in licenses:
        ids = split_spdx_expression(lic)
        for lid in ids:
            statuses.add(evaluate_license(lid, policy))

    if "denied" in statuses:
        return "denied"
    if "warned" in statuses:
        return "warned"
    if "unknown" in statuses:
        return "unknown"
    return "allowed"


class LicenseComplianceService:
    def __init__(
        self,
        policy_repo: LicensePolicyRepository,
        sbom_repo: ScanSbomRepository,
    ) -> None:
        self.policy_repo = policy_repo
        self.sbom_repo = sbom_repo

    async def get_policy(self, policy_id: str | None = None) -> dict[str, Any] | None:
        """Fetch the requested policy or fall back to the default."""
        if policy_id:
            return await self.policy_repo.get(policy_id)
        return await self.policy_repo.get_default()

    async def evaluate_scan(
        self,
        scan_id: str,
        policy_id: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate all SBOM components in a scan against a license policy.

        Returns {policyId, policyName, summary: {allowed, denied, warned, unknown},
                 violations: [{name, version, type, purl, licenses, status, evaluatedLicenses}]}.
        """
        policy = await self.get_policy(policy_id)
        if not policy:
            return {
                "policyId": None,
                "policyName": None,
                "summary": {"allowed": 0, "denied": 0, "warned": 0, "unknown": 0},
                "violations": [],
            }

        components = await self.sbom_repo.list_all_by_scan(scan_id)

        summary = {"allowed": 0, "denied": 0, "warned": 0, "unknown": 0}
        violations: list[dict[str, Any]] = []

        for comp in components:
            licenses: list[str] = comp.get("licenses", [])
            status = evaluate_component_licenses(licenses, policy)
            summary[status] = summary.get(status, 0) + 1

            if status in ("denied", "warned", "unknown"):
                evaluated: list[dict[str, str]] = []
                for lic in licenses:
                    for lid in split_spdx_expression(lic):
                        evaluated.append({
                            "licenseId": lid,
                            "status": evaluate_license(lid, policy),
                        })

                violations.append({
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "type": comp.get("type", ""),
                    "purl": comp.get("purl"),
                    "licenses": licenses,
                    "status": status,
                    "evaluatedLicenses": evaluated,
                })

        return {
            "policyId": str(policy["_id"]),
            "policyName": policy.get("name", ""),
            "summary": summary,
            "violations": violations,
        }

    async def compute_summary(
        self,
        scan_id: str,
        policy_id: str | None = None,
    ) -> dict[str, int] | None:
        """Compute a lightweight compliance summary for storage on ScanDocument."""
        policy = await self.get_policy(policy_id)
        if not policy:
            return None

        components = await self.sbom_repo.list_all_by_scan(scan_id)
        summary = {"allowed": 0, "denied": 0, "warned": 0, "unknown": 0}
        for comp in components:
            status = evaluate_component_licenses(comp.get("licenses", []), policy)
            summary[status] = summary.get(status, 0) + 1
        return summary

    async def get_license_overview(
        self,
        scan_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Aggregate license usage across multiple scans.

        Returns a list of {licenseId, componentCount, components: [{name, version}]}.
        """
        if not scan_ids:
            return []

        license_map: dict[str, list[dict[str, str]]] = {}
        for scan_id in scan_ids:
            components = await self.sbom_repo.list_all_by_scan(scan_id)
            for comp in components:
                for lic in comp.get("licenses", []):
                    for lid in split_spdx_expression(lic):
                        if lid not in license_map:
                            license_map[lid] = []
                        entry = {"name": comp.get("name", ""), "version": comp.get("version", "")}
                        if entry not in license_map[lid]:
                            license_map[lid].append(entry)

        result = [
            {
                "licenseId": lid,
                "componentCount": len(comps),
                "components": comps[:20],
            }
            for lid, comps in sorted(license_map.items())
        ]
        return result
