from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository

log = structlog.get_logger()


class VexService:
    def __init__(
        self,
        finding_repo: ScanFindingRepository,
        scan_repo: ScanRepository,
    ) -> None:
        self.finding_repo = finding_repo
        self.scan_repo = scan_repo

    async def export_cyclonedx_vex(self, scan_id: str) -> dict[str, Any]:
        """Build a CycloneDX 1.5 VEX document from findings with VEX annotations."""
        scan = await self.scan_repo.get(scan_id)
        if not scan:
            return {}

        vex_findings = await self.finding_repo.get_vex_findings_by_scan(scan_id)
        if not vex_findings:
            return {}

        # Map VEX status to CycloneDX analysis.state
        status_map = {
            "not_affected": "not_affected",
            "affected": "affected",
            "fixed": "resolved",
            "under_investigation": "in_triage",
        }

        vulnerabilities: list[dict[str, Any]] = []
        for finding in vex_findings:
            vuln_id = finding.get("vulnerability_id", "")
            vex_status = finding.get("vex_status", "")

            entry: dict[str, Any] = {
                "id": vuln_id,
                "analysis": {
                    "state": status_map.get(vex_status, vex_status),
                },
                "affects": [{
                    "ref": finding.get("package_name", ""),
                    "versions": [{
                        "version": finding.get("package_version", ""),
                        "status": status_map.get(vex_status, vex_status),
                    }] if finding.get("package_version") else [],
                }],
            }

            if finding.get("vex_justification"):
                entry["analysis"]["justification"] = finding["vex_justification"]
            if finding.get("vex_detail"):
                entry["analysis"]["detail"] = finding["vex_detail"]
            if finding.get("vex_response"):
                entry["analysis"]["response"] = finding["vex_response"]

            vulnerabilities.append(entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "tools": [{"vendor": "Hecate", "name": "Hecate VEX Export"}],
                "component": {
                    "name": scan.get("target_name", scan.get("target_id", "")),
                    "type": "application",
                },
            },
            "vulnerabilities": vulnerabilities,
        }

    async def import_cyclonedx_vex(
        self,
        vex_data: dict[str, Any],
        target_id: str,
    ) -> dict[str, int]:
        """Import CycloneDX VEX document and apply to matching findings."""
        # Reverse map from CycloneDX state to our VEX status
        state_map = {
            "not_affected": "not_affected",
            "affected": "affected",
            "resolved": "fixed",
            "resolved_with_pedigree": "fixed",
            "in_triage": "under_investigation",
            "exploitable": "affected",
            "false_positive": "not_affected",
        }

        vulnerabilities = vex_data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return {"applied": 0, "skipped": 0, "not_found": 0}

        applied = 0
        skipped = 0
        not_found = 0

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            vuln_id = vuln.get("id", "")
            analysis = vuln.get("analysis", {})
            if not isinstance(analysis, dict):
                continue

            state = analysis.get("state", "")
            vex_status = state_map.get(state)
            if not vex_status:
                skipped += 1
                continue

            justification = analysis.get("justification")
            detail = analysis.get("detail")

            count = await self.finding_repo.bulk_update_vex_by_vulnerability(
                target_id=target_id,
                vulnerability_id=vuln_id,
                vex_status=vex_status,
                vex_justification=justification or detail,
                vex_updated_by="vex-import",
            )
            if count > 0:
                applied += count
            else:
                not_found += 1

        return {"applied": applied, "skipped": skipped, "not_found": not_found}

    async def carry_forward_vex(self, old_scan_id: str, new_scan_id: str) -> int:
        """Copy VEX annotations from previous scan to new scan."""
        return await self.finding_repo.carry_forward_vex(old_scan_id, new_scan_id)
