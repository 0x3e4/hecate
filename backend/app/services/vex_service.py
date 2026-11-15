from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository
from app.services.vex_export import cyclonedx_justification

log = structlog.get_logger()


_VEX_TEXT_LIMIT = 2000


# CycloneDX analysis.state -> Hecate's VEX status. "affected" is not a
# CycloneDX state but older Hecate exports wrote it, so it is still read.
CYCLONEDX_STATE_TO_VEX = {
    "not_affected": "not_affected",
    "affected": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "in_triage": "under_investigation",
    "exploitable": "affected",
    "false_positive": "not_affected",
}


def _vex_text(value: Any) -> str | None:
    return value[:_VEX_TEXT_LIMIT] if isinstance(value, str) and value else None


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

        # Map VEX status to CycloneDX analysis.state. CycloneDX has no
        # "affected"; its counterpart (as in CISA's OpenVEX mapping) is
        # "exploitable", which the import maps back to "affected".
        status_map = {
            "not_affected": "not_affected",
            "affected": "exploitable",
            "fixed": "resolved",
            "under_investigation": "in_triage",
        }
        # affects[].versions[].status has an enum of its own.
        version_status_map = {
            "not_affected": "unaffected",
            "affected": "affected",
            "fixed": "unaffected",
            "under_investigation": "unknown",
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
                        "status": version_status_map.get(vex_status, "unknown"),
                    }] if finding.get("package_version") else [],
                }],
            }

            # CycloneDX only accepts its own justification enum: map labels,
            # and carry free text in detail rather than as an invalid value.
            justification = finding.get("vex_justification")
            cdx_justification = cyclonedx_justification(justification)
            if cdx_justification:
                entry["analysis"]["justification"] = cdx_justification
            detail = finding.get("vex_detail")
            if not cdx_justification and isinstance(justification, str) and justification.strip():
                detail = f"{justification.strip()}\n\n{detail}" if detail else justification.strip()
            if detail:
                entry["analysis"]["detail"] = detail
            if finding.get("vex_response"):
                entry["analysis"]["response"] = finding["vex_response"]
            updated_at = finding.get("vex_updated_at")
            if isinstance(updated_at, datetime):
                entry["analysis"]["lastUpdated"] = updated_at.isoformat()
            # Review evidence: who set the status, at which version, re-review date.
            properties = [
                {"name": name, "value": str(finding[key])}
                for name, key in (
                    ("hecate:vex:updated-by", "vex_updated_by"),
                    ("hecate:vex:assessed-version", "vex_assessed_version"),
                    ("hecate:vex:review-due", "vex_review_due"),
                )
                if finding.get(key)
            ]
            if properties:
                entry["properties"] = properties

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

    async def import_vex_document(
        self,
        vex_data: dict[str, Any],
        target_id: str,
    ) -> dict[str, Any]:
        """Import a CycloneDX VEX or OpenVEX document; the format is detected.

        Raises ``ValueError`` for a document that is neither.
        """
        from app.services.vex_source_service import is_openvex

        if is_openvex(vex_data):
            result: dict[str, Any] = await self.import_openvex(vex_data, target_id)
            result["format"] = "openvex"
            return result
        if isinstance(vex_data.get("vulnerabilities"), list):
            result = await self.import_cyclonedx_vex(vex_data, target_id)
            result["format"] = "cyclonedx"
            return result
        raise ValueError("The document is neither CycloneDX VEX nor OpenVEX.")

    async def import_openvex(
        self,
        vex_data: dict[str, Any],
        target_id: str,
    ) -> dict[str, int]:
        """Import an OpenVEX document and apply it to the target's findings.

        Statements are read like a VEX source's (aliases, package scoping when
        one vulnerability has different statuses per package), but an import
        overwrites the status a finding has, like the CycloneDX import.
        """
        from app.services.vex_source_service import _parse_openvex, scope_statements

        raw = vex_data.get("statements") or []
        statements = _parse_openvex(vex_data)
        scoped, skipped = scope_statements(statements)
        skipped += len(raw) - len(statements)  # unknown status or no vulnerability id
        applied = not_found = 0
        seen: set[tuple[tuple[str, ...], str, tuple[str, ...]]] = set()
        for st, packages in scoped:
            # One statement per (vulnerability, package) is common; once it
            # covers the whole vulnerability, a repeat would only count twice.
            key = (tuple(st.ids), st.status, tuple(packages or ()))
            if key in seen:
                continue
            seen.add(key)
            count = await self.finding_repo.bulk_update_vex_by_vulnerability_ids(
                target_id,
                st.ids,
                st.status,
                package_names=packages,
                vex_justification=st.justification or st.detail,
                vex_detail=st.detail,
                vex_updated_by="vex-import",
            )
            if count > 0:
                applied += count
            else:
                not_found += 1
        return {"applied": applied, "skipped": skipped, "not_found": not_found}

    async def import_cyclonedx_vex(
        self,
        vex_data: dict[str, Any],
        target_id: str,
    ) -> dict[str, int]:
        """Import CycloneDX VEX document and apply to matching findings."""
        state_map = CYCLONEDX_STATE_TO_VEX

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
            if not isinstance(vuln_id, str):
                continue
            analysis = vuln.get("analysis", {})
            if not isinstance(analysis, dict):
                continue

            # Imported JSON is caller-shaped: a list as `state` made the lookup raise,
            # and a non-string justification was stored and broke every later read
            # of that target's findings.
            state = analysis.get("state")
            vex_status = state_map.get(state) if isinstance(state, str) else None
            if not vex_status:
                skipped += 1
                continue

            justification = _vex_text(analysis.get("justification"))
            detail = _vex_text(analysis.get("detail"))

            # The justification is the short reason the findings table shows;
            # without one the detail stands in for it. The detail itself goes
            # to vex_detail, where the VEX editor shows it in full.
            count = await self.finding_repo.bulk_update_vex_by_vulnerability(
                target_id=target_id,
                vulnerability_id=vuln_id,
                vex_status=vex_status,
                vex_justification=justification or detail,
                vex_updated_by="vex-import",
                vex_detail=detail,
            )
            if count > 0:
                applied += count
            else:
                not_found += 1

        return {"applied": applied, "skipped": skipped, "not_found": not_found}

    async def carry_forward_vex(self, old_scan_id: str, new_scan_id: str) -> int:
        """Copy VEX annotations from previous scan to new scan."""
        return await self.finding_repo.carry_forward_vex(old_scan_id, new_scan_id)
