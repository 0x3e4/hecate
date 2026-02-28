"""Stateless parsers that normalize scanner output into internal models."""

from __future__ import annotations

import re
from typing import Any

import structlog

from app.models.scan import ScanFindingDocument, ScanSbomComponentDocument, ScanSummary

log = structlog.get_logger()

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "negligible",
    "info": "negligible",
    "informational": "negligible",
    "none": "negligible",
    "unknown": "unknown",
    "": "unknown",
}

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _normalize_severity(raw: str | None) -> str:
    if not raw:
        return "unknown"
    return _SEVERITY_MAP.get(raw.lower().strip(), "unknown")


def _build_summary(findings: list[ScanFindingDocument]) -> ScanSummary:
    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0,
    }
    for f in findings:
        key = f.severity if f.severity in counts else "unknown"
        counts[key] += 1
    return ScanSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        negligible=counts["negligible"],
        unknown=counts["unknown"],
        total=len(findings),
    )


def _extract_cve_id(text: str | None) -> str | None:
    """Extract a CVE ID from a string."""
    if not text:
        return None
    match = _CVE_PATTERN.search(text)
    return match.group(0).upper() if match else None


def parse_trivy_json(
    data: dict[str, Any],
    scan_id: str,
    target_id: str,
) -> tuple[list[ScanFindingDocument], list[ScanSbomComponentDocument], ScanSummary]:
    """Parse Trivy JSON output into findings and SBOM components."""
    findings: list[ScanFindingDocument] = []
    components: list[ScanSbomComponentDocument] = []
    seen_vulns: set[str] = set()

    results = data.get("Results", [])
    if not isinstance(results, list):
        return findings, components, ScanSummary()

    for result in results:
        if not isinstance(result, dict):
            continue
        target_name = result.get("Target", "")
        result_type = result.get("Type", "")

        # Parse vulnerabilities
        for vuln in result.get("Vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "")
            dedup_key = f"{vuln_id}:{pkg_name}:{vuln.get('InstalledVersion', '')}"
            if dedup_key in seen_vulns:
                continue
            seen_vulns.add(dedup_key)

            severity = _normalize_severity(vuln.get("Severity"))
            cve_id = _extract_cve_id(vuln_id)

            findings.append(ScanFindingDocument(
                scan_id=scan_id,
                target_id=target_id,
                vulnerability_id=cve_id,
                scanner="trivy",
                package_name=pkg_name,
                package_version=vuln.get("InstalledVersion", ""),
                package_type=result_type,
                package_path=target_name or None,
                severity=severity,
                title=vuln.get("Title"),
                description=vuln.get("Description"),
                fix_version=vuln.get("FixedVersion"),
                fix_state="fixed" if vuln.get("FixedVersion") else "not_fixed",
                data_source=vuln.get("DataSource", {}).get("Name") if isinstance(vuln.get("DataSource"), dict) else None,
                urls=vuln.get("References", []) or [],
                cvss_score=_extract_trivy_cvss_score(vuln),
                cvss_vector=_extract_trivy_cvss_vector(vuln),
            ))

        # Parse packages as SBOM components
        for pkg in result.get("Packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            components.append(ScanSbomComponentDocument(
                scan_id=scan_id,
                target_id=target_id,
                name=pkg.get("Name", ""),
                version=pkg.get("Version", ""),
                type=result_type,
                purl=pkg.get("PURL"),
                licenses=[lic for lic in (pkg.get("Licenses") or []) if isinstance(lic, str)],
                file_path=target_name or None,
            ))

    # Filter out "file" type entries and merge duplicates
    components = _filter_and_merge_sbom(components)

    return findings, components, _build_summary(findings)


def _extract_trivy_cvss_score(vuln: dict[str, Any]) -> float | None:
    """Extract best CVSS score from Trivy vulnerability data."""
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict):
        return None
    # Prefer NVD, then any source
    for source in ["nvd", "ghsa", "redhat"]:
        for key, entry in cvss.items():
            if isinstance(entry, dict) and source in key.lower():
                score = entry.get("V3Score") or entry.get("V2Score")
                if isinstance(score, (int, float)):
                    return float(score)
    # Fallback to any
    for entry in cvss.values():
        if isinstance(entry, dict):
            score = entry.get("V3Score") or entry.get("V2Score")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _extract_trivy_cvss_vector(vuln: dict[str, Any]) -> str | None:
    """Extract best CVSS vector from Trivy vulnerability data."""
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict):
        return None
    for entry in cvss.values():
        if isinstance(entry, dict):
            vec = entry.get("V3Vector") or entry.get("V2Vector")
            if isinstance(vec, str):
                return vec
    return None


def parse_grype_json(
    data: dict[str, Any],
    scan_id: str,
    target_id: str,
) -> tuple[list[ScanFindingDocument], ScanSummary]:
    """Parse Grype JSON output into findings."""
    findings: list[ScanFindingDocument] = []
    seen: set[str] = set()

    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return findings, ScanSummary()

    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln_data = match.get("vulnerability", {})
        if not isinstance(vuln_data, dict):
            continue

        vuln_id = vuln_data.get("id", "")
        artifact = match.get("artifact", {})
        if not isinstance(artifact, dict):
            artifact = {}

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        dedup_key = f"{vuln_id}:{pkg_name}:{pkg_version}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        severity = _normalize_severity(vuln_data.get("severity"))
        cve_id = _extract_cve_id(vuln_id)

        # Extract fix versions
        fix_versions = vuln_data.get("fix", {})
        fix_state_raw = "unknown"
        fix_version = None
        if isinstance(fix_versions, dict):
            fix_state_raw = fix_versions.get("state", "unknown")
            versions = fix_versions.get("versions", [])
            if isinstance(versions, list) and versions:
                fix_version = versions[0] if isinstance(versions[0], str) else None

        fix_state_map = {"fixed": "fixed", "not-fixed": "not_fixed", "wont-fix": "wont_fix"}
        fix_state = fix_state_map.get(fix_state_raw, "unknown")

        urls = vuln_data.get("urls", []) or []
        cvss_entries = vuln_data.get("cvss", [])
        cvss_score = None
        cvss_vector = None
        if isinstance(cvss_entries, list):
            for entry in cvss_entries:
                if isinstance(entry, dict):
                    score = entry.get("metrics", {}).get("baseScore") if isinstance(entry.get("metrics"), dict) else None
                    if isinstance(score, (int, float)):
                        cvss_score = float(score)
                    vec = entry.get("vector")
                    if isinstance(vec, str):
                        cvss_vector = vec
                    if cvss_score:
                        break

        findings.append(ScanFindingDocument(
            scan_id=scan_id,
            target_id=target_id,
            vulnerability_id=cve_id,
            scanner="grype",
            package_name=pkg_name,
            package_version=pkg_version,
            package_type=artifact.get("type", ""),
            package_path=artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else None,
            severity=severity,
            title=None,
            description=vuln_data.get("description"),
            fix_version=fix_version,
            fix_state=fix_state,
            data_source=vuln_data.get("dataSource"),
            urls=urls if isinstance(urls, list) else [],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        ))

    return findings, _build_summary(findings)


def parse_cyclonedx_sbom(
    data: dict[str, Any],
    scan_id: str,
    target_id: str,
) -> tuple[list[ScanSbomComponentDocument], int]:
    """Parse CycloneDX SBOM (from Syft) into SBOM components."""
    components: list[ScanSbomComponentDocument] = []

    raw_components = data.get("components", [])
    if not isinstance(raw_components, list):
        return components, 0

    for comp in raw_components:
        if not isinstance(comp, dict):
            continue

        name = comp.get("name", "")
        version = comp.get("version", "")
        comp_type = comp.get("type", "")
        purl = comp.get("purl")

        # Extract licenses
        licenses: list[str] = []
        for lic in comp.get("licenses", []) or []:
            if isinstance(lic, dict):
                license_obj = lic.get("license", {})
                if isinstance(license_obj, dict):
                    lic_id = license_obj.get("id") or license_obj.get("name")
                    if isinstance(lic_id, str):
                        licenses.append(lic_id)
                expression = lic.get("expression")
                if isinstance(expression, str):
                    licenses.append(expression)

        # Extract CPE
        cpe = None
        for prop in comp.get("properties", []) or []:
            if isinstance(prop, dict) and "cpe" in str(prop.get("name", "")).lower():
                cpe = prop.get("value")
                break

        supplier = None
        supplier_data = comp.get("supplier")
        if isinstance(supplier_data, dict):
            supplier = supplier_data.get("name")

        components.append(ScanSbomComponentDocument(
            scan_id=scan_id,
            target_id=target_id,
            name=name,
            version=version,
            type=comp_type,
            purl=purl,
            cpe=cpe,
            licenses=licenses,
            supplier=supplier,
        ))

    # Filter out "file" type entries and deduplicate
    components = _filter_and_merge_sbom(components)

    return components, len(components)


def _filter_and_merge_sbom(
    components: list[ScanSbomComponentDocument],
) -> list[ScanSbomComponentDocument]:
    """Filter out 'file' type SBOM entries and merge duplicates (same name+version)."""
    merged: dict[str, ScanSbomComponentDocument] = {}
    for comp in components:
        if comp.type.lower() == "file":
            continue
        key = f"{comp.name}:{comp.version}"
        if key in merged:
            existing = merged[key]
            # Merge: prefer non-empty fields
            if not existing.purl and comp.purl:
                existing.purl = comp.purl
            if not existing.cpe and comp.cpe:
                existing.cpe = comp.cpe
            if not existing.supplier and comp.supplier:
                existing.supplier = comp.supplier
            for lic in comp.licenses:
                if lic not in existing.licenses:
                    existing.licenses.append(lic)
            # Prefer more specific type over generic
            if comp.type and (not existing.type or existing.type == "library"):
                existing.type = comp.type
        else:
            merged[key] = comp
    return list(merged.values())


def parse_osv_json(
    data: dict[str, Any],
    scan_id: str,
    target_id: str,
) -> tuple[list[ScanFindingDocument], ScanSummary]:
    """Parse OSV Scanner JSON output into findings."""
    findings: list[ScanFindingDocument] = []
    seen: set[str] = set()

    results = data.get("results", [])
    if not isinstance(results, list):
        return findings, ScanSummary()

    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source", {})
        source_path = source.get("path", "") if isinstance(source, dict) else ""

        for pkg_info in result.get("packages", []) or []:
            if not isinstance(pkg_info, dict):
                continue
            pkg = pkg_info.get("package", {})
            if not isinstance(pkg, dict):
                continue

            pkg_name = pkg.get("name", "")
            pkg_version = pkg.get("version", "")
            pkg_ecosystem = pkg.get("ecosystem", "")

            for vuln_data in pkg_info.get("vulnerabilities", []) or []:
                if not isinstance(vuln_data, dict):
                    continue
                osv_id = vuln_data.get("id", "")
                dedup_key = f"{osv_id}:{pkg_name}:{pkg_version}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Try to extract CVE from aliases
                cve_id = _extract_cve_id(osv_id)
                if not cve_id:
                    for alias in vuln_data.get("aliases", []) or []:
                        cve_id = _extract_cve_id(alias)
                        if cve_id:
                            break

                # Extract severity from database_specific or severity array
                severity = "unknown"
                severity_entries = vuln_data.get("severity", [])
                if isinstance(severity_entries, list):
                    for sev in severity_entries:
                        if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
                            score_str = sev.get("score", "")
                            severity = _cvss_score_to_severity(_parse_cvss_base_score(score_str))
                            break

                db_specific = vuln_data.get("database_specific", {})
                if isinstance(db_specific, dict) and severity == "unknown":
                    raw_sev = db_specific.get("severity")
                    if isinstance(raw_sev, str):
                        severity = _normalize_severity(raw_sev)

                # Extract fix version from affected ranges
                fix_version = None
                for affected in vuln_data.get("affected", []) or []:
                    if not isinstance(affected, dict):
                        continue
                    for rng in affected.get("ranges", []) or []:
                        if not isinstance(rng, dict):
                            continue
                        for event in rng.get("events", []) or []:
                            if isinstance(event, dict) and "fixed" in event:
                                fix_version = event["fixed"]
                                break

                findings.append(ScanFindingDocument(
                    scan_id=scan_id,
                    target_id=target_id,
                    vulnerability_id=cve_id,
                    scanner="osv-scanner",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    package_type=pkg_ecosystem,
                    package_path=source_path or None,
                    severity=severity,
                    title=vuln_data.get("summary"),
                    description=vuln_data.get("details"),
                    fix_version=fix_version,
                    fix_state="fixed" if fix_version else "not_fixed",
                    urls=[ref.get("url") for ref in (vuln_data.get("references", []) or []) if isinstance(ref, dict) and isinstance(ref.get("url"), str)],
                ))

    return findings, _build_summary(findings)


def _parse_cvss_base_score(vector: str) -> float | None:
    """Try to extract base score from a CVSS vector string."""
    if not isinstance(vector, str):
        return None
    # Some OSV entries put just the score
    try:
        return float(vector)
    except ValueError:
        pass
    return None


def _cvss_score_to_severity(score: float | None) -> str:
    """Convert CVSS score to severity string."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "negligible"
