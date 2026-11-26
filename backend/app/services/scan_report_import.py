"""Scanner reports as imports: Trivy, Grype and OSV-Scanner JSON from outside Hecate.

The SBOM import (``ScanService.import_sbom``) also takes the JSON report of a
scanner someone already runs: in CI, on a host (``trivy rootfs /``), or from a
platform that keeps the files. The report is that scanner's answer, so its
findings are taken as they are and go through the same passes as a scan's
(CVE fallback, fix versions, severity from Hecate's database, scopes, VEX); no
sidecar scanner and no name match run on top.

The findings come from the parsers that read Hecate's own scanner runs
(``scan_parser``), so an imported Trivy finding looks like one from a Trivy
scan. The SBOM is what the report lists: Trivy's ``Packages`` (all packages
with ``--list-all-pkgs``), Grype's and OSV-Scanner's matched packages (those
two list only vulnerable packages unless asked for more).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.models.scan import ScanFindingDocument, ScanSbomComponentDocument
from app.services.package_check_service import package_purl
from app.services.supply_chain_service import canonical_ecosystem

REPORT_FORMATS = ("trivy-json", "grype-json", "osv-scanner-json")
REPORT_SCANNERS = {"trivy-json": "trivy", "grype-json": "grype", "osv-scanner-json": "osv-scanner"}

# OSV ecosystems of OS packages -> (purl type, namespace). Language ecosystems
# go through package_purl.
_OSV_OS_PURLS = {
    "debian": ("deb", "debian"),
    "ubuntu": ("deb", "ubuntu"),
    "alpine": ("apk", "alpine"),
    "wolfi": ("apk", "wolfi"),
    "chainguard": ("apk", "chainguard"),
    "rocky linux": ("rpm", "rocky"),
    "almalinux": ("rpm", "almalinux"),
    "red hat": ("rpm", "redhat"),
    "suse": ("rpm", "suse"),
    "opensuse": ("rpm", "opensuse"),
}


def detect_report_format(data: dict[str, Any]) -> str | None:
    """``trivy-json``, ``grype-json`` or ``osv-scanner-json``; ``None`` for anything else."""
    if not isinstance(data, dict):
        return None
    if "SchemaVersion" in data and isinstance(data.get("Results", []), list) and (
        "Results" in data or "ArtifactName" in data
    ):
        return "trivy-json"
    descriptor = data.get("descriptor")
    if isinstance(data.get("matches"), list) and (
        (isinstance(descriptor, dict) and descriptor.get("name") == "grype") or "source" in data
    ):
        return "grype-json"
    results = data.get("results")
    if isinstance(results, list) and all(
        isinstance(r, dict) and ("packages" in r or "source" in r) for r in results
    ) and "bomFormat" not in data:
        return "osv-scanner-json"
    return None


def report_target_name(data: dict[str, Any], fmt: str) -> str | None:
    """The scanned thing as the report names it; ``None`` when it names nothing usable."""
    name: Any = None
    if fmt == "trivy-json":
        name = data.get("ArtifactName")
    elif fmt == "grype-json":
        source = data.get("source")
        target = source.get("target") if isinstance(source, dict) else None
        if isinstance(target, dict):
            name = target.get("userInput") or target.get("name") or target.get("path")
        elif isinstance(target, str):
            name = target
    return name.strip()[:200] if isinstance(name, str) and name.strip() else None


def report_package_count(data: dict[str, Any], fmt: str) -> int:
    """Packages and matches in the report, for the import's size limit."""
    if fmt == "trivy-json":
        return sum(
            len(r.get("Packages") or []) + len(r.get("Vulnerabilities") or [])
            for r in data.get("Results") or [] if isinstance(r, dict)
        )
    if fmt == "grype-json":
        return len(data.get("matches") or [])
    return sum(
        len(r.get("packages") or []) for r in data.get("results") or [] if isinstance(r, dict)
    )


def _osv_purl(ecosystem: str, name: str, version: str) -> str | None:
    base = ecosystem.split(":", 1)[0].strip().lower()
    if base in _OSV_OS_PURLS:
        purl_type, namespace = _OSV_OS_PURLS[base]
        return f"pkg:{purl_type}/{namespace}/{quote(name, safe='')}" + (f"@{quote(version, safe='')}" if version else "")
    eco = canonical_ecosystem(ecosystem.split(":", 1)[0])
    if not eco:
        return None
    try:
        return package_purl(eco, name, version or None)
    except KeyError:
        return None


def _grype_components(data: dict[str, Any], scan_id: str, target_id: str) -> list[ScanSbomComponentDocument]:
    components: dict[tuple[str, str], ScanSbomComponentDocument] = {}
    for match in data.get("matches") or []:
        artifact = match.get("artifact") if isinstance(match, dict) else None
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
            continue
        key = (artifact["name"], str(artifact.get("version") or ""))
        if key in components:
            continue
        licenses = [lic for lic in artifact.get("licenses") or [] if isinstance(lic, str)]
        cpes = [c for c in artifact.get("cpes") or [] if isinstance(c, str)]
        locations = artifact.get("locations") or []
        path = locations[0].get("path") if locations and isinstance(locations[0], dict) else None
        purl = artifact.get("purl")
        components[key] = ScanSbomComponentDocument(
            scan_id=scan_id,
            target_id=target_id,
            name=key[0],
            version=key[1],
            type=str(artifact.get("type") or "library"),
            purl=purl if isinstance(purl, str) and purl.startswith("pkg:") else None,
            cpe=cpes[0] if cpes else None,
            licenses=licenses,
            file_path=path if isinstance(path, str) else None,
        )
    return list(components.values())


def _osv_components(data: dict[str, Any], scan_id: str, target_id: str) -> list[ScanSbomComponentDocument]:
    components: dict[tuple[str, str], ScanSbomComponentDocument] = {}
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        source = result.get("source")
        path = source.get("path") if isinstance(source, dict) else None
        for entry in result.get("packages") or []:
            pkg = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                continue
            key = (pkg["name"], str(pkg.get("version") or ""))
            if key in components:
                continue
            ecosystem = str(pkg.get("ecosystem") or "")
            components[key] = ScanSbomComponentDocument(
                scan_id=scan_id,
                target_id=target_id,
                name=key[0],
                version=key[1],
                type=ecosystem.split(":", 1)[0] or "library",
                purl=_osv_purl(ecosystem, key[0], key[1]) if ecosystem else None,
                file_path=path if isinstance(path, str) else None,
            )
    return list(components.values())


def parse_report(
    data: dict[str, Any], fmt: str, scan_id: str, target_id: str,
) -> tuple[list[ScanFindingDocument], list[ScanSbomComponentDocument]]:
    """Findings and SBOM components of a scanner report."""
    from app.services.scan_parser import parse_grype_json, parse_osv_json, parse_trivy_json

    if fmt == "trivy-json":
        findings, components, _ = parse_trivy_json(data, scan_id, target_id)
        return findings, components
    if fmt == "grype-json":
        findings, _ = parse_grype_json(data, scan_id, target_id)
        return findings, _grype_components(data, scan_id, target_id)
    if fmt == "osv-scanner-json":
        findings, _ = parse_osv_json(data, scan_id, target_id)
        return findings, _osv_components(data, scan_id, target_id)
    raise ValueError(f"Unknown report format: {fmt}")


# ---------------------------------------------------------------- CycloneDX with vulnerabilities

# Scanner names a CycloneDX document's ``metadata.tools`` may carry, mapped to
# the names Hecate's own scans use, so the findings sit next to theirs.
_TOOL_SCANNERS = {"trivy": "trivy", "grype": "grype", "osv-scanner": "osv-scanner"}
CYCLONEDX_IMPORT_SCANNER = "cyclonedx-import"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ADVISORY_ID = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 1}
# CVSS methods by preference: the version Hecate's own data mostly carries first.
_CVSS_METHODS = ("CVSSv31", "CVSSv3", "CVSSv4", "CVSSv2")
_RECOMMENDATION = re.compile(r"Upgrade\s+(\S+)\s+to\s+(?:version\s+)?([^\s;,]+)", re.IGNORECASE)
# CycloneDX analysis.state -> Hecate's VEX status (as the VEX import reads it).
_ANALYSIS_STATES = {
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "exploitable": "affected",
    "in_triage": "under_investigation",
}


def cyclonedx_has_vulnerabilities(data: dict[str, Any]) -> bool:
    """A CycloneDX document that also states its components' vulnerabilities."""
    vulns = data.get("vulnerabilities") if data.get("bomFormat") == "CycloneDX" else None
    return isinstance(vulns, list) and any(isinstance(v, dict) and v.get("affects") for v in vulns)


def _flatten_components(components: Any, out: dict[str, dict[str, Any]]) -> None:
    for comp in components or []:
        if not isinstance(comp, dict):
            continue
        ref = comp.get("bom-ref")
        if isinstance(ref, str) and ref:
            out.setdefault(ref, comp)
        _flatten_components(comp.get("components"), out)


def _tool_names(data: dict[str, Any]) -> list[str]:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    tools = metadata.get("tools")
    entries = tools.get("components") if isinstance(tools, dict) else tools  # 1.5 object / 1.4 list
    if not isinstance(entries, list):
        return []
    return [str(t.get("name") or "").strip().lower() for t in entries if isinstance(t, dict)]


def cyclonedx_scanner(data: dict[str, Any]) -> str:
    """The scanner that wrote the document, as Hecate names it; ``cyclonedx-import`` when unknown."""
    for name in _tool_names(data):
        if name in _TOOL_SCANNERS:
            return _TOOL_SCANNERS[name]
    return CYCLONEDX_IMPORT_SCANNER


def _vulnerability_id(vuln: dict[str, Any]) -> str | None:
    """The CVE when the entry or its references name one, else its own advisory id."""
    candidates = [vuln.get("id")] + [r.get("id") for r in vuln.get("references") or [] if isinstance(r, dict)]
    for value in candidates:
        if isinstance(value, str) and _CVE_ID.match(value.strip()):
            return value.strip().upper()
    own = vuln.get("id")
    return own.strip() if isinstance(own, str) and _ADVISORY_ID.match(own.strip()) else None


def _rating_fields(ratings: Any) -> tuple[str, float | None, str | None]:
    """(severity, CVSS score, CVSS vector) from CycloneDX ratings.

    The severity is the worst any source gave (Hecate's database replaces it
    after the import where it knows the vulnerability). Score and vector come
    from one CVSS rating, NVD's first; EPSS and other "other" ratings are not CVSS.
    """
    severity, rank = "unknown", 0
    cvss: dict[str, Any] | None = None
    best_key: tuple[int, int] | None = None
    for rating in ratings or []:
        if not isinstance(rating, dict):
            continue
        sev = str(rating.get("severity") or "").lower()
        if _SEVERITY_RANK.get(sev, 0) > rank:
            severity, rank = ("info" if sev == "none" else sev), _SEVERITY_RANK[sev]
        method = rating.get("method")
        if method in _CVSS_METHODS and isinstance(rating.get("vector"), str):
            source = rating.get("source") if isinstance(rating.get("source"), dict) else {}
            key = (_CVSS_METHODS.index(method), 0 if str(source.get("name") or "").lower() == "nvd" else 1)
            if best_key is None or key < best_key:
                cvss, best_key = rating, key
    raw_score = cvss.get("score") if cvss else None
    score = float(raw_score) if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else None
    if severity == "unknown" and score is not None:
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return severity, score, (cvss.get("vector") if cvss else None)


def _fix_versions(recommendation: Any) -> dict[str, str]:
    """Package -> fix version from "Upgrade busybox to version 1.35.0-r18; Upgrade ssl_client to ..."."""
    if not isinstance(recommendation, str):
        return {}
    return {m.group(1): m.group(2).rstrip(".") for m in _RECOMMENDATION.finditer(recommendation)}


def _purl_type(purl: Any) -> str | None:
    match = re.match(r"pkg:([^/]+)/", purl) if isinstance(purl, str) else None
    return match.group(1) if match else None


def _apply_analysis(finding: ScanFindingDocument, analysis: dict[str, Any], stamp: datetime) -> None:
    from app.repositories.scan_finding_repository import VEX_IMPORT_ACTOR
    from app.services.vex_export import CYCLONEDX_TO_VEX_JUSTIFICATION

    status = _ANALYSIS_STATES.get(str(analysis.get("state") or ""))
    if not status:
        return
    justification = analysis.get("justification")
    detail = analysis.get("detail")
    response = [r for r in analysis.get("response") or [] if isinstance(r, str)]
    finding.vex_status = status
    finding.vex_justification = (
        CYCLONEDX_TO_VEX_JUSTIFICATION.get(justification, justification) if isinstance(justification, str) else None
    )
    finding.vex_detail = detail[:2000] if isinstance(detail, str) and detail else None
    finding.vex_response = response or None
    finding.vex_updated_at = stamp
    finding.vex_updated_by = VEX_IMPORT_ACTOR


def parse_cyclonedx_vulnerabilities(
    data: dict[str, Any], scan_id: str, target_id: str, *, now: datetime | None = None,
) -> list[ScanFindingDocument]:
    """Findings from a CycloneDX document's ``vulnerabilities``, one per affected component.

    ``affects[].ref`` must name a component's ``bom-ref``; a document whose
    references resolve to nothing (a VEX document, which names packages by
    name) raises ``ValueError``. An ``analysis`` is taken as the document's VEX
    statement (actor ``vex-import``), so a status set in another tool, or in
    the Hecate instance that exported the file, comes along.
    """
    refs: dict[str, dict[str, Any]] = {}
    _flatten_components(data.get("components"), refs)
    scanner = cyclonedx_scanner(data)
    stamp = now or datetime.now(tz=UTC)
    findings: list[ScanFindingDocument] = []
    seen: set[tuple[str, str, str]] = set()
    unresolved = 0
    for vuln in data.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        severity, score, vector = _rating_fields(vuln.get("ratings"))
        fixes = _fix_versions(vuln.get("recommendation"))
        urls = [
            a["url"] for a in vuln.get("advisories") or []
            if isinstance(a, dict) and isinstance(a.get("url"), str) and a["url"].startswith(("https://", "http://"))
        ]
        source = vuln.get("source") if isinstance(vuln.get("source"), dict) else {}
        analysis = vuln.get("analysis") if isinstance(vuln.get("analysis"), dict) else {}
        # A file Hecate exported names the scanners that reported the finding.
        named = next(
            (p.get("value") for p in vuln.get("properties") or []
             if isinstance(p, dict) and p.get("name") == "hecate:scanner" and isinstance(p.get("value"), str)),
            "",
        )
        finding_scanner = named.split(",")[0].strip() or scanner
        for affect in vuln.get("affects") or []:
            comp = refs.get(affect.get("ref")) if isinstance(affect, dict) else None
            if comp is None:
                unresolved += 1
                continue
            name = str(comp.get("name") or "")
            if comp.get("group") and _purl_type(comp.get("purl")) == "maven":
                name = f"{comp['group']}:{name}"
            version = str(comp.get("version") or "")
            key = (str(vuln.get("id") or ""), name, version)
            if not name or key in seen:
                continue
            seen.add(key)
            fix = fixes.get(str(comp.get("name") or "")) or fixes.get(name)
            finding = ScanFindingDocument(
                scan_id=scan_id,
                target_id=target_id,
                vulnerability_id=_vulnerability_id(vuln),
                scanner=finding_scanner,
                package_name=name,
                package_version=version,
                package_type=_purl_type(comp.get("purl")) or str(comp.get("type") or ""),
                severity=severity,
                description=vuln.get("description") if isinstance(vuln.get("description"), str) else None,
                fix_version=fix,
                fix_state="fixed" if fix else "unknown",
                data_source=source.get("name") if isinstance(source.get("name"), str) else None,
                urls=urls,
                cvss_score=score,
                cvss_vector=vector,
            )
            _apply_analysis(finding, analysis, stamp)
            findings.append(finding)
    if not findings and unresolved:
        raise ValueError(
            "The document's vulnerabilities name no component of it (no matching bom-ref). "
            "A VEX document goes to the VEX import of a scan instead."
        )
    return findings
