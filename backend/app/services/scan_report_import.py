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
