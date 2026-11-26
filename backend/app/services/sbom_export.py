"""SBOM export builders for CycloneDX 1.5 and SPDX 2.3 JSON formats.

The CycloneDX builder can also carry the scan's vulnerability findings
(``vulnerabilities``: severity, CVSS, CWEs, fix, VEX analysis, each pointing at
its component through ``bom-ref``). That is the shape vulnerability platforms
read as a scan report (tested with DefectDojo's "CycloneDX Scan" parser).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from app.services.vex_export import (
    VEX_TO_CYCLONEDX_VERSION_STATUS,
    _generator_version,
    collect_statements,
    cyclonedx_analysis,
    generic_purl,
    vex_review_properties,
)


def _extract_ecosystem(purl: str | None) -> str | None:
    """Extract ecosystem from a Package URL (e.g. 'pkg:npm/foo' -> 'npm')."""
    if not purl:
        return None
    match = re.match(r"pkg:([^/]+)/", purl)
    return match.group(1) if match else None


def _extract_group_and_name(purl: str | None, name: str) -> tuple[str, str]:
    """Extract group (namespace) and name from PURL, falling back to raw name."""
    if purl:
        match = re.match(r"pkg:[^/]+/(?:([^/]+)/)?([^@?#]+)", purl)
        if match:
            return match.group(1) or "", match.group(2)
    return "", name


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value if isinstance(value, str) and value else None


def supply_chain_properties(comp: dict[str, Any]) -> list[dict[str, str]]:
    """CycloneDX ``properties`` for the release-age / publisher signals (``hecate:`` namespace)."""
    props: list[dict[str, str]] = []

    def add(name: str, value: Any) -> None:
        if value is not None and value != "" and value != []:
            props.append({"name": f"hecate:{name}", "value": value if isinstance(value, str) else str(value).lower()})

    add("release:publishedAt", _iso(comp.get("published_at")))
    add("release:latestVersion", comp.get("latest_version"))
    add("release:latestPublishedAt", _iso(comp.get("latest_published_at")))
    add("release:fresh", comp.get("fresh_release"))
    add("release:unmaintained", comp.get("unmaintained"))
    add("npm:publisher", comp.get("publisher"))
    add("npm:publisherChanged", comp.get("publisher_changed"))
    # Native library compiled into a prebuilt package (app/services/bundled_libraries.py).
    add("bundledIn", comp.get("bundled_in"))
    return props


def unique_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per (name, version): scanners report the same package separately.

    The first row wins; fields it leaves empty are taken from later ones, so a
    purl or license only one scanner found is kept.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for comp in components:
        key = (str(comp.get("name") or ""), str(comp.get("version") or ""))
        current = merged.get(key)
        if current is None:
            merged[key] = dict(comp)
            continue
        for field, value in comp.items():
            if value not in (None, "", [], {}) and current.get(field) in (None, "", [], {}):
                current[field] = value
    return list(merged.values())


def _unique_ref(base: str, taken: set[str]) -> str:
    ref, n = base, 1
    while ref in taken:
        n += 1
        ref = f"{base}#{n}"
    taken.add(ref)
    return ref


@lru_cache(maxsize=1)
def _spdx_ids() -> dict[str, str]:
    """Lower-cased SPDX identifier -> its canonical spelling."""
    path = Path(__file__).resolve().parent.parent / "data" / "spdx_license_ids.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:  # pragma: no cover - the file ships with the app
        return {}
    return {line.strip().lower(): line.strip() for line in lines if line.strip() and not line.startswith("#")}


_EXPRESSION_RE = re.compile(r"\s(?:AND|OR|WITH)\s|^\(", re.IGNORECASE)


def cyclonedx_licenses(values: list[Any]) -> list[dict[str, Any]]:
    """CycloneDX ``licenses`` entries the schema accepts.

    ``license.id`` must be an SPDX identifier, so scanners' own words
    (Debian's ``Expat``, ``GPL-2+``) go in as ``name``. The schema takes an
    SPDX expression only as the list's single entry, so a lone expression is an
    ``expression`` and one next to other values is kept as a ``name``.
    """
    ids = _spdx_ids()
    texts: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip() and value.strip() not in texts:
            texts.append(value.strip())
    if len(texts) == 1 and _EXPRESSION_RE.search(texts[0]):
        return [{"expression": texts[0]}]
    return [
        {"license": {"id": ids[text.lower()]}} if text.lower() in ids else {"license": {"name": text[:200]}}
        for text in texts
    ]


# CycloneDX 1.5 component types. Scanners write their own package types
# (``python-pkg``, ``deb``, ``npm``), which the schema refuses; those become
# ``library`` and keep the scanner's word in ``hecate:packageType``.
CYCLONEDX_COMPONENT_TYPES = frozenset({
    "application", "framework", "library", "container", "platform", "operating-system",
    "device", "device-driver", "firmware", "file", "machine-learning-model", "data",
})
_OS_PACKAGE_TYPES = frozenset({"os", "operating-system"})


def cyclonedx_component_type(package_type: Any) -> str:
    value = str(package_type or "").strip().lower()
    if value in CYCLONEDX_COMPONENT_TYPES:
        return value
    return "operating-system" if value in _OS_PACKAGE_TYPES else "library"


def _cdx_component(comp: dict[str, Any], ref: str) -> dict[str, Any]:
    cdx_type = cyclonedx_component_type(comp.get("type"))
    c: dict[str, Any] = {
        "bom-ref": ref,
        "type": cdx_type,
        "name": comp.get("name", ""),
    }
    if comp.get("version"):
        c["version"] = comp["version"]
    if comp.get("purl"):
        c["purl"] = comp["purl"]
        group, parsed_name = _extract_group_and_name(comp["purl"], comp.get("name", ""))
        if group:
            c["group"] = group
            c["name"] = parsed_name

    licenses = cyclonedx_licenses(comp.get("licenses") or [])
    if licenses:
        c["licenses"] = licenses

    if comp.get("supplier"):
        c["supplier"] = {"name": comp["supplier"]}

    if comp.get("cpe"):
        c["cpe"] = comp["cpe"]

    properties = supply_chain_properties(comp)
    raw_type = str(comp.get("type") or "").strip()
    if raw_type and raw_type.lower() != cdx_type:
        properties.insert(0, {"name": "hecate:packageType", "value": raw_type})
    if properties:
        c["properties"] = properties
    return c


# ---------------------------------------------------------------- vulnerabilities

# CycloneDX ratings[].severity enum; "negligible" is Grype's word for info.
_CDX_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
    "info": "info",
}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
# Finding types without an advisory: SAST, secrets and compliance checks have
# their own tabs and no vulnerability to report.
_NO_ADVISORY_TYPES = frozenset({"sast-finding", "secret-finding", "compliance-check"})
MAX_ADVISORY_URLS = 20
_CWE_RE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)


def _rating_method(vector: str) -> str | None:
    if vector.startswith("CVSS:4.0/"):
        return "CVSSv4"
    if vector.startswith("CVSS:3.1/"):
        return "CVSSv31"
    if vector.startswith("CVSS:3.0/"):
        return "CVSSv3"
    if vector.startswith("AV:"):
        return "CVSSv2"
    return None


def _rating(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The worst rating the scanners gave, with its CVSS score and vector."""
    best: dict[str, Any] | None = None
    best_key: tuple[int, float] = (0, -1.0)
    for f in findings:
        severity = _CDX_SEVERITY.get(str(f.get("severity") or "").lower())
        raw_score = f.get("cvss_score")
        score = float(raw_score) if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else None
        key = (_SEVERITY_RANK.get(severity or "", 0), score if score is not None else -1.0)
        if key <= best_key:
            continue
        rating: dict[str, Any] = {}
        if severity:
            rating["severity"] = severity
        vector = f.get("cvss_vector").strip() if isinstance(f.get("cvss_vector"), str) else ""
        method = _rating_method(vector) if vector else None
        if method:
            rating["method"] = method
            rating["vector"] = vector
            if score is not None:
                rating["score"] = score
        if rating:
            best, best_key = rating, key
    return best


def _cwe_numbers(values: Any) -> list[int]:
    out: list[int] = []
    for value in values or []:
        match = _CWE_RE.match(str(value).strip())
        if match and int(match.group(1)) not in out:
            out.append(int(match.group(1)))
    return out


def _source(vuln_id: str) -> dict[str, str] | None:
    """Where the advisory lives: NVD for CVEs, GitHub for GHSAs, OSV for the rest."""
    upper = vuln_id.upper()
    quoted = quote(vuln_id, safe="")
    if upper.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{quoted}"}
    if upper.startswith("GHSA-"):
        return {"name": "GitHub", "url": f"https://github.com/advisories/{quoted}"}
    if re.match(r"^[A-Z0-9]+-", upper):
        return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{quoted}"}
    return None


def _advisories(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    urls: list[str] = []
    for f in findings:
        for url in f.get("urls") or []:
            if isinstance(url, str) and url.startswith(("https://", "http://")) and url not in urls:
                urls.append(url)
    return [{"url": url} for url in urls[:MAX_ADVISORY_URLS]]


def _first_text(findings: list[dict[str, Any]], field: str, limit: int) -> str | None:
    for f in findings:
        value = f.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()[:limit]
    return None


def _component_ref(
    refs: dict[tuple[str, str], str], name: str, version: str,
) -> str | None:
    exact = refs.get((name.lower(), version))
    if exact:
        return exact
    loose = refs.get((name.lower(), ""))
    # A component of another version would name the wrong release.
    return loose if loose and version and version in loose else None


def build_cyclonedx_vulnerabilities(
    findings: list[dict[str, Any]],
    refs: dict[tuple[str, str], str],
    *,
    cwes: dict[str, list[str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(vulnerabilities, extra components) for the CycloneDX ``vulnerabilities`` array.

    One entry per (vulnerability, package, version) across scanners, because the
    VEX status is kept per package. ``refs`` maps (lower-cased name, version)
    to the component's ``bom-ref``, with name-only keys (version ``""``) as a
    fallback; a package the SBOM does not list gets a component of its own so
    every ``affects`` reference resolves. Unassessed findings carry no
    ``analysis``: they are open, not "in triage".
    """
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for f in findings:
        vid = f.get("vulnerability_id")
        if not isinstance(vid, str) or not vid.strip() or f.get("package_type") in _NO_ADVISORY_TYPES:
            continue
        key = (vid.strip(), str(f.get("package_name") or ""), str(f.get("package_version") or ""))
        grouped.setdefault(key, []).append(f)

    statements = {
        (st["vulnerability_id"], st["package_name"], st["package_version"]): st
        for st in collect_statements(findings)
    }
    taken = set(refs.values())
    extra: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    for index, key in enumerate(sorted(grouped), start=1):
        vid, name, version = key
        rows = grouped[key]
        ref = _component_ref(refs, name, version)
        if ref is None:
            purl = generic_purl(name, version)
            ref = _unique_ref(purl, taken)
            refs[(name.lower(), version)] = ref
            component: dict[str, Any] = {"bom-ref": ref, "type": "library", "name": name or "unknown", "purl": purl}
            if version:
                component["version"] = version
            extra.append(component)

        statement = statements.get(key) or {}
        assessed = bool(statement.get("assessed"))
        # The row whose status the VEX exports state (newest status wins).
        status_row = next((f for f in rows if f.get("vex_status") == statement.get("status")), rows[0]) if assessed else rows[0]
        analysis = cyclonedx_analysis(status_row) if assessed else None

        entry: dict[str, Any] = {"bom-ref": f"vulnerability-{index}", "id": vid}
        source = _source(vid)
        if source:
            entry["source"] = source
        rating = _rating(rows)
        if rating:
            entry["ratings"] = [rating]
        cwe_numbers = _cwe_numbers((cwes or {}).get(vid))
        if cwe_numbers:
            entry["cwes"] = cwe_numbers
        description = _first_text(rows, "description", 4000) or _first_text(rows, "title", 500)
        if description:
            entry["description"] = description
        fix = _first_text(rows, "fix_version", 200)
        if fix:
            entry["recommendation"] = f"Upgrade {name} to {fix}." if name else f"Upgrade to {fix}."
        advisories = _advisories(rows)
        if advisories:
            entry["advisories"] = advisories
        if analysis:
            entry["analysis"] = analysis
        version_status = VEX_TO_CYCLONEDX_VERSION_STATUS.get(statement["status"], "affected") if assessed else "affected"
        affect: dict[str, Any] = {"ref": ref}
        if version:
            affect["versions"] = [{"version": version, "status": version_status}]
        entry["affects"] = [affect]

        scanners = ", ".join(sorted({str(f["scanner"]) for f in rows if f.get("scanner")}))
        properties = [{"name": "hecate:scanner", "value": scanners}] if scanners else []
        for prop, field in (
            ("hecate:dependencyScope", "dependency_scope"),
            ("hecate:fixState", "fix_state"),
            ("hecate:packagePath", "package_path"),
        ):
            value = _first_text(rows, field, 500)
            if value and value != "unknown":
                properties.append({"name": prop, "value": value})
        if analysis:
            properties.extend(vex_review_properties(status_row))
        if properties:
            entry["properties"] = properties
        vulnerabilities.append(entry)
    return vulnerabilities, extra


def build_cyclonedx_json(
    scan: dict[str, Any],
    target: dict[str, Any] | None,
    components: list[dict[str, Any]],
    *,
    findings: list[dict[str, Any]] | None = None,
    cwes: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON BOM document.

    Components are listed once per (name, version), each with a ``bom-ref``.
    With ``findings`` the document also lists the scan's vulnerabilities
    (``build_cyclonedx_vulnerabilities``); ``cwes`` maps a vulnerability id to
    the CWE ids of Hecate's record of it.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target_name = target.get("name", "") if target else scan.get("target_name", "unknown")
    target_type = target.get("type", "container_image") if target else "container_image"

    cdx_components = []
    refs: dict[tuple[str, str], str] = {}
    taken: set[str] = set()
    for comp in unique_components(components):
        base = comp.get("purl") or f"{comp.get('name') or 'unknown'}@{comp.get('version') or ''}"
        ref = _unique_ref(str(base), taken)
        name = str(comp.get("name") or "").lower()
        refs.setdefault((name, str(comp.get("version") or "")), ref)
        refs.setdefault((name, ""), ref)
        cdx_components.append(_cdx_component(comp, ref))

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Hecate", "name": "Hecate", "version": _generator_version()}],
            "component": {
                "type": "application" if target_type == "source_repo" else "container",
                "name": target_name,
            },
        },
        "components": cdx_components,
    }
    if findings is not None:
        vulnerabilities, extra = build_cyclonedx_vulnerabilities(findings, refs, cwes=cwes)
        doc["components"].extend(extra)
        doc["vulnerabilities"] = vulnerabilities
    return doc


def build_spdx_json(
    scan: dict[str, Any],
    target: dict[str, Any] | None,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON document."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_id = str(scan.get("_id", ""))
    target_name = target.get("name", "") if target else scan.get("target_name", "unknown")
    doc_spdx_id = "SPDXRef-DOCUMENT"

    packages = []
    relationships = []

    # Root package representing the scanned target
    root_id = "SPDXRef-RootPackage"
    packages.append({
        "SPDXID": root_id,
        "name": target_name,
        "versionInfo": scan.get("image_ref", "") or "",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    })
    relationships.append({
        "spdxElementId": doc_spdx_id,
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    })

    for i, comp in enumerate(components):
        pkg_id = f"SPDXRef-Package-{i}"
        licenses = comp.get("licenses") or []
        license_str = " AND ".join(licenses) if licenses else "NOASSERTION"

        pkg: dict[str, Any] = {
            "SPDXID": pkg_id,
            "name": comp.get("name", ""),
            "versionInfo": comp.get("version", ""),
            "downloadLocation": comp.get("purl") or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": license_str,
            "licenseDeclared": license_str,
            "copyrightText": "NOASSERTION",
        }

        if comp.get("supplier"):
            pkg["supplier"] = f"Organization: {comp['supplier']}"

        if comp.get("purl"):
            pkg["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp["purl"],
            }]

        packages.append(pkg)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_spdx_id,
        "name": f"Hecate SBOM for {target_name}",
        "documentNamespace": f"https://hecate.local/spdx/{scan_id}/{uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": [f"Tool: Hecate-{_generator_version()}"],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
        "relationships": relationships,
    }
