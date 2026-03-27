"""SBOM export builders for CycloneDX 1.5 and SPDX 2.3 JSON formats."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

HECATE_VERSION = "0.7.5"


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


def build_cyclonedx_json(
    scan: dict[str, Any],
    target: dict[str, Any] | None,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON BOM document."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target_name = target.get("name", "") if target else scan.get("target_name", "unknown")
    target_type = target.get("type", "container_image") if target else "container_image"

    cdx_components = []
    for comp in components:
        c: dict[str, Any] = {
            "type": comp.get("type") or "library",
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

        licenses = comp.get("licenses") or []
        if licenses:
            c["licenses"] = [
                {"license": {"id": lic} if not lic.startswith("(") else {"expression": lic}}
                for lic in licenses
            ]

        if comp.get("supplier"):
            c["supplier"] = {"name": comp["supplier"]}

        if comp.get("cpe"):
            c["cpe"] = comp["cpe"]

        cdx_components.append(c)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "Hecate", "version": HECATE_VERSION}],
            "component": {
                "type": "application" if target_type == "source_repo" else "container",
                "name": target_name,
            },
        },
        "components": cdx_components,
    }


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
            "creators": [f"Tool: Hecate-{HECATE_VERSION}"],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
        "relationships": relationships,
    }
