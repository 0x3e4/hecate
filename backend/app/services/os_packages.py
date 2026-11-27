"""Distribution packages in an imported SBOM, for the import's fallback match.

An imported SBOM is matched by Grype in the scanner sidecar, which knows the
distributions' advisories (``ScanService._scan_imported_sbom``). When no such
scanner answers (no sidecar, ``SCA_SBOM_IMPORT_SCANNERS`` empty, a failure),
Hecate matches the distribution packages against its own database, which has
no distribution advisories. Two things make that match less wrong:

- **The source package.** A binary package often carries another name than
  the project it is built from: ``libc6`` comes from ``glibc``, ``libssl3``
  from ``openssl``. The source is read from the purl qualifier ``upstream``
  (Syft, Grype: ``upstream=glibc`` or ``upstream=glibc%402.36-9``) or from
  Trivy's CycloneDX properties ``aquasecurity:trivy:SrcName`` /
  ``SrcVersion``.
- **The upstream version.** ``2.36-9+deb12u4`` is Debian's: an epoch
  (``1:``), the upstream version and the distribution's revision after the
  last hyphen. Upstream advisories name upstream versions, so the epoch, the
  revision and a repack suffix (``+dfsg``) are cut off; ``~rc1`` becomes a
  pre-release.

A fix the distribution backported into an older upstream version still looks
open this way. Those findings say so in their description; only a
distribution-aware scanner can tell.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, unquote

from app.services.sbom_ecosystem import OS_PURL_TYPES, _purl_type_and_namespace

_EPOCH = re.compile(r"^\d+:")
_APK_RELEASE = re.compile(r"-r\d+$")
_REPACK = re.compile(r"\+.*$")


def os_purl_type(purl: str | None) -> str | None:
    """``deb`` / ``rpm`` / ``apk`` / ``alpm`` for a distribution package's purl, else None."""
    purl_type, _ = _purl_type_and_namespace(purl)
    return purl_type if purl_type in OS_PURL_TYPES else None


def upstream_version(version: str, purl_type: str | None) -> str:
    """The upstream part of a distribution version (``1:2.36-9+deb12u4`` -> ``2.36``)."""
    text = (version or "").strip()
    if not text:
        return ""
    text = _EPOCH.sub("", text)
    if purl_type == "apk":
        text = _APK_RELEASE.sub("", text)
    elif "-" in text:
        # deb revision, rpm release, alpm pkgrel: all after the last hyphen.
        text = text.rsplit("-", 1)[0]
    text = _REPACK.sub("", text)
    return text.replace("~", "-")


def _qualifiers(purl: str) -> dict[str, str]:
    query = purl.split("?", 1)[1].split("#", 1)[0] if "?" in purl else ""
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=False).items() if v}


def purl_upstream(purl: str | None) -> tuple[str | None, str | None]:
    """``(source name, source version)`` from a purl's ``upstream`` qualifier."""
    if not purl or "?" not in purl:
        return None, None
    value = unquote(_qualifiers(purl).get("upstream", "")).strip()
    if not value:
        return None, None
    if value.endswith(".src.rpm"):
        # Syft writes an RPM's source as the source package's file name.
        parts = value[: -len(".src.rpm")].rsplit("-", 2)
        if len(parts) == 3 and all(parts):
            return parts[0], f"{parts[1]}-{parts[2]}"
        return None, None
    name, _, version = value.partition("@")
    if not name and version:
        return None, None
    # Syft writes "openssl@3.0.11-1" or "src (version)" on some distributions.
    match = re.match(r"^(\S+)\s+\((.+)\)$", name)
    if match:
        name, version = match.group(1), match.group(2)
    return name.strip() or None, version.strip() or None


def source_packages(sbom: dict[str, Any]) -> dict[tuple[str, str], tuple[str, str | None]]:
    """``(name, version)`` -> ``(source name, source version)`` for the SBOM's distribution packages.

    Only entries that name a source different from the package, or a source
    version, are listed; reading is best-effort and never raises.
    """
    out: dict[tuple[str, str], tuple[str, str | None]] = {}

    def add(name: Any, version: Any, purl: Any, src: str | None, src_version: str | None) -> None:
        if not isinstance(name, str) or not name or not isinstance(purl, str) or os_purl_type(purl) is None:
            return
        if not src:
            src, src_version = purl_upstream(purl)
        if src and (src != name or src_version):
            out[(name, version if isinstance(version, str) else "")] = (src, src_version)

    try:
        for comp in _cyclonedx_components(sbom.get("components")):
            props = {
                str(p.get("name")): str(p.get("value"))
                for p in comp.get("properties") or []
                if isinstance(p, dict) and p.get("name") and p.get("value") is not None
            }
            src = props.get("aquasecurity:trivy:SrcName") or None
            src_version = props.get("aquasecurity:trivy:SrcVersion") or None
            if src_version and props.get("aquasecurity:trivy:SrcRelease"):
                src_version = f"{src_version}-{props['aquasecurity:trivy:SrcRelease']}"
            add(comp.get("name"), comp.get("version"), comp.get("purl"), src, src_version)
        for pkg in sbom.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            purl = next(
                (
                    ref.get("referenceLocator")
                    for ref in pkg.get("externalRefs") or []
                    if isinstance(ref, dict) and ref.get("referenceType") in ("purl", "pkg:")
                ),
                None,
            )
            add(pkg.get("name"), pkg.get("versionInfo"), purl, None, None)
    except Exception:  # noqa: BLE001 - a fallback aid, never the reason an import fails
        return out
    return out


def _cyclonedx_components(components: Any) -> list[dict[str, Any]]:
    """Every component, nested ones included."""
    out: list[dict[str, Any]] = []
    stack = list(components) if isinstance(components, list) else []
    while stack:
        comp = stack.pop()
        if isinstance(comp, dict):
            out.append(comp)
            nested = comp.get("components")
            if isinstance(nested, list):
                stack.extend(nested)
    return out


def match_identity(
    name: str, version: str, purl: str | None, sources: dict[tuple[str, str], tuple[str, str | None]],
) -> tuple[str, str, str] | None:
    """What a distribution package is matched as: ``(name, upstream version, purl)``, else None.

    The purl handed on keeps the package's distribution type, so the vendor rule
    for distribution packages applies; the name is the source package's.
    """
    purl_type = os_purl_type(purl)
    if purl_type is None:
        return None
    src, src_version = sources.get((name, version)) or purl_upstream(purl)
    match_name = src or name
    match_version = upstream_version(src_version or version, purl_type)
    if not match_name or not match_version:
        return None
    return match_name, match_version, f"pkg:{purl_type}/{match_name}@{match_version}"
