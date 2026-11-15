"""Pre-install package check for AI coding agents and CI.

``check_package(ecosystem, name, version)`` answers "may I install this?" with
a verdict ``block`` | ``warn`` | ``ok`` and the reasons behind it:

- **block**: a known malicious package (an OSV ``MAL-*`` record that covers the
  version, or the whole package), a vulnerability affecting the version that
  CISA lists as exploited (KEV), or a critical one.
- **warn**: other vulnerabilities affecting the version; a release younger
  than ``SCA_FRESH_RELEASE_DAYS`` (the "cooldown", waived when an advisory
  names exactly this version as its fix); an npm version published by an
  account that published none of the versions before it; no release for
  ``SCA_UNMAINTAINED_DAYS``; a deprecated version; a package or version the
  registry doesn't know (a typo, or a name an assistant made up).
- **ok**: none of these.

Without a version the check uses the registry's latest version, which is what
an install without a pin would fetch. Advisories are matched like the SBOM
side of "Affected in your scans": the version has to sit in an
``impactedProducts`` range, and a registry package only takes the ranges of an
entry whose vendor fits it (``allowed_vendor_slugs``), so npm ``console`` never
borrows Citrix NetScaler Console's ranges. Used by ``GET /api/v1/packages/check``
and the MCP tool ``check_package``.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import structlog

from app.core.config import settings
from app.services.inventory_matcher import _BROAD_RANGE_SENTINELS, _compare_versions, _slug, is_marked_not_vulnerable
from app.services.sbom_ecosystem import allowed_vendor_slugs, vendor_names_component
from app.services.supply_chain_service import (
    ReleaseInfo,
    SupplyChainService,
    canonical_ecosystem,
    normalize_package_name,
)

log = structlog.get_logger()

_NAME_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@/._\-:~+]{0,299}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-+~:!]{0,99}$")
_MAX_ADVISORIES = 1000
_QUERY_TIMEOUT_MS = 5000

# Hecate ecosystem -> purl type (for the registry-vendor rule)
_PURL_TYPES = {
    "npm": "npm", "pypi": "pypi", "go": "golang", "maven": "maven", "cargo": "cargo",
    "nuget": "nuget", "rubygems": "gem", "packagist": "composer",
}

_PROJECTION = {
    "_id": 1, "aliases": 1, "title": 1, "summary": 1, "cvss": 1, "epss_score": 1,
    "exploitation": 1, "impactedProducts": 1, "impacted_products": 1, "published": 1,
}


class PackageCheckError(ValueError):
    """Invalid input (unknown ecosystem, malformed name or version)."""


def validate_input(ecosystem: str | None, name: str | None, version: str | None) -> tuple[str, str, str | None]:
    eco = canonical_ecosystem(ecosystem)
    if not eco:
        raise PackageCheckError(
            "Unknown ecosystem. Use one of: npm, pypi, go, maven, cargo, nuget, rubygems, packagist."
        )
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise PackageCheckError("Invalid package name.")
    version = (version or "").strip() or None
    if version and not _VERSION_RE.match(version):
        raise PackageCheckError("Invalid version.")
    return eco, normalize_package_name(eco, name), version


def package_purl(ecosystem: str, name: str, version: str | None = None) -> str:
    purl_type = _PURL_TYPES[ecosystem]
    if ecosystem == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group, safe='.')}/{quote(artifact, safe='')}"
    elif ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        path = f"{quote(scope, safe='')}/{quote(pkg, safe='')}"
    else:
        path = "/".join(quote(p, safe="") for p in name.split("/"))
    return f"pkg:{purl_type}/{path}" + (f"@{quote(version, safe='')}" if version else "")


def name_slugs(ecosystem: str, name: str) -> list[str]:
    """Product slugs an advisory for this package may carry."""
    slugs = {_slug(name)}
    if ecosystem == "maven" and ":" in name:
        # GHSA / OSV name Maven packages group:artifact; NVD often the artifact.
        slugs.add(_slug(name.split(":", 1)[1]))
    return sorted(s for s in slugs if s)


def _is_malicious(doc: dict[str, Any]) -> bool:
    ids = [str(doc.get("_id") or ""), *(str(a) for a in (doc.get("aliases") or []))]
    return any(i.upper().startswith("MAL-") for i in ids)


def _matching_entries(doc: dict[str, Any], slugs: set[str], allowed: frozenset[str] | None) -> list[dict[str, Any]]:
    impacted = doc.get("impactedProducts") or doc.get("impacted_products") or []
    out: list[dict[str, Any]] = []
    for entry in impacted:
        if not isinstance(entry, dict) or is_marked_not_vulnerable(entry):
            continue
        product = entry.get("product") or {}
        names = {_slug(v) for v in (product.get("slug"), product.get("name")) if isinstance(product, dict) and v}
        if not names & slugs:
            continue
        vendor = entry.get("vendor") or {}
        vendor_values = [vendor.get("slug"), vendor.get("name")] if isinstance(vendor, dict) else []
        if not vendor_names_component(allowed, vendor_values):
            continue
        out.append(entry)
    return out


def _ranges(entries: list[dict[str, Any]]) -> list[str]:
    return [str(v) for e in entries for v in (e.get("versions") or []) if str(v).strip()]


def _covers(version: str, entries: list[dict[str, Any]]) -> bool:
    from app.services.inventory_matcher import version_in_ranges

    ranges = _ranges(entries)
    return bool(ranges) and version_in_ranges(version, ranges)


def _whole_package(entries: list[dict[str, Any]]) -> bool:
    ranges = _ranges(entries)
    return not ranges or all(r.strip().lower() in _BROAD_RANGE_SENTINELS for r in ranges)


def _fixed_versions(entries: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for entry in entries:
        for key in ("patchedVersions", "patched_versions", "unaffectedVersions", "unaffected_versions"):
            for v in entry.get(key) or []:
                s = str(v).strip()
                if s and s not in seen and not s.startswith(("<", ">", "=")):
                    seen.append(s)
    return seen


def _severity(doc: dict[str, Any]) -> str:
    cvss = doc.get("cvss") if isinstance(doc.get("cvss"), dict) else {}
    return str(cvss.get("severity") or "unknown").lower()


def _version_key_sorted(versions: list[str]) -> list[str]:
    import functools

    def cmp(a: str, b: str) -> int:
        result = _compare_versions(a, b)
        return result if result is not None else (a > b) - (a < b)

    return sorted(set(versions), key=functools.cmp_to_key(cmp))


def evaluate_package(
    ecosystem: str,
    name: str,
    version: str | None,
    docs: list[dict[str, Any]],
    release: ReleaseInfo | None,
    *,
    version_source: str = "requested",
    max_items: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The verdict for one package version from its advisories and release info (pure)."""
    now = now or datetime.now(UTC)
    allowed = allowed_vendor_slugs(package_purl(ecosystem, name), name)
    slugs = set(name_slugs(ecosystem, name))
    reasons: list[dict[str, str]] = []

    def reason(level: str, code: str, message: str) -> None:
        reasons.append({"level": level, "code": code, "message": message})

    malicious: list[dict[str, Any]] = []
    vulns: list[dict[str, Any]] = []
    affected_entries: list[list[dict[str, Any]]] = []
    known_advisories = 0
    for doc in docs:
        entries = _matching_entries(doc, slugs, allowed)
        if not entries:
            continue
        known_advisories += 1
        doc_id = str(doc.get("_id") or "")
        if _is_malicious(doc):
            whole = _whole_package(entries)
            covers = True if whole else (_covers(version, entries) if version else None)
            malicious.append({
                "id": doc_id,
                "summary": (doc.get("summary") or doc.get("title") or "")[:300],
                "wholePackage": whole,
                "coversVersion": covers,
                "versions": _ranges(entries)[:20],
            })
            continue
        if not version or not _covers(version, entries):
            continue
        affected_entries.append(entries)
        vulns.append({
            "id": doc_id,
            "aliases": [a for a in (doc.get("aliases") or []) if isinstance(a, str)][:10],
            "title": (doc.get("title") or doc.get("summary") or "")[:200],
            "severity": _severity(doc),
            "cvss": (doc.get("cvss") or {}).get("base_score") if isinstance(doc.get("cvss"), dict) else None,
            "epss": doc.get("epss_score"),
            "kev": bool(doc.get("exploitation")),
            "fixedVersions": _fixed_versions(entries)[:10],
        })

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    vulns.sort(key=lambda v: (v["kev"], sev_rank.get(v["severity"], 0), v["cvss"] or 0), reverse=True)

    # --- malicious
    for m in malicious:
        if m["coversVersion"]:
            what = "every version of this package" if m["wholePackage"] else f"version {version}"
            reason("block", "malicious", f"{m['id']}: known malicious package, covering {what}.")
        elif m["coversVersion"] is None:
            reason("warn", "malicious_versions", f"{m['id']}: some versions of this package are known malicious.")

    # --- vulnerabilities
    kev = [v for v in vulns if v["kev"]]
    critical = [v for v in vulns if v["severity"] == "critical" and not v["kev"]]
    others = [v for v in vulns if not v["kev"] and v["severity"] != "critical"]
    if kev:
        reason("block", "kev", f"Affected by {len(kev)} actively exploited vulnerabilit{'y' if len(kev) == 1 else 'ies'} "
               f"(CISA KEV): {', '.join(v['id'] for v in kev[:5])}.")
    if critical:
        reason("block", "critical", f"Affected by {len(critical)} critical vulnerabilit{'y' if len(critical) == 1 else 'ies'}: "
               f"{', '.join(v['id'] for v in critical[:5])}.")
    if others:
        reason("warn", "vulnerable", f"Affected by {len(others)} vulnerabilit{'y' if len(others) == 1 else 'ies'}: "
               f"{', '.join(v['id'] for v in others[:5])}.")

    # --- release signals
    release_out: dict[str, Any] | None = None
    if release is not None:
        flags = release.flags(now)
        age = release.age_days(now)
        release_out = {
            "packageFound": release.package_found,
            "versionFound": release.version_found,
            "publishedAt": release.published_at.isoformat() if release.published_at else None,
            "ageDays": round(age, 1) if age is not None else None,
            "latestVersion": release.latest_version,
            "latestPublishedAt": release.latest_published_at.isoformat() if release.latest_published_at else None,
            "deprecated": release.deprecated,
            "publisher": release.publisher,
            "previousPublishers": release.previous_publishers,
            "newMaintainers": release.new_maintainers,
            "freshRelease": flags["fresh_release"],
            "unmaintained": flags["unmaintained"],
            "publisherChanged": flags["publisher_changed"],
        }
        if not release.package_found:
            reason("warn", "unknown_package",
                   f"The {ecosystem} registry doesn't know this package (check the name for a typo or a made-up "
                   "package; private packages show up here too).")
        elif version and not release.version_found:
            reason("warn", "unknown_version", f"The registry has no version {version} of this package.")
        if flags["fresh_release"]:
            fixes = [v for v in docs if version and version in _fixed_versions(_matching_entries(v, slugs, allowed))]
            days = f"{age:.0f}" if age is not None else "?"
            if fixes:
                reason("info", "fresh_release_fix",
                       f"Published {days} days ago, but it is the fix for {fixes[0].get('_id')}; the cooldown is waived.")
            else:
                reason("warn", "fresh_release",
                       f"Published {days} days ago (cooldown: less than the configured minimum age). New releases are how "
                       "worms like Shai-Hulud spread; prefer the previous version unless you need this one.")
        if flags["publisher_changed"]:
            reason("warn", "publisher_changed",
                   f"Published by npm account '{release.publisher}', which published none of the previous versions "
                   f"({', '.join(release.previous_publishers)}).")
        if release.new_maintainers:
            reason("info", "new_maintainers", f"Maintainers added since the previous version: {', '.join(release.new_maintainers)}.")
        if flags["unmaintained"]:
            reason("warn", "unmaintained", "No release for a long time: the package looks unmaintained.")
        if release.deprecated:
            reason("warn", "deprecated", "The registry marks this version as deprecated.")

    # --- recommendation: the lowest named fix (or the latest) that no matched advisory covers
    recommended: str | None = None
    if version and (vulns or any(m["coversVersion"] for m in malicious if not m["wholePackage"])):
        candidates = [f for entries in affected_entries for f in _fixed_versions(entries)]
        if release and release.latest_version:
            candidates.append(release.latest_version)
        mal_entries = [_matching_entries(d, slugs, allowed) for d in docs if _is_malicious(d)]
        for candidate in _version_key_sorted(candidates):
            if _compare_versions(candidate, version) not in (1,):
                continue
            all_entries = [e for e in (_matching_entries(d, slugs, allowed) for d in docs) if e]
            if any(_covers(candidate, e) for e in all_entries) or any(_whole_package(e) for e in mal_entries if e):
                continue
            recommended = candidate
            break

    levels = {r["level"] for r in reasons}
    verdict = "block" if "block" in levels else "warn" if "warn" in levels else "ok"
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "versionSource": version_source,
        "purl": package_purl(ecosystem, name, version),
        "verdict": verdict,
        "reasons": reasons,
        "malicious": malicious[:max_items],
        "vulnerabilities": vulns[:max_items],
        "vulnerabilityCount": len(vulns),
        "advisoriesForPackage": known_advisories,
        "release": release_out,
        "recommendedVersion": recommended,
        "checkedAt": now.isoformat(),
    }


async def find_package_advisories(vuln_collection: Any, ecosystem: str, name: str) -> list[dict[str, Any]]:
    """Advisories naming this package (indexed ``product_slugs`` lookup, time-boxed)."""
    slugs = name_slugs(ecosystem, name)
    cursor = vuln_collection.find({"product_slugs": {"$in": slugs}}, _PROJECTION).limit(_MAX_ADVISORIES)
    try:
        cursor = cursor.max_time_ms(_QUERY_TIMEOUT_MS)
    except AttributeError:
        pass
    return [doc async for doc in cursor]


async def check_package(
    ecosystem: str | None,
    name: str | None,
    version: str | None = None,
    *,
    vuln_collection: Any,
    supply_chain: SupplyChainService | None,
    max_items: int = 50,
) -> dict[str, Any]:
    """Validate, look everything up, decide. Raises ``PackageCheckError`` on bad input."""
    eco, pkg, requested = validate_input(ecosystem, name, version)
    release: ReleaseInfo | None = None
    if supply_chain is not None:
        try:
            # The lookup waits on the deps.dev rate limit every caller shares;
            # past the deadline the check answers from advisory data alone, well
            # inside a pre-install hook's timeout, and gives up its queue slot.
            release = await asyncio.wait_for(
                supply_chain.get_release_info(eco, pkg, requested or ""),
                timeout=settings.package_check_release_timeout_seconds,
            )
        except TimeoutError:
            log.info("package_check.release_lookup_timed_out", ecosystem=eco, package=pkg)
        except Exception:  # noqa: BLE001 - release data is enrichment
            log.warning("package_check.release_lookup_failed", ecosystem=eco, package=pkg, exc_info=True)
    effective = requested
    source = "requested"
    if not requested and release is not None and release.version:
        effective, source = release.version, "latest"
    docs = await find_package_advisories(vuln_collection, eco, pkg)
    return evaluate_package(eco, pkg, effective, docs, release, version_source=source, max_items=max_items)
