"""Which advisory vendors can name an SBOM component.

The SBOM side of "Affected in your scans" and the dashboard's scan coverage
match a component to a CVE by package name. A name alone is not enough: npm's
``console`` package and Citrix NetScaler *Console* share it, and the numeric
version check then happily puts ``console@0.15.11`` below NetScaler's
``< 14.1-74.34``.

A component from a language registry (purl type npm, pypi, maven, …) can only
be what an advisory names when the advisory's vendor is that registry (GHSA and
OSV write ``npm`` / ``PyPI`` / ``Maven`` as the vendor), the package's own
namespace (``@angular`` → ``angular``, ``org.apache.logging.log4j`` →
``apache``), or the package itself (NVD's ``lodash:lodash``). OS and binary
packages (``deb``, ``apk``, ``rpm``, ``generic``, …) and components without a
purl keep the plain name match: there NVD's vendors are the projects
themselves (``openssl``, ``nodejs``) and no registry name exists to compare.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import unquote

from app.services.inventory_matcher import _slug, is_marked_not_vulnerable, version_in_ranges
from app.utils.strings import slugify

# purl type -> vendor slugs that stand for the registry itself.
LANGUAGE_ECOSYSTEM_VENDORS: dict[str, frozenset[str]] = {
    "npm": frozenset({"npm", "npmjs"}),
    "pypi": frozenset({"pypi", "pip", "python"}),
    "maven": frozenset({"maven"}),
    "golang": frozenset({"go", "golang"}),
    "cargo": frozenset({"cargo", "crates-io"}),
    "nuget": frozenset({"nuget"}),
    "gem": frozenset({"rubygems", "gem"}),
    "composer": frozenset({"packagist", "composer"}),
    "pub": frozenset({"pub"}),
    "hex": frozenset({"hex"}),
    "swift": frozenset({"swift", "swiftpm"}),
    "cocoapods": frozenset({"cocoapods"}),
    "conda": frozenset({"conda"}),
    "github": frozenset({"github-actions"}),
    "githubactions": frozenset({"github-actions"}),
}

# Namespace pieces that say nothing about who makes a package.
_NOISE_SEGMENTS = frozenset({"com", "org", "net", "io", "dev", "co", "www", "github", "gitlab"})


def _purl_type_and_namespace(purl: str | None) -> tuple[str | None, str | None]:
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    body = body.rsplit("@", 1)[0] if "@" in body.split("/")[-1] else body
    parts = [p for p in body.split("/") if p]
    if not parts:
        return None, None
    purl_type = parts[0].lower()
    namespace = "/".join(parts[1:-1]) if len(parts) > 2 else None
    return purl_type, unquote(namespace) if namespace else None


def allowed_vendor_slugs(purl: str | None, name: str | None) -> frozenset[str] | None:
    """Vendor slugs an advisory may carry to name this component.

    ``None`` means any vendor: the component is no language-registry package
    (OS / binary / generic / no purl), so the name match stays as it was.
    """
    purl_type, namespace = _purl_type_and_namespace(purl)
    registry = LANGUAGE_ECOSYSTEM_VENDORS.get(purl_type or "")
    if registry is None:
        return None
    allowed: set[str] = set(registry)
    if name:
        allowed.add(slugify(name))
        # npm scoped names arrive as "@scope/pkg" in the SBOM name as well.
        if name.startswith("@") and "/" in name:
            allowed.add(slugify(name[1:].split("/", 1)[0]))
    if namespace:
        allowed.add(slugify(namespace.lstrip("@")))
        for segment in namespace.replace("/", ".").split("."):
            segment = segment.strip().lstrip("@")
            if segment and segment.lower() not in _NOISE_SEGMENTS:
                allowed.add(slugify(segment))
    return frozenset(s for s in allowed if s)


def vendor_names_component(allowed: frozenset[str] | None, vendor_values: Iterable[str | None]) -> bool:
    """Whether any of an advisory entry's vendor values fits the component.

    An entry without vendor information is not held against the component.
    """
    if allowed is None:
        return True
    slugs = {slugify(v) for v in vendor_values if isinstance(v, str) and v.strip()}
    if not slugs:
        return True
    return not slugs.isdisjoint(allowed)


# --- Version-checked SBOM match against a CVE's impactedProducts ------------
#
# Shared by the vulnerability detail page ("Affected in your scans", sbom pass)
# and the dashboard / advisories coverage (``ScanService.sbom_version_hits``),
# so a package name alone never counts: the installed version has to sit in the
# advisory's affected range, and a registry package only takes the ranges of an
# entry whose vendor fits it.

# product-slug -> [(vendor values, affected version-range strings)]
AffectedEntries = dict[str, list[tuple[tuple[str, ...], list[str]]]]


def affected_entries_by_slug(
    impacted_products: Iterable[Any] | None,
) -> tuple[AffectedEntries, set[str]]:
    """Index a CVE's impactedProducts by product slug, plus the SBOM names to query.

    The vendor stays with its ranges: a name shared across ecosystems (npm
    ``console`` vs. Citrix NetScaler Console) must not borrow another product's
    ranges. Entries marked ``vulnerable: false`` (the platform the vulnerable
    product runs on) and entries without versions are skipped.
    """
    entries_by_slug: AffectedEntries = {}
    candidate_names: set[str] = set()
    for entry in impacted_products or []:
        if not isinstance(entry, dict) or is_marked_not_vulnerable(entry):
            continue
        product = entry.get("product") or {}
        prod_slug = product.get("slug") if isinstance(product, dict) else None
        prod_name = product.get("name") if isinstance(product, dict) else None
        vendor = entry.get("vendor") or {}
        vendor_values = tuple(
            str(v) for v in ((vendor.get("slug"), vendor.get("name")) if isinstance(vendor, dict) else ())
            if v
        )
        ranges = [str(v) for v in (entry.get("versions") or []) if str(v).strip()]
        if not ranges:
            continue
        slugs_for_entry: set[str] = set()
        for raw in (prod_slug, prod_name):
            if raw:
                candidate_names.add(str(raw))
                candidate_names.add(str(raw).lower())
                slug = _slug(raw)
                if slug:
                    candidate_names.add(slug)
                    slugs_for_entry.add(slug)
        for slug in slugs_for_entry:
            entries_by_slug.setdefault(slug, []).append((vendor_values, ranges))
    return entries_by_slug, candidate_names


_UNSET: Any = object()


def component_in_affected_range(
    entries_by_slug: AffectedEntries,
    *,
    name: str,
    version: str,
    purl: str | None = None,
    slug: str | None = None,
    allowed: frozenset[str] | None = _UNSET,
    memo: dict[tuple[str, tuple[str, ...]], bool] | None = None,
) -> bool:
    """Whether an SBOM component sits at a version ``entries_by_slug`` marks affected.

    ``slug`` / ``allowed`` may be passed precomputed (the dashboard index holds
    them per component); ``memo`` caches the range evaluation per
    (version, ranges) across many CVEs.
    """
    if not version:
        return False
    slug = slug if slug is not None else _slug(name)
    entries = entries_by_slug.get(slug)
    if not entries:
        return False
    if allowed is _UNSET:
        allowed = allowed_vendor_slugs(purl, name)
    ranges = [
        r
        for vendor_values, entry_ranges in entries
        if vendor_names_component(allowed, vendor_values)
        for r in entry_ranges
    ]
    if not ranges:
        return False
    # Whole list at once, so the release-branch rule applies.
    if memo is None:
        return version_in_ranges(version, ranges)
    key = (version, tuple(ranges))
    hit = memo.get(key)
    if hit is None:
        hit = memo[key] = version_in_ranges(version, ranges)
    return hit
