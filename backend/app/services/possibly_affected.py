"""Possibly affected: name matches for advisories that name no affected versions.

Many CVEs now arrive without CPE or version data (NIST stopped enriching most
of them), and version-based matching then finds nothing, silently. For such a
vulnerability, and only for such one, this module lists the inventory items
and latest-scan SBOM components whose product or package name matches a
product the advisory names, so the detail page can say "possibly affected".

The rules that keep it honest:

- "No version evidence" is decided by ``collect_product_evidence``, the same
  function the inventory matcher and the range index use. As soon as any tier
  carries a version or a range, the version-confirmed blocks decide and this
  returns nothing.
- A language-registry package (npm, PyPI, …) only matches when the advisory's
  vendor fits it (``allowed_vendor_slugs``): npm ``console`` never matches
  Citrix NetScaler Console. Unlike the version-checked SBOM pass, a registry
  package needs a vendor here: a name alone is too little.
- The result is separate from ``affectedInventory`` / ``affectedScanTargets``
  and nothing else (dashboard counts, notifications) reads it.
"""
from __future__ import annotations

from typing import Any

import structlog
from pymongo.errors import PyMongoError

from app.services.inventory_matcher import (
    _coerce_cpe_configurations,
    _coerce_impacted_products,
    _coerce_slug_set,
    _coerce_string_list,
    _cpe_match_pair,
    _cpe_uri_pair,
    _get_attr,
    _iter_matches,
    _slug,
    collect_product_evidence,
    impacted_entry_pairs,
    is_marked_not_vulnerable,
    platform_cpe_filter,
)
from app.services.sbom_ecosystem import allowed_vendor_slugs, vendor_names_component

log = structlog.get_logger()

MAX_ROWS = 25
MAX_SBOM_CANDIDATES = 500
SBOM_QUERY_MAX_TIME_MS = 2000


def has_version_evidence(vuln: Any) -> bool:
    impacted = _coerce_impacted_products(_get_attr(vuln, "impacted_products", "impactedProducts"))
    configs = _coerce_cpe_configurations(_get_attr(vuln, "cpe_configurations", "cpeConfigurations"))
    cpes = _coerce_string_list(_get_attr(vuln, "cpes"))
    return bool(collect_product_evidence(impacted, configs, cpes))


def named_products(vuln: Any) -> tuple[dict[str, set[str]], set[str]]:
    """Product slug -> vendor slugs the advisory names it under, plus raw names.

    Pairs come from impactedProducts, vulnerable CPE matches and non-platform
    flat CPEs; the top-level ``products`` array adds products under every
    top-level vendor, since it carries no pairing. The raw names (as written,
    lower-cased, slugged) are what the SBOM ``name`` index is queried with.
    """
    impacted = _coerce_impacted_products(_get_attr(vuln, "impacted_products", "impactedProducts"))
    configs = _coerce_cpe_configurations(_get_attr(vuln, "cpe_configurations", "cpeConfigurations"))
    cpes = _coerce_string_list(_get_attr(vuln, "cpes"))
    products: dict[str, set[str]] = {}
    raw_names: set[str] = set()

    def add(vendor: str, product: str, *names: Any) -> None:
        if not product:
            return
        bucket = products.setdefault(product, set())
        if vendor:
            bucket.add(vendor)
        raw_names.add(product)
        for name in names:
            if isinstance(name, str) and name.strip():
                raw_names.add(name.strip())
                raw_names.add(name.strip().lower())

    for entry in impacted:
        if is_marked_not_vulnerable(entry):
            continue
        product_obj = entry.get("product") if isinstance(entry.get("product"), dict) else {}
        for vendor, product in impacted_entry_pairs(entry):
            add(vendor, product, product_obj.get("name"), product_obj.get("slug"))
    for config in configs:
        for match in _iter_matches(config.nodes):
            if is_marked_not_vulnerable(match):
                continue
            pair = _cpe_match_pair(match)
            if pair:
                add(pair[0], pair[1])
    platform_criteria, platform_pairs = platform_cpe_filter(impacted, configs)
    for cpe in cpes:
        if cpe in platform_criteria:
            continue
        pair = _cpe_uri_pair(cpe)
        if pair and pair not in platform_pairs:
            add(pair[0], pair[1])

    top_vendors = _coerce_slug_set(_get_attr(vuln, "vendor_slugs", "vendorSlugs")) | _coerce_slug_set(
        _get_attr(vuln, "vendors")
    )
    top_products = _get_attr(vuln, "product_slugs", "productSlugs") or []
    top_products = list(top_products) + list(_get_attr(vuln, "products") or [])
    for raw in top_products:
        if not isinstance(raw, str):
            continue
        product = _slug(raw)
        if not product:
            continue
        add("", product, raw)
        products[product] |= top_vendors
    return products, raw_names


def inventory_name_matches(
    products: dict[str, set[str]],
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Inventory items whose product slug the advisory names, under a vendor it names."""
    all_vendors = set().union(*products.values()) if products else set()
    out: list[dict[str, Any]] = []
    for item in inventory:
        if not isinstance(item, dict):
            continue
        product = _slug(item.get("product_slug"))
        vendor = _slug(item.get("vendor_slug"))
        if not product or product not in products:
            continue
        # Same tolerance as items_for_vuln: historical slugs drift
        # (graylog vs graylog2), so any vendor the advisory names counts.
        if all_vendors and vendor not in all_vendors:
            continue
        out.append({
            "kind": "inventory",
            "itemId": str(item.get("_id") or item.get("id") or ""),
            "name": item.get("name") or item.get("product_name") or product,
            "vendorSlug": item.get("vendor_slug"),
            "productSlug": item.get("product_slug"),
            "version": item.get("version"),
            "environment": item.get("environment"),
            "deployment": item.get("deployment"),
        })
        if len(out) >= MAX_ROWS:
            break
    return out


def sbom_component_fits(products: dict[str, set[str]], name: str, purl: str | None) -> bool:
    """Whether an SBOM component's name and ecosystem fit a product the advisory names."""
    slug = _slug(name)
    if not slug or slug not in products:
        return False
    allowed = allowed_vendor_slugs(purl, name)
    vendors = products[slug]
    if allowed is not None and not vendors:
        return False  # a registry package needs the advisory's vendor to fit it
    return vendor_names_component(allowed, vendors)


async def sbom_name_matches(scan_service: Any, products: dict[str, set[str]], raw_names: set[str]) -> list[dict[str, Any]]:
    """Latest-scan SBOM components named like a product the advisory names.

    Bounded: ``scan_id $in`` + ``name $in`` on the SBOM collection's indexes,
    a row limit and ``maxTimeMS``.
    """
    names = sorted(n for n in raw_names if n)[:200]
    if not names:
        return []
    scan_ids = await scan_service.scan_repo.get_latest_completed_scan_ids()
    if not scan_ids:
        return []
    try:
        cursor = (
            scan_service.sbom_repo.collection.find(
                {"scan_id": {"$in": scan_ids}, "name": {"$in": names}},
                {"scan_id": 1, "target_id": 1, "name": 1, "version": 1, "purl": 1},
            )
            .limit(MAX_SBOM_CANDIDATES)
            .max_time_ms(SBOM_QUERY_MAX_TIME_MS)
        )
        components = [doc async for doc in cursor]
    except PyMongoError as exc:
        log.warning("possibly_affected.sbom_query_failed", error=str(exc))
        return []

    target_names: dict[str, str] = {}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for comp in components:
        name = str(comp.get("name") or "")
        if not sbom_component_fits(products, name, comp.get("purl")):
            continue
        target_id = str(comp.get("target_id") or "")
        version = str(comp.get("version") or "")
        key = (target_id, name, version)
        if key in seen:
            continue
        seen.add(key)
        scan_id = str(comp.get("scan_id") or "")
        if scan_id not in target_names:
            scan = await scan_service.scan_repo.get(scan_id) if scan_id else None
            target_names[scan_id] = (scan or {}).get("target_name") or target_id
        out.append({
            "kind": "sbom",
            "scanId": scan_id,
            "targetId": target_id,
            "targetName": target_names[scan_id],
            "packageName": name,
            "packageVersion": version,
            "purl": comp.get("purl"),
        })
        if len(out) >= MAX_ROWS:
            break
    return out


async def possibly_affected_for_vuln(
    vuln: Any,
    *,
    inventory: list[dict[str, Any]],
    scan_service: Any | None,
) -> list[dict[str, Any]]:
    """Name-only matches for a vulnerability without any version evidence, else ``[]``."""
    if has_version_evidence(vuln):
        return []
    products, raw_names = named_products(vuln)
    if not products:
        return []
    rows = inventory_name_matches(products, inventory or [])
    if scan_service is not None:
        rows += await sbom_name_matches(scan_service, products, raw_names)
    return rows
