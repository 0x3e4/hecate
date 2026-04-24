"""Enrich malicious-package vulnerability documents with published versions.

OSSF's `malicious-packages` feed — which OSV re-exports under `MAL-*` IDs —
publishes every record with a conservative `{"introduced": "0"}` range for
each affected package, meaning "the whole namespace is hostile because the
attacker owns it". The same pattern occasionally shows up on GHSA-* entries
for malicious packages. In the UI this surfaces as an unhelpful "all
versions" chip and hides the actual count (usually 1–5 for typosquat
malware). deps.dev's Package endpoint gives us the authoritative list of
published versions per ecosystem so we can replace the blanket range.

We enrich at four points:

1. **OSV ingestion** — for every MAL-* record we touch (new or updated), the
   OSV pipeline's post-upsert hook calls `maybe_enrich_by_id()`.
2. **Manual refresh** — `/api/v1/vulnerabilities/refresh` for MAL-*/GHSA-*
   IDs runs the same helper on the freshly-persisted doc, regardless of the
   upstream `inserted/updated/unchanged` verdict. Even if OSV had nothing
   new, we still patch local docs whose ranges are stale-broad.
3. **Backfill** — `poetry run python -m app.cli enrich-mal [--limit N]`
   walks MAL-* docs (JobTracker-wrapped for audit-log visibility).
4. Enrichment writes a `change_history` entry (`job_name="deps_dev_enrichment"`)
   and updates `last_change_job` / `last_change_at` so the changelog and the
   vulnerability-detail Change History tab surface the update.

`enrich_document()` is idempotent: if a doc already carries specific version
strings, we skip; if deps.dev returns no versions or fails, we leave the
doc untouched and don't write a change entry.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.db.mongo import get_database
from app.services.ingestion.deps_dev_client import DepsDevClient, osv_to_deps_dev_system

log = structlog.get_logger()


# Prefixes on which we consider enrichment. Kept open so the manual-refresh
# endpoint can call the same helper for GHSA-* records that ship with broad
# ranges (rare, but the helper is a no-op when ranges are already specific).
_ENRICHABLE_PREFIXES: tuple[str, ...] = ("MAL-", "GHSA-")


def _is_broad_range(versions: list[Any] | None) -> bool:
    """True when a versions list is either empty or holds only the OSSF-style
    sentinel strings that signal "all versions"."""
    if not versions:
        return True
    for v in versions:
        if not isinstance(v, str):
            return False
        s = v.strip()
        if not s:
            continue
        # OSV range strings from `introduced: "0"` come through our normalizer
        # as ">=0". Anything else means upstream had specifics.
        if s in {">=0", ">= 0", "*", "-", "ANY"}:
            continue
        return False
    return True


def _patch_impacted_products(
    impacted: list[dict[str, Any]],
    enriched_versions_by_product: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], int]:
    """Return (new_impacted_products, num_patched). Only broad entries with a
    matching deps.dev lookup get replaced; everything else is preserved
    in-place so the `$set` overwrite is safe for repeated calls."""
    patched = 0
    out: list[dict[str, Any]] = []
    for entry in impacted:
        if not isinstance(entry, dict):
            out.append(entry)
            continue
        product = entry.get("product") or {}
        name = (product.get("name") or "").strip()
        if not name:
            out.append(entry)
            continue
        if not _is_broad_range(entry.get("versions")):
            out.append(entry)
            continue
        new_versions = enriched_versions_by_product.get(name.lower())
        if not new_versions:
            out.append(entry)
            continue
        new_entry = dict(entry)
        new_entry["versions"] = list(new_versions)
        out.append(new_entry)
        patched += 1
    return out, patched


def _build_enrichment_change_entry(
    old_impacted: list[Any],
    new_impacted: list[Any],
) -> dict[str, Any]:
    """Minimal change-history entry attributed to the deps.dev enrichment.

    Unlike ingestion writers we don't snapshot the full document — the change
    is narrow (one field) and the snapshot field is optional on the UI side.
    `job_name` lets the changelog filter and the audit-log dropdown pick
    these up via the existing 'last_change_job' indexed path.
    """
    return {
        "changed_at": datetime.now(tz=UTC),
        "job_name": "deps_dev_enrichment",
        "job_label": "deps.dev Enrichment",
        "change_type": "update",
        "fields": [
            {
                "name": "impactedProducts",
                "previous": copy.deepcopy(old_impacted),
                "current": copy.deepcopy(new_impacted),
            }
        ],
        "snapshot": {},
        "metadata": {"trigger": "deps_dev", "provider": "deps.dev"},
    }


async def enrich_document(
    doc: dict[str, Any],
    *,
    client: DepsDevClient | None = None,
) -> int:
    """Enrich one stored vulnerability doc in place.

    Returns the number of `impactedProducts` entries whose version list got
    replaced. Zero means nothing changed (already specific, unknown
    ecosystem, or deps.dev didn't know the package) — and nothing is
    persisted in that case. Caller owns `client` lifecycle when provided;
    otherwise a short-lived client is spawned.
    """
    vuln_id = doc.get("_id") or doc.get("vuln_id") or ""
    if not isinstance(vuln_id, str):
        return 0
    if not vuln_id.upper().startswith(_ENRICHABLE_PREFIXES):
        return 0

    impacted_raw = doc.get("impactedProducts") or doc.get("impacted_products") or []
    if not isinstance(impacted_raw, list) or not impacted_raw:
        return 0

    # Collect (system, name) pairs that need enrichment.
    targets: list[tuple[str, str, str]] = []  # (system, name, product_lower_key)
    for entry in impacted_raw:
        if not isinstance(entry, dict):
            continue
        if not _is_broad_range(entry.get("versions")):
            continue
        vendor = entry.get("vendor") or {}
        product = entry.get("product") or {}
        eco = (vendor.get("name") or "").strip()
        name = (product.get("name") or "").strip()
        if not eco or not name:
            continue
        mapped = osv_to_deps_dev_system(eco)
        if not mapped:
            continue
        targets.append((mapped, name, name.lower()))

    if not targets:
        return 0

    own_client = client is None
    cli = client or DepsDevClient()
    enriched: dict[str, list[str]] = {}
    try:
        for system, name, key in targets:
            if key in enriched:
                continue
            versions = await cli.fetch_package_versions(system=system, name=name)
            if versions:
                enriched[key] = versions
    finally:
        if own_client:
            await cli.close()

    if not enriched:
        return 0

    new_impacted, patched = _patch_impacted_products(impacted_raw, enriched)
    if patched == 0:
        return 0

    # Rebuild the denormalized flat `product_versions` array from the patched
    # impactedProducts. Without this the VulnerabilityDetail "Versions" line
    # (driven by the flat field) keeps showing `>=0` even though the structured
    # list is specific. Dedupe preserving first-seen order, skipping OSSF-range
    # sentinels that linger on non-broad entries we left alone.
    new_product_versions: list[str] = []
    seen_versions: set[str] = set()
    for entry in new_impacted:
        if not isinstance(entry, dict):
            continue
        for v in entry.get("versions") or []:
            if not isinstance(v, str):
                continue
            s = v.strip()
            if not s or s in {">=0", ">= 0", "*", "-", "ANY"}:
                continue
            if s in seen_versions:
                continue
            seen_versions.add(s)
            new_product_versions.append(s)

    change_entry = _build_enrichment_change_entry(impacted_raw, new_impacted)
    database = await get_database()
    collection = database[settings.mongo_vulnerabilities_collection]
    update_set: dict[str, Any] = {
        "impactedProducts": new_impacted,
        # Denormalized last_change_* fields power the changelog's
        # indexed queries — mirror the invariant that ingestion
        # writers maintain in _stamp_last_change_job().
        "last_change_job": change_entry["job_name"],
        "last_change_at": change_entry["changed_at"],
    }
    if new_product_versions:
        update_set["product_versions"] = new_product_versions
    await collection.update_one(
        {"_id": vuln_id},
        {
            "$set": update_set,
            "$unset": {"impacted_products": ""},
            "$push": {"change_history": change_entry},
        },
    )

    # Reindex into OpenSearch. The vulnerability-detail endpoint reads from
    # OpenSearch (not Mongo), so without this the UI keeps showing the stale
    # pre-enrichment `>=0` range even after we patch Mongo. Mirrors the
    # reindex pattern at the end of every ingestion-writer in
    # VulnerabilityRepository (e.g. upsert_from_osv). Best-effort: if
    # validation/index fails the Mongo write is still authoritative and the
    # next full re-sync will align OpenSearch.
    try:
        from app.db.opensearch import async_index_document
        from app.models.vulnerability import VulnerabilityDocument

        fresh = await collection.find_one({"_id": vuln_id})
        if isinstance(fresh, dict):
            sanitized = {k: v for k, v in fresh.items() if k not in {"_id", "change_history"}}
            try:
                model = VulnerabilityDocument.model_validate(sanitized)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "mal_enrichment.reindex_validation_failed",
                    vuln_id=vuln_id,
                    error=str(exc),
                )
            else:
                os_doc = model.opensearch_document()
                # `last_change_job` / `last_change_at` are denormalized fields
                # that live on the Mongo doc but aren't declared on
                # VulnerabilityDocument, so model_dump drops them. Re-inject
                # them manually so the changelog's indexed job filter finds
                # this record after enrichment.
                for key in ("last_change_job", "last_change_at"):
                    if key in fresh:
                        os_doc[key] = fresh[key]
                await async_index_document(
                    index=settings.opensearch_index,
                    document_id=vuln_id,
                    document=os_doc,
                )
    except Exception as exc:  # noqa: BLE001
        log.warning("mal_enrichment.reindex_failed", vuln_id=vuln_id, error=str(exc))

    log.info(
        "mal_enrichment.patched",
        vuln_id=vuln_id,
        patched=patched,
        lookups=len(enriched),
    )
    return patched


# Keep the legacy name so existing imports keep working.
enrich_mal_document = enrich_document


async def maybe_enrich_by_id(
    vuln_id: str,
    *,
    client: DepsDevClient | None = None,
) -> int:
    """Look up a single vulnerability by ID and enrich it. Used by the OSV
    pipeline's post-upsert hook, the manual-refresh endpoint, and the CLI
    backfill. Silently no-ops for IDs outside the enrichable prefix set."""
    if not vuln_id.upper().startswith(_ENRICHABLE_PREFIXES):
        return 0
    database = await get_database()
    collection = database[settings.mongo_vulnerabilities_collection]
    doc = await collection.find_one({"_id": vuln_id})
    if not doc:
        return 0
    return await enrich_document(doc, client=client)
