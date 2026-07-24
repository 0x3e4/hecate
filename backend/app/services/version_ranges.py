"""Numeric version-range extraction for OpenSearch-side "affected version" search.

Hecate stores the versions a CVE affects in three different shapes:

1. ``impactedProducts[].versions`` — curated EUVD-style *range strings*
   (``">= 7.0, < 7.0.2"``, ``"1.2.3"``, ``"<= 5.0.9"``).
2. ``cpeConfigurations[].nodes[].matches[]`` — structured NVD bounds
   (``versionStartIncluding`` / ``versionEndExcluding`` / …).
3. ``cpes[]`` — flat CPE 2.3 URIs whose 6th component may carry a concrete
   version.

None of those can answer *"which CVEs affect the version 7.0.1 that I run?"*
in OpenSearch: the range strings are opaque keywords, and the denormalised
``productVersions`` array only ever contains the range **boundaries**
(``6.9``, ``6.9.5``, ``7.0``, ``7.0.2``), never the versions in between. A
term query for ``7.0.1`` therefore misses every CVE that covers it.

This module folds all three shapes into one flat, indexable list of
half-open numeric intervals::

    versionRanges: [
      {vendorSlug, productSlug, startNumeric, endNumeric},
      ...
    ]

``startNumeric`` is **inclusive**, ``endNumeric`` is **exclusive**, so the
whole question collapses into a single OpenSearch nested clause::

    startNumeric <= encode(7.0.1) < endNumeric

Semantics deliberately mirror :mod:`app.services.inventory_matcher` — the
same clause parser is reused, and the same fail-closed rules apply:

* Broad / unconstrained ranges (``*``, ``-``, ``>=0``, empty) are **not
  indexed**. They carry no version information, and indexing them would make
  every version match.
* A bound that cannot be encoded numerically (pre-release suffixes such as
  ``2.0.0-beta``) drops the whole range rather than widening it.
* Version-less wildcard CPEs (``cpe:2.3:a:phpbb:phpbb:*``) are skipped —
  consistent with ``_match_cpe_entry`` / tier 3 of ``match_in_configuration``.

The encoding is the base-10000 fold already used for
``cpeConfigurations.*.versionStartNumeric`` (see
``app.services.ingestion.normalizer._encode_version_numeric``) so the two
representations stay directly comparable.
"""

from __future__ import annotations

from typing import Any, Iterable

import structlog

from app.services.ingestion.normalizer import _encode_version_numeric
from app.services.inventory_matcher import (
    _coerce_cpe_configurations,
    _coerce_impacted_products,
    _iter_matches,
    _parse_range_clauses,
    _slug,
)

log = structlog.get_logger()

# One past the largest value ``_encode_version_numeric`` can produce
# (9999.9999.9999.9999 -> 9_999_999_999_999_999). Used as the "no upper
# bound" sentinel so every indexed range is a closed integer interval and
# the query needs no ``exists`` gymnastics.
VERSION_NUMERIC_MAX = 10**16

# Cap on the number of nested entries emitted per document. Some CVEs (the
# WordPress core advisories, for instance) enumerate 20+ release lines across
# several vendor spellings; a handful of pathological records would otherwise
# blow up the nested-document count. 512 covers every real record observed
# while keeping the per-doc nested overhead bounded.
MAX_VERSION_RANGES = 512


def encode_version(value: str | None) -> int | None:
    """Encode ``value`` to the base-10000 integer used by the range index.

    Thin wrapper over the normalizer's encoder that additionally tolerates a
    leading ``v`` (``v1.2.3``). Returns ``None`` when the value carries no
    parsable numeric release, which callers must treat as "cannot be indexed
    / cannot be searched" rather than as an open bound.
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate[0] in ("v", "V") and len(candidate) > 1 and candidate[1].isdigit():
        candidate = candidate[1:]
    return _encode_version_numeric(candidate)


def _bounds_from_clauses(clauses: list[tuple[str, str]]) -> tuple[int, int] | None:
    """Fold ``(op, version)`` clauses into a half-open ``[start, end)`` pair.

    Returns ``None`` when the clause set is unconstrained (mirroring
    ``_version_in_range_string``'s ``>= 0`` guard) or when any bound fails to
    encode.
    """
    start_in: str | None = None
    start_ex: str | None = None
    end_in: str | None = None
    end_ex: str | None = None
    exact_values: list[str] = []

    for op, ver in clauses:
        if op in ("=", "=="):
            exact_values.append(ver)
        elif op == ">=":
            start_in = ver
        elif op == ">":
            start_ex = ver
        elif op == "<=":
            end_in = ver
        elif op == "<":
            end_ex = ver
        # "!=" is ignored — exclusions aren't modelled, same as the matcher.

    has_relational = any(v is not None for v in (start_in, start_ex, end_in, end_ex))

    # Plain "1.2.3" with no relational operator: an exact pin.
    if exact_values and not has_relational:
        encoded = encode_version(exact_values[0])
        if encoded is None:
            return None
        return encoded, encoded + 1

    if not has_relational:
        return None

    # "from zero upwards with no ceiling" is unconstrained — fail closed.
    if end_in is None and end_ex is None:
        lower = start_in if start_in is not None else start_ex
        lower_encoded = encode_version(lower)
        if lower_encoded is None:
            return None
        if lower_encoded == 0:
            return None

    return _half_open(
        start_in=start_in,
        start_ex=start_ex,
        end_in=end_in,
        end_ex=end_ex,
    )


def _half_open(
    *,
    start_in: str | None,
    start_ex: str | None,
    end_in: str | None,
    end_ex: str | None,
) -> tuple[int, int] | None:
    """Convert inclusive/exclusive bound strings into ``[start, end)`` integers.

    ``>= X`` -> ``start = enc(X)``; ``> X`` -> ``start = enc(X) + 1``.
    ``< X``  -> ``end = enc(X)``;   ``<= X`` -> ``end = enc(X) + 1``.

    A bound that is present but unencodable aborts the range (``None``) so we
    never silently widen it to the sentinel.
    """
    start = 0
    end = VERSION_NUMERIC_MAX

    if start_in is not None:
        encoded = encode_version(start_in)
        if encoded is None:
            return None
        start = max(start, encoded)
    if start_ex is not None:
        encoded = encode_version(start_ex)
        if encoded is None:
            return None
        start = max(start, encoded + 1)
    if end_in is not None:
        encoded = encode_version(end_in)
        if encoded is None:
            return None
        end = min(end, encoded + 1)
    if end_ex is not None:
        encoded = encode_version(end_ex)
        if encoded is None:
            return None
        end = min(end, encoded)

    if start >= end:
        return None
    return start, end


def range_bounds_from_string(range_str: str) -> tuple[int, int] | None:
    """Public helper: ``">= 7.0, < 7.0.2"`` -> ``(enc(7.0), enc(7.0.2))``.

    ``None`` for broad, unconstrained or unencodable inputs.
    """
    clauses = _parse_range_clauses(range_str)
    if not clauses:
        return None
    return _bounds_from_clauses(clauses)


def _slug_pairs_from_impacted_entry(entry: dict[str, Any]) -> list[tuple[str, str]]:
    """All (vendor, product) slug spellings an impacted-products entry answers to.

    Mirrors ``_impacted_product_matches_item``: both the curated ``slug`` and
    the slugified display ``name`` are accepted on each side, so the index
    matches whichever spelling the user filters by.
    """
    vendor_obj = entry.get("vendor")
    product_obj = entry.get("product")
    if not isinstance(vendor_obj, dict) or not isinstance(product_obj, dict):
        return []

    vendors = {_slug(vendor_obj.get("slug")), _slug(vendor_obj.get("name"))}
    products = {_slug(product_obj.get("slug")), _slug(product_obj.get("name"))}
    vendors.discard("")
    products.discard("")
    return [(v, p) for v in sorted(vendors) for p in sorted(products)]


def _version_from_cpe(criteria: str | None) -> str | None:
    """Concrete version out of a CPE 2.3 URI, or ``None`` for wildcards."""
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    version = parts[5].strip()
    if version in ("", "*", "-"):
        return None
    return version


def _cpe_slugs(criteria: str | None) -> tuple[str, str] | None:
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor = _slug(parts[3])
    product = _slug(parts[4])
    if not vendor or not product:
        return None
    return vendor, product


def build_version_ranges(
    *,
    impacted_products: Any = None,
    cpe_configurations: Iterable[Any] | None = None,
    cpes: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Flatten every version-range signal on a vulnerability into nested docs.

    Returns a list of ``{vendorSlug, productSlug, startNumeric, endNumeric}``
    dicts with ``endNumeric`` **exclusive**, deduplicated and capped at
    :data:`MAX_VERSION_RANGES`. Empty list when the document carries no usable
    version information (which correctly makes it unmatchable by an
    affected-version query rather than matching everything).
    """
    seen: set[tuple[str, str, int, int]] = set()
    out: list[dict[str, Any]] = []

    def add(vendor: str, product: str, bounds: tuple[int, int] | None) -> bool:
        """Append one interval. Returns False once the per-doc cap is hit."""
        if bounds is None or not vendor or not product:
            return True
        key = (vendor, product, bounds[0], bounds[1])
        if key in seen:
            return True
        if len(out) >= MAX_VERSION_RANGES:
            return False
        seen.add(key)
        out.append(
            {
                "vendorSlug": vendor,
                "productSlug": product,
                "startNumeric": bounds[0],
                "endNumeric": bounds[1],
            }
        )
        return True

    # --- Tier 1: curated impactedProducts range strings ---
    for entry in _coerce_impacted_products(impacted_products):
        pairs = _slug_pairs_from_impacted_entry(entry)
        if not pairs:
            continue
        versions = entry.get("versions")
        if not isinstance(versions, list):
            continue
        for raw_range in versions:
            if not isinstance(raw_range, str):
                continue
            try:
                bounds = range_bounds_from_string(raw_range)
            except Exception as exc:  # pragma: no cover - defensive
                log.debug(
                    "version_ranges.range_string_error",
                    range_str=raw_range,
                    error=str(exc),
                )
                continue
            for vendor, product in pairs:
                if not add(vendor, product, bounds):
                    return out

    # --- Tier 2: structured NVD cpeConfigurations bounds ---
    for config in _coerce_cpe_configurations(cpe_configurations):
        for match in _iter_matches(config.nodes):
            vendor = _slug(getattr(match, "vendor", None))
            product = _slug(getattr(match, "product", None))
            if not vendor or not product:
                fallback = _cpe_slugs(getattr(match, "criteria", None))
                if fallback is None:
                    continue
                vendor, product = fallback

            bounds = _half_open(
                start_in=getattr(match, "version_start_including", None),
                start_ex=getattr(match, "version_start_excluding", None),
                end_in=getattr(match, "version_end_including", None),
                end_ex=getattr(match, "version_end_excluding", None),
            )
            if bounds is None:
                # No usable range bounds — fall back to a concrete version in
                # the CPE criteria. A bare wildcard yields nothing (fail-closed).
                concrete = getattr(match, "version", None) or _version_from_cpe(
                    getattr(match, "criteria", None)
                )
                encoded = encode_version(concrete)
                bounds = (encoded, encoded + 1) if encoded is not None else None
            if not add(vendor, product, bounds):
                return out

    # --- Tier 3: flat CPE URIs with a concrete version ---
    for cpe in cpes or []:
        slugs = _cpe_slugs(cpe)
        if slugs is None:
            continue
        encoded = encode_version(_version_from_cpe(cpe))
        if encoded is None:
            continue
        if not add(slugs[0], slugs[1], (encoded, encoded + 1)):
            return out

    return out
