"""Version-range extraction for OpenSearch-side "affected version" search.

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

This module folds them into one flat, indexable list of half-open intervals::

    versionRanges: [
      {vendorSlug, productSlug, startKey, endKey},
      ...
    ]

``startKey`` is **inclusive**, ``endKey`` is **exclusive**, and both are
:func:`app.services.inventory_matcher.version_sort_key` keywords, whose byte
order is the matcher's version order. The question collapses into one nested
clause::

    startKey <= key(7.0.1) < endKey

Which ranges go in is decided by
:func:`app.services.inventory_matcher.collect_product_evidence`, the function
the inventory matcher uses too: the first tier with version evidence per
product, platforms (``vulnerable: false``) skipped, the release-branch rule
applied. Unconstrained ranges (``*``, ``-``, ``>=0``) and version-less wildcard
CPEs carry no evidence and are never indexed.

Indices built before the keys existed hold ``startNumeric`` / ``endNumeric``
(base-10000 longs, segments capped at 9999). The query falls back to those for
documents without keys until ``reindex-opensearch`` has rewritten them.
"""

from __future__ import annotations

from typing import Any, Iterable

import structlog

from app.services.ingestion.normalizer import _encode_version_numeric
from app.services.inventory_matcher import (
    KEY_AFTER,
    KEY_MAX,
    VersionSpan,
    _parse_range,
    coalesce_pins,
    collect_product_evidence,
    effective_spans,
    version_sort_key,
)

log = structlog.get_logger()

# Cap on the number of nested entries emitted per document, kept well below
# OpenSearch's ``index.mapping.nested_objects.limit`` (10,000 per document,
# shared with impactedProducts and the CPE configurations). Advisories that
# enumerate every affected release need far more than the old 512: Go modules
# with pseudo-versions (Argo Workflows GHSA-prqf-xr2j-xf65: 2,442 ranges after
# merging, from 3,550 listed versions), Traefik and NATS (~1,500), Magick.NET's
# 18 NuGet packages (~2,000). None of 66 such documents checked needs more than
# 4,096; past it, ``_fit_to_cap`` keeps every product's newest ranges.
MAX_VERSION_RANGES = 4096


def encode_version(value: str | None) -> int | None:
    """Legacy base-10000 encoding, only for documents indexed before the keys.

    Tolerates a leading ``v``. ``None`` when the value has no numeric release.
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate[0] in ("v", "V") and len(candidate) > 1 and candidate[1].isdigit():
        candidate = candidate[1:]
    return _encode_version_numeric(candidate)


def _encode_span(span: VersionSpan) -> tuple[str, str] | None:
    """``[startKey, endKey)`` for a span; ``None`` if a bound has no key.

    A bound without a key (a string the matcher can only compare by equality)
    drops the range rather than widening it. A span without any bound carries
    no version evidence and is not indexed.
    """
    if span.start is None and span.end is None:
        return None
    if span.start is None:
        start = ""
    else:
        key = version_sort_key(span.start)
        if key is None:
            return None
        start = key if span.start_inclusive else key + KEY_AFTER
    if span.end is None:
        end = KEY_MAX
    else:
        key = version_sort_key(span.end)
        if key is None:
            return None
        end = key + KEY_AFTER if span.end_inclusive else key
    if start >= end:
        return None
    return start, end


def _pin_interval(pin: str) -> tuple[str, str] | None:
    key = version_sort_key(pin)
    return (key, key + KEY_AFTER) if key is not None else None


def _merge_intervals(intervals: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Union of half-open intervals, sorted; ``[a, b)`` + ``[b, c)`` -> ``[a, c)``."""
    merged: list[tuple[str, str]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def range_bounds_from_string(range_str: str) -> tuple[str, str] | None:
    """Public helper: ``">= 7.0, < 7.0.2"`` -> ``(key(7.0), key(7.0.2))``.

    ``None`` for broad, unconstrained or unusable inputs. Evaluates one string
    in isolation, without tier selection or the release-branch rule.
    """
    exact, span = _parse_range(range_str)
    if exact:
        return _pin_interval(exact[0])
    return _encode_span(span) if span is not None else None


def build_version_ranges(
    *,
    impacted_products: Any = None,
    cpe_configurations: Iterable[Any] | None = None,
    cpes: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Flatten a vulnerability's version evidence into nested range docs.

    Returns ``{vendorSlug, productSlug, startKey, endKey}`` dicts with
    ``endKey`` **exclusive**, merged per product and capped at
    :data:`MAX_VERSION_RANGES`. Empty when the document carries no usable
    version information, which makes it unmatchable by an affected-version
    query rather than matching everything.
    """
    per_product: list[tuple[str, str, list[tuple[str, str]]]] = []
    evidence = collect_product_evidence(impacted_products, cpe_configurations, cpes)

    for (vendor, product), item in evidence.items():
        intervals: list[tuple[str, str]] = []
        for pins, spans in item.groups:
            # NetScaler spans are already branch-scoped by their own rule.
            if item.branch_segments is None and item.branch_rule:
                spans = effective_spans(spans)
            # Consecutive pins fold into one span, as in the matcher; the NuGet
            # runtime advisories list hundreds of them. Pins are added after
            # the branch rule so it never cuts one.
            singles, pin_spans = coalesce_pins(pins)
            for pin in singles:
                bounds = _pin_interval(pin)
                if bounds is not None:
                    intervals.append(bounds)
            for span in [*pin_spans, *spans]:
                bounds = _encode_span(span)
                if bounds is not None:
                    intervals.append(bounds)

        merged = _merge_intervals(intervals)
        if merged:
            per_product.append((vendor, product, merged))

    return [
        {"vendorSlug": vendor, "productSlug": product, "startKey": start, "endKey": end}
        for vendor, product, kept in _fit_to_cap(per_product)
        for start, end in kept
    ]


def _fit_to_cap(
    per_product: list[tuple[str, str, list[tuple[str, str]]]],
) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Trim to :data:`MAX_VERSION_RANGES`, keeping each product's newest ranges.

    The cap used to cut the output in order: the last products of a document
    vanished entirely, and a product's ranges were written oldest first, so the
    current releases were the ones dropped. Now every product gets a share in
    turn, newest range first, until the cap is reached. Queries are about the
    version someone runs, which is rarely the oldest one listed.
    """
    total = sum(len(ranges) for _, _, ranges in per_product)
    if total <= MAX_VERSION_RANGES:
        return per_product

    newest_first = [sorted(ranges, reverse=True) for _, _, ranges in per_product]
    taken = [0] * len(per_product)
    budget = MAX_VERSION_RANGES
    while budget > 0:
        progressed = False
        for index, ranges in enumerate(newest_first):
            if budget == 0:
                break
            if taken[index] < len(ranges):
                taken[index] += 1
                budget -= 1
                progressed = True
        if not progressed:
            break

    log.debug(
        "version_ranges.cap_reached",
        products=len(per_product),
        ranges=total,
        kept=MAX_VERSION_RANGES,
        dropped_from=[f"{v}/{p}" for (v, p, r), n in zip(per_product, taken) if n < len(r)][:5],
    )
    return [
        (vendor, product, sorted(newest_first[index][: taken[index]]))
        for index, (vendor, product, _) in enumerate(per_product)
        if taken[index]
    ]
