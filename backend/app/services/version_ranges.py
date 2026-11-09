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

# Cap on the number of nested entries emitted per document. Some CVEs (the
# WordPress core advisories, for instance) enumerate 20+ release lines across
# several vendor spellings; a handful of pathological records would otherwise
# blow up the nested-document count. With consecutive pins folded and
# overlapping intervals merged, the largest of 1,271 .NET advisories needs 346.
MAX_VERSION_RANGES = 512


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
    out: list[dict[str, Any]] = []
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

        for start, end in _merge_intervals(intervals):
            if len(out) >= MAX_VERSION_RANGES:
                log.debug("version_ranges.cap_reached", vendor=vendor, product=product)
                return out
            out.append({"vendorSlug": vendor, "productSlug": product, "startKey": start, "endKey": end})

    return out
