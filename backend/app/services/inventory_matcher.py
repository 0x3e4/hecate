from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

import structlog

from app.models.vulnerability import CpeConfiguration, CpeMatch, CpeNode
from app.utils.strings import slugify

log = structlog.get_logger()


# --- Version comparison ---
#
# Hecate stores versions as free-form strings; CVE CPE configurations use the
# same format. We don't depend on ``packaging.version`` because it isn't a
# pinned backend dependency, so we ship a small self-contained comparator that
# handles the common cases seen in CPE data:
#
# - Dotted numeric strings (``1.2.3``, ``8.0.25``)
# - Pre-release suffixes separated by ``-`` or ``_`` (``8.0.25-preview.1``)
#   Pre-releases compare *less than* the same base version without a suffix.
# - Wildcards at the end (``8.0.*``) which expand to a half-open range.
#
# For version tokens that don't parse cleanly we fall back to case-folded
# lexicographic compare. That's not perfect for every ecosystem but it never
# raises, and the matcher is intentionally fail-closed (a version we can't
# compare is treated as *not* matching, see ``_compare_versions``).

_SEGMENT_SPLIT_RE = re.compile(r"[._-]")
_NUMERIC_RE = re.compile(r"^\d+$")


@dataclass(frozen=True)
class ParsedVersion:
    """A comparable representation of a version string.

    ``release`` holds the numeric components (``8.0.25`` → ``(8, 0, 25)``).
    ``pre`` is ``()`` for final releases and a tuple for pre-releases that
    sorts *before* the empty tuple by convention (see ``_tuple_for_compare``).
    ``raw`` is the original string for lexicographic fallback.
    ``valid`` is True when the leading segment parsed as a number.
    """

    release: tuple[int, ...]
    pre: tuple[Any, ...]
    raw: str
    valid: bool


def parse_version(raw: str) -> ParsedVersion:
    """Parse a version string into a ``ParsedVersion``.

    Never raises — returns a ``ParsedVersion`` with ``valid=False`` if the
    string doesn't start with a numeric segment.
    """
    if raw is None:
        return ParsedVersion(release=(), pre=(), raw="", valid=False)
    text = str(raw).strip()
    if not text:
        return ParsedVersion(release=(), pre=(), raw="", valid=False)

    # Strip leading "v" / "V" prefix commonly seen in tags.
    if text[0] in ("v", "V"):
        text = text[1:]

    # Split release and pre-release at the first dash (after any version suffix
    # separators). ``8.0.25-preview.1`` → release ``8.0.25``, pre ``preview.1``.
    release_part, _, pre_part = text.partition("-")

    release_tokens = _SEGMENT_SPLIT_RE.split(release_part)
    release_ints: list[int] = []
    valid = True
    for token in release_tokens:
        if not token:
            continue
        if _NUMERIC_RE.match(token):
            release_ints.append(int(token))
        else:
            # First non-numeric token marks the end of the comparable release.
            # If *nothing* parsed numerically, the whole version is invalid.
            if not release_ints:
                valid = False
            break

    pre_tokens: tuple[Any, ...] = ()
    if pre_part:
        segs: list[Any] = []
        for token in _SEGMENT_SPLIT_RE.split(pre_part):
            if not token:
                continue
            if _NUMERIC_RE.match(token):
                segs.append((1, int(token)))
            else:
                segs.append((0, token.lower()))
        pre_tokens = tuple(segs)

    return ParsedVersion(
        release=tuple(release_ints),
        pre=pre_tokens,
        raw=text,
        valid=valid,
    )


def _tuple_for_compare(v: ParsedVersion) -> tuple[Any, ...]:
    """Return a tuple where release < pre-release of same release.

    The second element is ``0`` for pre-releases and ``1`` for final releases,
    so ``8.0.25-preview.1 < 8.0.25``. When comparing releases of different
    length we right-pad the shorter with zeros so ``8.0`` == ``8.0.0``.
    """
    return (v.release, 0 if v.pre else 1, v.pre)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    length = max(len(a), len(b))
    return (a + (0,) * (length - len(a)), b + (0,) * (length - len(b)))


def _compare_versions(left: str, right: str) -> int | None:
    """Return -1/0/1 if ``left`` can be compared against ``right``, else ``None``.

    ``None`` means the comparison is undecidable — callers should treat the
    match as failed rather than guessing.
    """
    lv = parse_version(left)
    rv = parse_version(right)
    if not lv.valid or not rv.valid:
        # Fall back to case-insensitive string equality only. Ordering on
        # arbitrary strings is meaningless for version ranges and would cause
        # false positives.
        if lv.raw.lower() == rv.raw.lower():
            return 0
        return None
    la, ra = _pad(lv.release, rv.release)
    if la != ra:
        return -1 if la < ra else 1
    lt = _tuple_for_compare(ParsedVersion(la, lv.pre, lv.raw, lv.valid))
    rt = _tuple_for_compare(ParsedVersion(ra, rv.pre, rv.raw, rv.valid))
    if lt == rt:
        return 0
    return -1 if lt < rt else 1


# --- CPE match evaluation ---


@dataclass(frozen=True)
class InventoryKey:
    """The lookup key for an inventory item against CVE data."""

    vendor_slug: str
    product_slug: str
    version: str


def _slug(value: Any) -> str:
    """Normalize a slug the same way the asset catalog does.

    The asset catalog normalizer (``app.utils.strings.slugify``) collapses
    non-alphanumerics to ``-`` and lowercases. Using the same helper here
    ensures CPE-sourced tokens like ``.net_8.0`` and inventory slugs like
    ``net-8-0`` compare equal.
    """
    if not isinstance(value, str):
        return ""
    trimmed = value.strip()
    if not trimmed:
        return ""
    return slugify(trimmed)


def _extract_version_from_cpe(criteria: str | None) -> str | None:
    """Extract the version field (6th component) from a CPE 2.3 URI."""
    if not criteria or not isinstance(criteria, str):
        return None
    if not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    version = parts[5]
    if version in ("", "*", "-", "ANY", "NA"):
        return None
    return version


def _expand_wildcard(version: str) -> tuple[str, str] | None:
    """Expand ``8.0.*`` into a half-open range ``[8.0, 8.1)``.

    Returns ``None`` for non-wildcard inputs.
    """
    if not version.endswith(".*"):
        return None
    prefix = version[:-2]
    tokens = prefix.split(".")
    if not tokens or not tokens[-1].isdigit():
        return None
    lower = ".".join(tokens)
    upper_tokens = tokens[:-1] + [str(int(tokens[-1]) + 1)]
    upper = ".".join(upper_tokens)
    return lower, upper


def _match_cpe_entry(item_version: str, match: CpeMatch) -> bool:
    """Return True if ``item_version`` falls within the CPE match criteria."""
    # Exact version on the CPE URI — must equal the item version (or fall
    # inside a wildcard range if the item uses one).
    exact = _extract_version_from_cpe(match.criteria)
    if exact is not None and not any(
        (match.version_start_including, match.version_start_excluding,
         match.version_end_including, match.version_end_excluding)
    ):
        return _versions_equivalent(item_version, exact)

    # Range-based match: evaluate each bound.
    start_in = match.version_start_including
    start_ex = match.version_start_excluding
    end_in = match.version_end_including
    end_ex = match.version_end_excluding

    if not any((start_in, start_ex, end_in, end_ex)):
        # No range and no exact version — treat as "any version of this
        # product", which is the NVD semantic when only vendor+product match.
        # Still return True because the caller has already verified the
        # vendor/product slugs.
        return True

    cmp_result = _compare_bounds(
        item_version,
        start_in=start_in,
        start_ex=start_ex,
        end_in=end_in,
        end_ex=end_ex,
    )
    return cmp_result


def _versions_equivalent(item_version: str, cpe_version: str) -> bool:
    cmp = _compare_versions(item_version, cpe_version)
    if cmp is not None:
        return cmp == 0
    # Handle wildcard in the item version against an exact CPE version.
    wc = _expand_wildcard(item_version)
    if wc is not None:
        lower, upper = wc
        return _compare_bounds(cpe_version, start_in=lower, start_ex=None, end_in=None, end_ex=upper)
    return False


def _compare_bounds(
    version: str,
    *,
    start_in: str | None,
    start_ex: str | None,
    end_in: str | None,
    end_ex: str | None,
) -> bool:
    """Return True if ``version`` falls within the supplied half-open bounds."""

    def _cmp_or_fail(a: str, b: str) -> int | None:
        return _compare_versions(a, b)

    # Expand a wildcard item version by comparing both edges of the implied
    # range against the CPE bounds. If *any* concrete version inside the item
    # range satisfies the CPE bounds we consider it a match.
    wc = _expand_wildcard(version)
    if wc is not None:
        lower, upper = wc
        # A wildcard range [lower, upper) intersects [start, end] iff
        #   lower < end(+ε)  and  upper > start(−ε)
        #
        # We approximate "(−/+ ε)" by treating the inclusive bounds as
        # equivalence and the exclusive bounds as strict.
        if end_in is not None:
            cmp_val = _cmp_or_fail(lower, end_in)
            if cmp_val is None or cmp_val > 0:
                return False
        if end_ex is not None:
            cmp_val = _cmp_or_fail(lower, end_ex)
            if cmp_val is None or cmp_val >= 0:
                return False
        if start_in is not None:
            cmp_val = _cmp_or_fail(upper, start_in)
            if cmp_val is None or cmp_val <= 0:
                return False
        if start_ex is not None:
            cmp_val = _cmp_or_fail(upper, start_ex)
            if cmp_val is None or cmp_val <= 0:
                return False
        return True

    # Concrete version — evaluate each bound directly.
    if start_in is not None:
        cmp_val = _cmp_or_fail(version, start_in)
        if cmp_val is None or cmp_val < 0:
            return False
    if start_ex is not None:
        cmp_val = _cmp_or_fail(version, start_ex)
        if cmp_val is None or cmp_val <= 0:
            return False
    if end_in is not None:
        cmp_val = _cmp_or_fail(version, end_in)
        if cmp_val is None or cmp_val > 0:
            return False
    if end_ex is not None:
        cmp_val = _cmp_or_fail(version, end_ex)
        if cmp_val is None or cmp_val >= 0:
            return False
    return True


# --- Version-range-string parser (for `impacted_products[].versions`) ---
#
# EUVD-style range strings look like:
#   - "1.2.3"              (exact)
#   - ">= 1.0.0, < 5.0.9"  (half-open range, AND semantics)
#   - "< 5.0.9"            (only upper bound)
#   - ">= 5.1.0, < 5.1.3"  (half-open range)
#   - "*" / "" / "-"       (unconstrained — we ignore these)
#
# A single ``versions: [...]`` list is evaluated with OR semantics: if *any*
# range string in the list matches the user's version, the item is vulnerable.

_VERSION_OP_RE = re.compile(
    r"(?P<op>>=|<=|!=|==|>|<|=)?\s*(?P<ver>[A-Za-z0-9][\w.+:\-*]*)"
)


def _version_in_range_string(version: str, range_str: str) -> bool:
    """Return True if ``version`` satisfies ``range_str``.

    Unknown or unconstrained strings (``*``, ``-``, empty) return False —
    they provide no usable information and we fail closed rather than match
    everything.
    """
    s = (range_str or "").strip()
    if not s or s in ("*", "-", "ANY", "any"):
        return False

    clauses: list[tuple[str, str]] = []
    for part in (p.strip() for p in s.split(",")):
        if not part:
            continue
        match = _VERSION_OP_RE.match(part)
        if not match:
            continue
        op = match.group("op") or "="
        ver = match.group("ver")
        clauses.append((op, ver))

    if not clauses:
        return False

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
        # != is ignored — we don't model exclusions

    # Exact equality takes precedence when present (a plain "1.2.3" with no
    # relational operators).
    if exact_values and not any((start_in, start_ex, end_in, end_ex)):
        for v in exact_values:
            cmp_val = _compare_versions(version, v)
            if cmp_val == 0:
                return True
        return False

    return _compare_bounds(
        version,
        start_in=start_in,
        start_ex=start_ex,
        end_in=end_in,
        end_ex=end_ex,
    )


def _coerce_impacted_products(value: Any) -> list[dict[str, Any]]:
    """Normalize ``impacted_products`` / ``impactedProducts`` entries to dicts.

    Accepts three shapes:

    - raw dicts (what MongoDB returns for pipelines that inject API JSON)
    - Pydantic models (``ImpactedProduct`` instances from
      ``VulnerabilityDetail``, loaded via
      ``VulnerabilityService.get_by_id``)
    - mixed lists

    Pydantic entries are dumped via ``model_dump(by_alias=False)`` so the
    resulting dicts always use snake_case keys (``versions``, ``vendor``,
    ``product``), which ``_impacted_product_matches_item`` expects.
    """
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, dict):
            result.append(entry)
            continue
        dump = getattr(entry, "model_dump", None)
        if callable(dump):
            try:
                result.append(dump(by_alias=False))
                continue
            except Exception:  # pragma: no cover - defensive
                pass
    return result


def _impacted_product_matches_item(
    entry: dict[str, Any],
    item: "InventoryKey",
) -> bool:
    """Return True if the impacted_product entry's vendor/product matches the item."""
    vendor_obj = entry.get("vendor")
    product_obj = entry.get("product")
    if not isinstance(vendor_obj, dict) or not isinstance(product_obj, dict):
        return False

    vendor_candidates = {
        _slug(vendor_obj.get("slug")),
        _slug(vendor_obj.get("name")),
    }
    vendor_candidates.discard("")
    if item.vendor_slug not in vendor_candidates:
        return False

    product_candidates = {
        _slug(product_obj.get("slug")),
        _slug(product_obj.get("name")),
    }
    product_candidates.discard("")
    return item.product_slug in product_candidates


def _iter_matches(nodes: Iterable[CpeNode]) -> Iterable[CpeMatch]:
    for node in nodes or []:
        if node is None:
            continue
        for match in node.matches or []:
            if match is not None:
                yield match
        if node.nodes:
            yield from _iter_matches(node.nodes)


def match_in_configuration(
    item: InventoryKey,
    cpe_configurations: list[CpeConfiguration],
    flat_cpes: list[str] | None = None,
    *,
    impacted_products: list[dict[str, Any]] | None = None,
) -> bool:
    """Return True if any data source confirms the item is affected.

    Priority order (fail-closed when an authoritative source says "no"):

    1. ``impacted_products`` — curated vendor/product/version range strings
       from EUVD. When an entry matches the item's vendor+product slug, its
       ``versions`` list is evaluated; if none match we stop and return
       False without consulting the CPE data (the entry is authoritative).

    2. ``cpe_configurations`` — structured NVD range data. Same semantic:
       if a match entry for the item's vendor+product exists but none of
       its range bounds satisfy the version, we return False.

    3. ``flat_cpes`` — plain CPE 2.3 URIs, evaluated **only** as a
       last-resort fallback when neither of the above yielded any
       vendor/product-matching entries. Wildcards (``*`` / ``-``) in the
       version component are **ignored** rather than matched: an unbounded
       wildcard CPE tells us nothing about a specific version.
    """
    item_vendor = _slug(item.vendor_slug)
    item_product = _slug(item.product_slug)
    item_version = item.version.strip()
    if not item_vendor or not item_product or not item_version:
        return False

    normalized_item = InventoryKey(
        vendor_slug=item_vendor,
        product_slug=item_product,
        version=item_version,
    )

    # --- Tier 1: impacted_products (curated EUVD / enrichment data) ---
    saw_product_in_impacted = False
    for entry in impacted_products or []:
        if not _impacted_product_matches_item(entry, normalized_item):
            continue
        saw_product_in_impacted = True
        versions = entry.get("versions") or []
        if not isinstance(versions, list):
            continue
        for raw_range in versions:
            if not isinstance(raw_range, str):
                continue
            try:
                if _version_in_range_string(item_version, raw_range):
                    return True
            except Exception as exc:  # pragma: no cover - defensive
                log.debug(
                    "inventory_matcher.range_string_error",
                    range_str=raw_range,
                    version=item_version,
                    error=str(exc),
                )
    if saw_product_in_impacted:
        # The curated source listed this exact vendor/product but no version
        # range matched. Trust it.
        return False

    # --- Tier 2: cpe_configurations (structured NVD range data) ---
    saw_product_in_cpe = False
    for config in cpe_configurations or []:
        for match in _iter_matches(config.nodes):
            mv = _slug(match.vendor)
            mp = _slug(match.product)
            if mv != item_vendor or mp != item_product:
                continue
            saw_product_in_cpe = True
            try:
                if _match_cpe_entry(item_version, match):
                    return True
            except Exception as exc:  # pragma: no cover - defensive
                log.debug(
                    "inventory_matcher.match_error",
                    vendor=item_vendor,
                    product=item_product,
                    version=item_version,
                    error=str(exc),
                )
    if saw_product_in_cpe:
        # Structured source evaluated this product's ranges — none matched.
        return False

    # --- Tier 3: flat CPEs (last-resort fallback) ---
    # Only honored when no other source has any entry for this vendor/product.
    # Wildcard versions are ignored: they can't confirm a specific version.
    if flat_cpes:
        for cpe in flat_cpes:
            if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
                continue
            parts = cpe.split(":")
            if len(parts) < 6:
                continue
            vendor = _slug(parts[3])
            product = _slug(parts[4])
            if vendor != item_vendor or product != item_product:
                continue
            cpe_version = parts[5]
            if cpe_version in ("", "*", "-"):
                # Unbounded wildcard gives no version information — skip.
                continue
            if _versions_equivalent(item_version, cpe_version):
                return True

    return False


# --- High-level query helpers ---


def items_for_vuln(
    vuln: Any,
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return the subset of ``inventory`` items affected by ``vuln``.

    ``vuln`` may be a ``VulnerabilityDocument``, a ``VulnerabilityDetail``, or
    a raw ``dict`` from MongoDB/OpenSearch. The pre-filter union-set combines
    the denormalized slug arrays, the raw display-name arrays, and every
    vendor/product slug referenced by ``impacted_products`` — any of these
    may be the only place a given product identifier shows up. The full
    matcher then validates each surviving candidate against all three data
    sources (impacted_products → cpe_configurations → flat cpes).
    """
    impacted_products = _coerce_impacted_products(
        _get_attr(vuln, "impacted_products", "impactedProducts")
    )
    cpe_configurations = _coerce_cpe_configurations(
        _get_attr(vuln, "cpe_configurations", "cpeConfigurations")
    )
    flat_cpes = _coerce_string_list(_get_attr(vuln, "cpes"))

    vendor_slug_set = _coerce_slug_set(_get_attr(vuln, "vendor_slugs", "vendorSlugs"))
    product_slug_set = _coerce_slug_set(_get_attr(vuln, "product_slugs", "productSlugs"))
    vendor_slug_set |= _coerce_slug_set(_get_attr(vuln, "vendors"))
    product_slug_set |= _coerce_slug_set(_get_attr(vuln, "products"))
    # Also pull vendor/product identifiers out of impacted_products entries —
    # the Microsoft/.NET CVE stores everything there and nothing in the
    # top-level slug arrays.
    for entry in impacted_products:
        vendor_obj = entry.get("vendor") or {}
        product_obj = entry.get("product") or {}
        for k in ("slug", "name"):
            v = _slug(vendor_obj.get(k))
            if v:
                vendor_slug_set.add(v)
            p = _slug(product_obj.get(k))
            if p:
                product_slug_set.add(p)

    if not cpe_configurations and not flat_cpes and not vendor_slug_set and not impacted_products:
        return []

    results: list[dict[str, Any]] = []
    for raw in inventory:
        if not isinstance(raw, dict):
            continue
        vendor = _slug(raw.get("vendor_slug"))
        product = _slug(raw.get("product_slug"))
        if not vendor or not product:
            continue
        if vendor_slug_set and vendor not in vendor_slug_set:
            continue
        if product_slug_set and product not in product_slug_set:
            continue
        key = InventoryKey(
            vendor_slug=vendor,
            product_slug=product,
            version=str(raw.get("version") or ""),
        )
        if not key.version.strip():
            continue
        if match_in_configuration(
            key,
            cpe_configurations,
            flat_cpes,
            impacted_products=impacted_products,
        ):
            results.append(raw)
    return results


async def vulns_for_item(
    vuln_repo: Any,
    item: InventoryKey,
    *,
    projection: dict[str, int] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return raw vulnerability documents affected by the inventory item.

    The Mongo pre-filter queries both the denormalized slug arrays
    (``vendor_slugs`` / ``product_slugs``) and the raw display-name arrays
    (``vendors`` / ``products``). Historic CPE tags frequently store a
    different slug than the asset catalog exposes to the user (e.g. the
    catalog lists ``graylog``/``graylog`` while old CPEs use
    ``graylog2``/``graylog2-server``), so a slug-only filter misses those
    records entirely. The matcher then uses the actual CPE data to decide.
    """
    if projection is None:
        projection = {
            "_id": 1,
            "vuln_id": 1,
            "title": 1,
            "cvss": 1,
            "epss_score": 1,
            "exploited": 1,
            "published": 1,
            "cpe_configurations": 1,
            "cpes": 1,
            "vendor_slugs": 1,
            "product_slugs": 1,
            "vendors": 1,
            "products": 1,
            "impacted_products": 1,
            "impactedProducts": 1,
        }

    vendor = _slug(item.vendor_slug)
    product = _slug(item.product_slug)
    # The CVE may reference the product via the denormalized vendor_slugs/
    # product_slugs arrays OR the raw display-name vendors/products arrays.
    # Both sets of fields are indexed, so the query planner can use either
    # side of the $or without falling back to a collection scan. We
    # intentionally do NOT query the nested ``impacted_products.*.slug``
    # paths here (no index exists) — in practice every CVE we've seen has
    # at least one of the denormalized arrays populated with a slug the
    # matcher can hit; the nested-path data is then read from the returned
    # document and evaluated in Python by the full matcher.
    query = {
        "$and": [
            {"$or": [{"vendor_slugs": vendor}, {"vendors": vendor}]},
            {"$or": [{"product_slugs": product}, {"products": product}]},
        ],
    }
    cursor = vuln_repo.collection.find(query, projection=projection)
    if limit:
        cursor = cursor.limit(limit)

    hits: list[dict[str, Any]] = []
    async for doc in cursor:
        cpe_configurations = _coerce_cpe_configurations(doc.get("cpe_configurations"))
        flat_cpes = _coerce_string_list(doc.get("cpes"))
        impacted_products = _coerce_impacted_products(
            doc.get("impacted_products") or doc.get("impactedProducts")
        )
        if match_in_configuration(
            item,
            cpe_configurations,
            flat_cpes,
            impacted_products=impacted_products,
        ):
            hits.append(doc)
    return hits


# --- Coercion helpers (raw dict documents vs. Pydantic models) ---


def _get_attr(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
        else:
            value = getattr(obj, name, None)
            if value is not None:
                return value
    return None


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _coerce_slug_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {_slug(v) for v in value if isinstance(v, str) and v}


def _coerce_cpe_configurations(value: Any) -> list[CpeConfiguration]:
    """Accept raw dict/list structures from Mongo or already-parsed models."""
    if not value:
        return []
    result: list[CpeConfiguration] = []
    for entry in value:
        if isinstance(entry, CpeConfiguration):
            result.append(entry)
            continue
        if isinstance(entry, dict):
            try:
                result.append(CpeConfiguration.model_validate(entry))
            except Exception:  # pragma: no cover - defensive
                continue
    return result
