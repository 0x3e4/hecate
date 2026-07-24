"""Tests for numeric affected-version ranges and the DQL plumbing around them.

Motivating bug: searching the vulnerability explorer for a version you actually
run returned nothing unless an advisory happened to *name* that exact string.
CVE-2026-63030 ("WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2") stores
``productVersions = [6, 6.9, 6.9.5, 7, 7.0, 7.0.2]`` — the range boundaries, not
the versions in between — so ``7.0.1`` matched nothing despite being squarely
affected.

Second bug found while fixing the first: EUVD writes a large share of its
version strings with a typographic operator and an implicit lower bound
(``"4.7 ≤4.7.30"``, ``"0 ≤2.4.7"``, ``"n/a ≤6.8.2"``). The shared clause parser
read only the leading token, so those parsed as the *exact* version ``4.7`` /
``0`` / ``n`` — silently suppressing inventory matches too.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.vulnerability import VulnerabilityDocument
from app.services.inventory_matcher import (
    _parse_range_clauses,
    _version_in_range_string,
)
from app.services.version_ranges import (
    VERSION_NUMERIC_MAX,
    build_version_ranges,
    encode_version,
    range_bounds_from_string,
)
from app.services.vulnerability_service import (
    _extract_affected_version_terms,
    _extract_slug_scope,
    _version_range_clause,
)

LE = "≤"  # ≤


def _impacted(versions: list[str], vendor: str = "wordpress", product: str = "wordpress"):
    return [
        {
            "vendor": {"name": vendor, "slug": vendor},
            "product": {"name": product, "slug": product},
            "versions": versions,
        }
    ]


def _covers(ranges: list[dict], version: str) -> bool:
    encoded = encode_version(version)
    assert encoded is not None, f"{version!r} should be encodable"
    return any(r["startNumeric"] <= encoded < r["endNumeric"] for r in ranges)


# --- encoding ---------------------------------------------------------------


def test_encode_version_pads_and_orders():
    assert encode_version("7.0") == encode_version("7.0.0")
    assert encode_version("7.0.1") > encode_version("7.0")
    assert encode_version("7.0.2") > encode_version("7.0.1")
    assert encode_version("10.0") > encode_version("9.9")


def test_encode_version_tolerates_v_prefix():
    assert encode_version("v1.2.3") == encode_version("1.2.3")


def test_encode_version_rejects_unparsable():
    assert encode_version(None) is None
    assert encode_version("") is None
    assert encode_version("latest") is None


# --- range string -> half-open interval -------------------------------------


@pytest.mark.parametrize(
    "range_str",
    ["", "*", "-", "any", ">=0", ">= 0", ">0", "> 0", "n/a", "unknown"],
)
def test_broad_sentinels_are_not_indexed(range_str):
    """Unconstrained strings carry no information — indexing them would make
    every version match, so they must produce no interval at all."""
    assert range_bounds_from_string(range_str) is None


def test_bounds_are_half_open():
    start, end = range_bounds_from_string(">= 7.0, < 7.0.2")
    assert start == encode_version("7.0")
    assert end == encode_version("7.0.2")


def test_inclusive_upper_bound_includes_its_own_boundary():
    ranges = build_version_ranges(impacted_products=_impacted(["<= 5.0.9"]))
    assert _covers(ranges, "5.0.9")
    assert not _covers(ranges, "5.0.10")


def test_exclusive_upper_bound_excludes_its_own_boundary():
    ranges = build_version_ranges(impacted_products=_impacted(["< 5.0.9"]))
    assert not _covers(ranges, "5.0.9")
    assert _covers(ranges, "5.0.8")


def test_exclusive_lower_bound_excludes_its_own_boundary():
    ranges = build_version_ranges(impacted_products=_impacted(["> 5.0.9, < 6.0"]))
    assert not _covers(ranges, "5.0.9")
    assert _covers(ranges, "5.0.10")


def test_exact_version_pins_a_single_point():
    ranges = build_version_ranges(impacted_products=_impacted(["2.2.3"]))
    assert _covers(ranges, "2.2.3")
    assert not _covers(ranges, "2.2.4")
    assert not _covers(ranges, "2.2.2")


def test_open_ended_lower_bound_keeps_the_max_sentinel():
    start, end = range_bounds_from_string(">= 5.1.0")
    assert start == encode_version("5.1.0")
    assert end == VERSION_NUMERIC_MAX


def test_unencodable_bound_drops_the_range_rather_than_widening_it():
    """Fail closed: a bound we cannot compare must not silently become 0/MAX."""
    assert range_bounds_from_string(">= 2.0.0-beta, < snapshot") is None


def test_inverted_bounds_are_dropped():
    assert range_bounds_from_string(">= 9.0, < 2.0") is None


# --- EUVD typographic / implicit-lower-bound shapes -------------------------


@pytest.mark.parametrize(
    "range_str, expected",
    [
        (f"4.7 {LE}4.7.30", [(">=", "4.7"), ("<=", "4.7.30")]),
        (f"6.9 {LE}6.9.1", [(">=", "6.9"), ("<=", "6.9.1")]),
        (f"0 {LE}2.4.7", [("<=", "2.4.7")]),
        (f"n/a {LE}5.0.0", [("<=", "5.0.0")]),
        (f"* {LE}1.4.2", [("<=", "1.4.2")]),
        (f"n/a {LE}{LE} 1.50.2", [("<=", "1.50.2")]),
    ],
)
def test_euvd_range_shapes_parse_as_ranges(range_str, expected):
    assert _parse_range_clauses(range_str) == expected


def test_ascii_range_shapes_are_untouched():
    assert _parse_range_clauses(">= 1.0.0, < 5.0.9") == [(">=", "1.0.0"), ("<", "5.0.9")]
    assert _parse_range_clauses("1.2.3") == [("=", "1.2.3")]


@pytest.mark.parametrize(
    "version, expected",
    [("4.7", True), ("4.7.20", True), ("4.7.30", True), ("4.7.31", False), ("4.6.9", False)],
)
def test_matcher_understands_euvd_shape(version, expected):
    """Regression: this whole family used to parse as the exact version 4.7."""
    assert _version_in_range_string(version, f"4.7 {LE}4.7.30") is expected


# --- the reported CVE -------------------------------------------------------


def test_wordpress_7_0_1_matches_the_spanning_advisory():
    """CVE-2026-63030: WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2.

    7.0.1 appears nowhere in the advisory's version list, only in the span.
    """
    ranges = build_version_ranges(
        impacted_products=_impacted([">= 6.9, < 6.9.5", ">= 7.0, < 7.0.2"])
    )
    assert _covers(ranges, "7.0.1")
    assert _covers(ranges, "7.0")
    assert _covers(ranges, "6.9.4")
    assert not _covers(ranges, "7.0.2")  # fixed release
    assert not _covers(ranges, "6.9.5")  # fixed release
    assert not _covers(ranges, "7.1")


def test_ranges_carry_the_owning_vendor_and_product():
    ranges = build_version_ranges(impacted_products=_impacted([">= 7.0, < 7.0.2"]))
    assert {(r["vendorSlug"], r["productSlug"]) for r in ranges} == {("wordpress", "wordpress")}


def test_display_name_spelling_is_indexed_alongside_the_slug():
    """The matcher accepts either spelling, so both must be searchable."""
    entry = [
        {
            "vendor": {"name": "WordPress Foundation", "slug": "wordpress"},
            "product": {"name": "WordPress", "slug": "wordpress"},
            "versions": ["< 7.0.2"],
        }
    ]
    vendors = {r["vendorSlug"] for r in build_version_ranges(impacted_products=entry)}
    assert vendors == {"wordpress", "wordpress-foundation"}


# --- other range sources ----------------------------------------------------


def test_cpe_configuration_bounds_are_folded_in():
    configs = [
        {
            "nodes": [
                {
                    "matches": [
                        {
                            "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                            "vendor": "wordpress",
                            "product": "wordpress",
                            "versionStartIncluding": "6.8",
                            "versionEndIncluding": "6.8.2",
                        }
                    ]
                }
            ]
        }
    ]
    ranges = build_version_ranges(cpe_configurations=configs)
    assert _covers(ranges, "6.8.1")
    assert _covers(ranges, "6.8.2"), "an *Including* upper bound must include itself"
    assert not _covers(ranges, "6.8.3")


def test_versionless_wildcard_cpe_contributes_nothing():
    """Mirrors the matcher's tier-3 rule: a bare `*` proves nothing."""
    assert build_version_ranges(cpes=["cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*"]) == []
    assert build_version_ranges(cpes=["cpe:2.3:a:phpbb:phpbb:-:*:*:*:*:*:*:*"]) == []


def test_versionless_wildcard_cpe_node_is_not_a_catch_all_range():
    """Regression: a cpeConfiguration match with a vendor/product but NO version
    bounds and no concrete version must not be indexed as ``[0, MAX)``.

    WordPress core CVEs almost always carry a bare ``wordpress:wordpress:*`` node
    alongside their real bounded ranges. Folding it to an open interval made
    *every* ``affectedVersion:`` query match those CVEs — an inventory running
    7.0.1 came back for advisories patched years before 7.0 existed."""
    configs = [
        {
            "nodes": [
                {
                    "matches": [
                        {  # the real, bounded range — patched in 5.4.1
                            "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                            "vendor": "wordpress",
                            "product": "wordpress",
                            "versionStartIncluding": "3.7",
                            "versionEndExcluding": "5.4.1",
                        },
                        {  # the bare wildcard node — no bounds, no version
                            "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                            "vendor": "wordpress",
                            "product": "wordpress",
                        },
                    ]
                }
            ]
        }
    ]
    ranges = build_version_ranges(cpe_configurations=configs)
    assert len(ranges) == 1  # only the bounded range survives
    assert _covers(ranges, "5.0.0")
    assert not _covers(ranges, "7.0.1")


def test_zero_lower_bound_with_upper_is_kept():
    """`versionStartIncluding: "0"` is a real bound ("everything before X"), not
    the all-None case — it must still produce a range."""
    configs = [
        {
            "nodes": [
                {
                    "matches": [
                        {
                            "vendor": "wordpress",
                            "product": "wordpress",
                            "versionStartIncluding": "0",
                            "versionEndExcluding": "5.4",
                        }
                    ]
                }
            ]
        }
    ]
    ranges = build_version_ranges(cpe_configurations=configs)
    assert _covers(ranges, "5.0.0")
    assert not _covers(ranges, "7.0.1")


def test_concrete_flat_cpe_pins_its_version():
    ranges = build_version_ranges(cpes=["cpe:2.3:a:phpbb:phpbb:3.3.17:*:*:*:*:*:*:*"])
    assert _covers(ranges, "3.3.17")
    assert not _covers(ranges, "3.3.18")


def test_no_version_evidence_yields_no_ranges():
    assert build_version_ranges(impacted_products=_impacted(["*", "n/a", ">=0"])) == []
    assert build_version_ranges() == []


def test_ranges_are_deduplicated():
    ranges = build_version_ranges(
        impacted_products=_impacted(["< 7.0.2", "< 7.0.2"]),
        cpes=["cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"],
    )
    assert len(ranges) == 1


# --- query construction -----------------------------------------------------


def test_affected_version_is_lifted_out_of_the_dql():
    remaining, versions = _extract_affected_version_terms(
        'vendorSlugs:"wordpress" AND affectedVersion:7.0.1'
    )
    assert versions == ["7.0.1"]
    # The surrounding boolean structure has to stay syntactically valid.
    assert "affectedVersion" not in remaining
    assert 'vendorSlugs:"wordpress" AND *:*' == remaining


def test_affected_version_accepts_quotes_and_the_snake_case_spelling():
    _, versions = _extract_affected_version_terms('affected_version:"1.2.3"')
    assert versions == ["1.2.3"]


def test_dql_without_affected_version_is_untouched():
    remaining, versions = _extract_affected_version_terms('vendorSlugs:"wordpress"')
    assert versions == []
    assert remaining == 'vendorSlugs:"wordpress"'


def test_version_range_clause_scopes_inside_the_nested_query():
    """The interval that covers the version must belong to the filtered product,
    otherwise a multi-product CVE matches on an unrelated component's range."""
    clause = _version_range_clause(
        ["7.0.1"], vendor_slugs=["wordpress"], product_slugs=["wordpress"]
    )
    must = clause["nested"]["query"]["bool"]["must"]
    assert clause["nested"]["path"] == "versionRanges"
    assert {"terms": {"versionRanges.vendorSlug": ["wordpress"]}} in must
    assert {"terms": {"versionRanges.productSlug": ["wordpress"]}} in must
    encoded = encode_version("7.0.1")
    assert {"range": {"versionRanges.startNumeric": {"lte": encoded}}} in must
    assert {"range": {"versionRanges.endNumeric": {"gt": encoded}}} in must


def test_version_range_clause_is_none_when_nothing_encodes():
    assert _version_range_clause(["latest"]) is None
    assert _version_range_clause([]) is None


def test_slug_scope_is_read_from_the_dql():
    vendors, products = _extract_slug_scope('vendorSlugs:"wordpress" AND productSlugs:"wordpress"')
    assert vendors == ["wordpress"]
    assert products == ["wordpress"]


def test_slug_scope_bails_out_on_negation():
    """A naive scan can't tell `vendorSlugs:x` from `NOT vendorSlugs:x`, and
    narrowing the range clause to an *excluded* slug would invert the filter."""
    assert _extract_slug_scope('NOT vendorSlugs:"wordpress"') == ([], [])


def test_slug_scope_skips_wildcards():
    assert _extract_slug_scope('vendorSlugs:word*') == ([], [])


# --- indexing path ----------------------------------------------------------

_MONGO_BASE = {
    "vuln_id": "CVE-2026-63030",
    "title": "t",
    "summary": "s",
    "ingested_at": datetime(2026, 7, 24, tzinfo=UTC),
}


def test_reindex_hydrates_snake_case_mongo_documents():
    """``mongo_serializable`` dumps without ``by_alias``, so MongoDB holds
    snake_case keys — but the fields declare a camelCase ``alias``. Without
    ``populate_by_name`` the reindex path (``model_validate(mongo_doc)``)
    silently dropped impacted products, CPE configurations and version tokens,
    which would have left ``versionRanges`` permanently empty."""
    doc = VulnerabilityDocument.model_validate(
        {
            **_MONGO_BASE,
            "impacted_products": _impacted([">= 7.0, < 7.0.2"]),
            "cpe_version_tokens": ["7.0"],
            "cpe_configurations": [
                {"nodes": [{"matches": [{"vendor": "wordpress", "product": "wordpress",
                                         "versionEndExcluding": "7.0.2"}]}]}
            ],
        }
    )
    assert doc.impacted_products
    assert doc.cpe_configurations
    assert doc.cpe_version_tokens == ["7.0"]
    assert _covers(doc.opensearch_document()["versionRanges"], "7.0.1")


def test_camel_case_key_still_wins_when_both_are_present():
    """Preserves the documented invariant that ``impactedProducts`` is the
    authoritative spelling."""
    doc = VulnerabilityDocument.model_validate(
        {
            **_MONGO_BASE,
            "impacted_products": _impacted(["< 1.0"]),
            "impactedProducts": _impacted(["< 9.0"]),
        }
    )
    assert doc.impacted_products == _impacted(["< 9.0"])


def test_serialization_stays_camel_case():
    doc = VulnerabilityDocument.model_validate(
        {**_MONGO_BASE, "impacted_products": _impacted(["< 7.0.2"])}
    )
    dumped = doc.opensearch_document()
    assert "impactedProducts" in dumped
    assert "impacted_products" not in dumped


def test_document_without_version_evidence_omits_the_field():
    doc = VulnerabilityDocument.model_validate(_MONGO_BASE)
    assert "versionRanges" not in doc.opensearch_document()
