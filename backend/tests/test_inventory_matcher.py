"""Regression tests for the inventory CPE/version matcher.

Focus: the matcher must be **fail-closed** for version-less references. A
vendor/product that appears only via a wildcard CPE (``cpe:2.3:a:phpbb:phpbb:*``
/ ``:-:``) or a broad ``>=0`` range string carries no version evidence and must
NOT match a concrete inventory version.

Motivating bug: an inventory item phpBB / phpbb / 3.3.17 was wrongly flagged by
CVE-2008-6301, CVE-2007-5688, CVE-2006-7168, CVE-2007-5173 — all about
third-party phpBB *modules* (Small ShoutBox, Multi-Forums, Add Name, OpenID)
that reference ``phpbb:phpbb`` only as a secondary, version-less platform CPE.
"""
from __future__ import annotations

import pytest

from app.services.inventory_matcher import (
    InventoryKey,
    _coerce_cpe_configurations,
    match_in_configuration,
)

PHPBB = InventoryKey(vendor_slug="phpbb", product_slug="phpbb", version="3.3.17")


def _cpe_config(matches: list[dict]) -> list:
    return _coerce_cpe_configurations(
        [{"nodes": [{"operator": "OR", "negate": False, "matches": matches, "nodes": []}]}]
    )


# --- Negatives: version-less / broad references must NOT match 3.3.17 ---


@pytest.mark.parametrize(
    "flat_cpes",
    [
        ["cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*"],
        ["cpe:2.3:a:phpbb:phpbb:-:*:*:*:*:*:*:*"],
        # secondary product is the real vuln; phpbb is only a wildcard platform CPE
        ["cpe:2.3:a:prezmo:small_shoutbox:1.4:*:*:*:*:*:*:*", "cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*"],
    ],
)
def test_flat_wildcard_cpe_does_not_match(flat_cpes):
    assert match_in_configuration(PHPBB, [], flat_cpes, impacted_products=[]) is False


@pytest.mark.parametrize("versions", [[">=0"], [">= 0"], [">0"], ["*"], ["-"], ["n/a"], [""], []])
def test_broad_impacted_products_versions_do_not_match(versions):
    impacted = [{"vendor": {"slug": "phpbb"}, "product": {"slug": "phpbb"}, "versions": versions}]
    assert match_in_configuration(PHPBB, [], [], impacted_products=impacted) is False


def test_impacted_products_na_slug_does_not_match():
    impacted = [{"vendor": {"name": "n/a", "slug": "n-a"}, "product": {"name": "n/a", "slug": "n-a"}, "versions": ["n/a"]}]
    flat = ["cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*"]
    assert match_in_configuration(PHPBB, [], flat, impacted_products=impacted) is False


def test_cpe_config_wildcard_without_bounds_does_not_match():
    cfg = _cpe_config(
        [{"vendor": "phpbb", "product": "phpbb", "criteria": "cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*", "vulnerable": True}]
    )
    assert match_in_configuration(PHPBB, cfg, [], impacted_products=[]) is False


# --- Positives: concrete / properly-bounded data must still match 3.3.17 ---


@pytest.mark.parametrize("versions", [[">= 3.0.0, < 3.4.0"], ["3.3.17"], [">= 3.0.0"]])
def test_real_impacted_products_ranges_match(versions):
    impacted = [{"vendor": {"slug": "phpbb"}, "product": {"slug": "phpbb"}, "versions": versions}]
    assert match_in_configuration(PHPBB, [], [], impacted_products=impacted) is True


def test_flat_concrete_cpe_matches():
    flat = ["cpe:2.3:a:phpbb:phpbb:3.3.17:*:*:*:*:*:*:*"]
    assert match_in_configuration(PHPBB, [], flat, impacted_products=[]) is True


def test_cpe_config_with_end_excluding_bound_matches():
    cfg = _cpe_config(
        [{"vendor": "phpbb", "product": "phpbb", "criteria": "cpe:2.3:a:phpbb:phpbb:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "3.4.0"}]
    )
    assert match_in_configuration(PHPBB, cfg, [], impacted_products=[]) is True


def test_standalone_lower_bound_excludes_below_and_includes_above():
    older = InventoryKey(vendor_slug="phpbb", product_slug="phpbb", version="2.0.0")
    newer = InventoryKey(vendor_slug="phpbb", product_slug="phpbb", version="6.0.0")
    impacted = [{"vendor": {"slug": "phpbb"}, "product": {"slug": "phpbb"}, "versions": [">= 5.1.0"]}]
    assert match_in_configuration(older, [], [], impacted_products=impacted) is False
    assert match_in_configuration(newer, [], [], impacted_products=impacted) is True


# --- Malformed comma-laced version, NON-curated vendor (generic fail-closed
# --- path): must not coincidentally satisfy an unrelated branch's clause ---
#
# Deliberately uses a vendor/product pair that is NOT in
# ``_BRANCH_SCOPED_PRODUCTS`` (that table uses ("netscaler", "adc") /
# ("netscaler", "gateway"), see the branch-scoped tests further below) --
# these exercise the ordinary, non-branch-aware fallback behavior.

BRANCH_SCOPED_VERSIONS = [
    ">= 12.1-FIPS and NDcPP, < 55.333",
    ">= 13.1, < 60.32",
    ">= 13.1-FIPS and NDcPP, < 37.250",
    ">= 14.1, < 56.73",
]


def test_comma_laced_version_does_not_match_unrelated_branch_range():
    # "14.1, 66.59" is Citrix NetScaler's branch+build convention (branch
    # 14.1, build 66.59). Build 66.59 is newer than the branch's own fix
    # threshold (56.73), so this install is patched. Before the
    # parse_version fix, the comma caused silent truncation to
    # release=(14,) which numerically (and coincidentally) fell inside the
    # UNRELATED ">= 13.1, < 60.32" branch's window -- a false positive. For
    # a vendor/product NOT in ``_BRANCH_SCOPED_PRODUCTS``, parse_version's
    # fail-closed behavior is what prevents the false positive here.
    item = InventoryKey(vendor_slug="citrix", product_slug="netscaler", version="14.1, 66.59")
    impacted = [
        {
            "vendor": {"slug": "citrix"},
            "product": {"slug": "netscaler"},
            "versions": BRANCH_SCOPED_VERSIONS,
        }
    ]
    assert match_in_configuration(item, [], [], impacted_products=impacted) is False


def test_clean_version_still_matches_multi_branch_range():
    # Sanity check against over-correction: a genuinely vulnerable, cleanly
    # formatted version on the same multi-entry range list must still match.
    item = InventoryKey(vendor_slug="citrix", product_slug="netscaler", version="13.1.10.0")
    impacted = [
        {
            "vendor": {"slug": "citrix"},
            "product": {"slug": "netscaler"},
            "versions": BRANCH_SCOPED_VERSIONS,
        }
    ]
    assert match_in_configuration(item, [], [], impacted_products=impacted) is True


# --- Branch-aware matching for curated vendors (``_BRANCH_SCOPED_PRODUCTS``):
# --- NetScaler ADC/Gateway run an independent build counter per branch ---

def _netscaler_item(version: str) -> InventoryKey:
    return InventoryKey(vendor_slug="netscaler", product_slug="adc", version=version)


def _netscaler_impacted(versions: list[str]) -> list[dict]:
    return [{"vendor": {"slug": "netscaler"}, "product": {"slug": "adc"}, "versions": versions}]


def test_branch_scoped_patched_build_on_own_branch_does_not_match():
    # The originally reported case: branch 14.1, build 66.59 -- newer than
    # the branch's own fix threshold (56.73) -- must NOT be flagged.
    item = _netscaler_item("14.1, 66.59")
    impacted = _netscaler_impacted(BRANCH_SCOPED_VERSIONS)
    assert match_in_configuration(item, [], [], impacted_products=impacted) is False


def test_branch_scoped_vulnerable_build_on_own_branch_matches():
    # Same branch, but a build below the 56.73 threshold -- must match.
    item = _netscaler_item("14.1, 40.00")
    impacted = _netscaler_impacted(BRANCH_SCOPED_VERSIONS)
    assert match_in_configuration(item, [], [], impacted_products=impacted) is True


def test_branch_scoped_build_does_not_cross_match_unrelated_branch():
    # Branch 13.1, build 65.00 is ABOVE its own branch's threshold (60.32) --
    # not vulnerable via its own clause -- and must not accidentally match
    # any of the other three branches' clauses either (this is exactly the
    # cross-branch collision the original bug produced).
    item = _netscaler_item("13.1, 65.00")
    impacted = _netscaler_impacted(BRANCH_SCOPED_VERSIONS)
    assert match_in_configuration(item, [], [], impacted_products=impacted) is False


def test_branch_scoped_item_without_build_segment_does_not_match():
    # Only a branch, no build number at all -- insufficient data to evaluate
    # the threshold, fail closed rather than guess.
    item = _netscaler_item("14.1")
    impacted = _netscaler_impacted(BRANCH_SCOPED_VERSIONS)
    assert match_in_configuration(item, [], [], impacted_products=impacted) is False


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("14.1, 40.00", True),  # vulnerable build, fully-qualified bound matches
        ("14.1, 66.59", False),  # patched build, fully-qualified bound matches
    ],
)
def test_branch_scoped_fully_qualified_end_bound(version, expected):
    # Some CVE data repeats the branch prefix on the end bound itself
    # (e.g. "14.1.56.73" instead of the bare "56.73"). The branch prefix on
    # the end bound must be stripped and checked for consistency, not
    # compared against the item's build number at the wrong scale.
    item = _netscaler_item(version)
    impacted = _netscaler_impacted([">= 14.1, < 14.1.56.73"])
    assert match_in_configuration(item, [], [], impacted_products=impacted) is expected
