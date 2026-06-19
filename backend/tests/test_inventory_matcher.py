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
