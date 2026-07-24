"""Tests for exact-match routing of identifier fields in DQL queries.

Motivating bug: ``vendorSlugs:"wordpress"`` returned advisories for *other*
vendors — "Dokan WordPress Plugin", "WPMU DEV - Your All-in-One WordPress
Platform", "WordPress.com" — because those vendors' slugs all *contain* the
token ``wordpress``.

Root cause is mapping drift, not the query: ``vendorSlugs`` is declared
``keyword`` in ``ensure_vulnerability_index``, but indices created before that
declaration existed had it dynamically mapped as analyzed ``text`` plus a
``.keyword`` sub-field. On such an index the standard analyzer turns
``dokan-wordpress-plugin`` into ``[dokan, wordpress, plugin]`` and the clause
matches. Field mapping types cannot be changed in place, so the query is routed
to whichever path is exact on the live index instead.
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.db import opensearch as os_module
from app.services.vulnerability_service import _translate_dql_fields


@pytest.fixture
def drifted_index(monkeypatch):
    """Simulate an index where the slug fields were dynamically mapped as text."""
    monkeypatch.setitem(
        os_module._exact_field_paths,
        settings.opensearch_index,
        {
            "vendorSlugs": "vendorSlugs.keyword",
            "productSlugs": "productSlugs.keyword",
            "productVersions": "productVersions.keyword",
            "productVersionIds": "productVersionIds.keyword",
            "sourceNames": "sourceNames.keyword",
            "vendors": "vendors",
            "summary": "summary",
        },
    )


@pytest.fixture
def clean_index(monkeypatch):
    """Simulate a correctly mapped index — every field is already keyword."""
    monkeypatch.setitem(
        os_module._exact_field_paths,
        settings.opensearch_index,
        {
            "vendorSlugs": "vendorSlugs",
            "productSlugs": "productSlugs",
            "vendors": "vendors",
        },
    )


def test_slug_clause_is_routed_to_the_exact_path(drifted_index):
    assert _translate_dql_fields('vendorSlugs:"wordpress"') == 'vendorSlugs.keyword:"wordpress"'


def test_snake_case_alias_is_translated_then_routed(drifted_index):
    assert _translate_dql_fields('vendor_slugs:"wordpress"') == 'vendorSlugs.keyword:"wordpress"'


def test_wildcards_still_work_after_routing(drifted_index):
    """Substring search stays available — it just runs over the whole slug now
    instead of over analyzer tokens."""
    assert _translate_dql_fields("vendorSlugs:*wordpress*") == "vendorSlugs.keyword:*wordpress*"


def test_already_qualified_field_is_not_double_suffixed(drifted_index):
    assert _translate_dql_fields('vendorSlugs.keyword:"wordpress"') == 'vendorSlugs.keyword:"wordpress"'


def test_display_name_fields_stay_analyzed(drifted_index):
    """`vendors:wordpress` should keep finding "WordPress Foundation" — token
    matching is the useful behaviour for prose-ish display names."""
    assert _translate_dql_fields('vendors:"wordpress"') == 'vendors:"wordpress"'


def test_source_expansion_output_is_routed_too(drifted_index):
    translated = _translate_dql_fields("source:NVD")
    assert translated == "(source:NVD OR sourceNames.keyword:NVD)"


def test_no_rewrite_on_a_correctly_mapped_index(clean_index):
    assert _translate_dql_fields('vendorSlugs:"wordpress"') == 'vendorSlugs:"wordpress"'


def test_unknown_mapping_leaves_the_query_untouched(monkeypatch):
    """Before the mapping has been read (or when OpenSearch is unreachable) the
    query must pass through unchanged rather than target a field that may not
    exist."""
    monkeypatch.setattr(os_module, "_exact_field_paths", {})
    assert _translate_dql_fields('vendorSlugs:"wordpress"') == 'vendorSlugs:"wordpress"'


def test_mapping_walk_detects_text_with_keyword_subfield():
    resolved: dict[str, str] = {}
    os_module._walk_mapping_properties(
        {
            "vendorSlugs": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
            },
            "products": {"type": "keyword"},
            "summary": {"type": "text"},
            "cvss": {"properties": {"severity": {"type": "keyword"}}},
        },
        "",
        resolved,
    )
    assert resolved["vendorSlugs"] == "vendorSlugs.keyword"
    assert resolved["products"] == "products"
    # text with no keyword sub-field has no exact path — leave it alone.
    assert resolved["summary"] == "summary"
    assert resolved["cvss.severity"] == "cvss.severity"
