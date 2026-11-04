"""Stats aggregations pick the aggregatable path from the live mapping.

Motivating log: on an index where ``vendorSlugs`` was dynamically mapped as
``text`` (+ ``.keyword``), the dashboard's Today summary aggregated on the bare
field first, got a 400 "Text fields are not optimised for operations that
require per-document field data", logged ``opensearch.request_error`` and only
then retried on ``.keyword`` — on every request.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.core.config import settings
from app.db import opensearch as os_module
from app.services.stats_service import StatsService, _aggregation_field_resolver


def _drifted(monkeypatch) -> None:
    monkeypatch.setitem(
        os_module._exact_field_paths,
        settings.opensearch_index,
        {
            "vendorSlugs": "vendorSlugs.keyword",
            "productSlugs": "productSlugs.keyword",
            "vendors": "vendors",
            "cvss.severity": "cvss.severity",
        },
    )


def test_drifted_text_fields_use_the_keyword_subfield_on_the_first_try(monkeypatch):
    _drifted(monkeypatch)
    field = _aggregation_field_resolver(use_keyword_suffix=False)
    assert field("vendorSlugs") == "vendorSlugs.keyword"
    assert field("productSlugs") == "productSlugs.keyword"


def test_keyword_fields_are_never_suffixed_on_the_retry(monkeypatch):
    # A field that is already keyword has no .keyword sub-field; suffixing it
    # returns an empty bucket list without an error.
    _drifted(monkeypatch)
    field = _aggregation_field_resolver(use_keyword_suffix=True)
    assert field("vendors") == "vendors"
    assert field("cvss.severity") == "cvss.severity"


def test_unknown_mapping_keeps_the_bare_name_then_the_suffix(monkeypatch):
    monkeypatch.setattr(os_module, "_exact_field_paths", {})
    assert _aggregation_field_resolver(False)("vendorSlugs") == "vendorSlugs"
    assert _aggregation_field_resolver(True)("vendorSlugs") == "vendorSlugs.keyword"
    assert _aggregation_field_resolver(True)("x.keyword") == "x.keyword"


def test_vulnerability_stats_query_uses_the_live_paths(monkeypatch):
    monkeypatch.setitem(
        os_module._exact_field_paths,
        settings.opensearch_index,
        {"vendors": "vendors.keyword", "products": "products", "cwes": "cwes"},
    )
    body = StatsService()._build_vulnerability_query(
        start_30_days=datetime(2026, 1, 1, tzinfo=UTC),
        use_keyword_suffix=False,
    )
    aggs = body["aggs"]
    assert aggs["vendors"]["terms"]["field"] == "vendors.keyword"
    assert aggs["products"]["terms"]["field"] == "products"
    assert aggs["cwes"]["terms"]["field"] == "cwes"
