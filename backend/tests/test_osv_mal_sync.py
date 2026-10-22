"""Regression tests for the OSV / malware-feed sync fixes (litellm 1.107.0 case).

1. A MAL-* record that gains a new affected version must update the existing
   impactedProducts entry (previously only new (vendor, product) keys merged).
2. A non-MAL record aliasing a MAL-* (PYSEC-2026-2 ↔ MAL-2026-2144) must resolve
   to the MAL-* doc instead of creating a duplicate.
3. Incremental syncs re-read a lookback window but skip (id, modified) rows
   they already processed.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.repositories.vulnerability_repository import (
    _merge_osv_entry_versions,
    _osv_would_change,
)
from app.services.ingestion.normalizer import build_document_from_osv
from app.services.ingestion.osv_client import OsvClient
from app.services.ingestion.osv_pipeline import OsvPipeline, _prune_processed_rows


# --------------------------------------------------------------------------
# 1. impactedProducts version merge
# --------------------------------------------------------------------------

def test_merge_adds_new_concrete_version():
    assert _merge_osv_entry_versions(["1.82.7", "1.82.8"], ["1.82.7", "1.82.8", "1.107.0"]) == [
        "1.82.7",
        "1.82.8",
        "1.107.0",
    ]


def test_merge_no_change_returns_none():
    assert _merge_osv_entry_versions(["1.82.7", "1.82.8"], ["1.82.8", "1.82.7"]) is None


def test_merge_never_removes_versions():
    assert _merge_osv_entry_versions(["1.0", "2.0"], ["2.0"]) is None


def test_merge_ignores_incoming_broad_sentinel():
    # deps.dev already resolved ">=0" to concrete versions — keep them.
    assert _merge_osv_entry_versions(["1.0.0", "1.0.1"], [">=0"]) is None


def test_merge_replaces_broad_sentinel_with_concrete():
    assert _merge_osv_entry_versions([">=0"], ["1.82.7"]) == ["1.82.7"]


def _litellm_entry(versions):
    return {
        "vendor": {"name": "PyPI", "slug": "pypi"},
        "product": {"name": "litellm", "slug": "litellm"},
        "versions": versions,
    }


def _would_change(existing, impacted, raw):
    return _osv_would_change(
        existing,
        osv_id="MAL-2026-2144",
        vendors=None,
        products=None,
        product_versions=None,
        vendor_slugs=None,
        product_slugs=None,
        product_version_ids=None,
        impacted_products=impacted,
        references=None,
        aliases=["MAL-2026-2144"],
        cwes=None,
        cvss_metrics=None,
        osv_raw=raw,
    )


def test_would_change_detects_new_version_on_existing_entry():
    raw = {"id": "MAL-2026-2144"}
    existing = {
        "aliases": ["MAL-2026-2144"],
        "impactedProducts": [_litellm_entry(["1.82.7", "1.82.8"])],
        "sources": [{"source": "OSV", "raw": raw}],
    }
    # Same versions → nothing to do (fast path must still short-circuit).
    assert _would_change(existing, [_litellm_entry(["1.82.7", "1.82.8"])], raw) is False
    # New version on the same (vendor, product) key → must enter the merge path.
    assert _would_change(existing, [_litellm_entry(["1.82.7", "1.82.8", "1.107.0"])], raw) is True


# --------------------------------------------------------------------------
# 2. MAL-* alias priority (pipeline, normalizer)
# --------------------------------------------------------------------------

PYSEC_RECORD = {
    "id": "PYSEC-2026-2",
    "aliases": ["MAL-2026-2144"],
    "modified": "2026-03-25T16:45:07.164747Z",
    "published": "2026-03-24T15:35:32Z",
    "summary": "litellm compromised",
    "affected": [
        {"package": {"ecosystem": "PyPI", "name": "litellm"}, "versions": ["1.82.7", "1.82.8"]}
    ],
}


def test_resolve_vuln_id_prefers_mal_alias():
    assert OsvPipeline._resolve_vuln_id(PYSEC_RECORD) == "MAL-2026-2144"


def test_resolve_vuln_id_mal_alias_beats_cve():
    record = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1", "MAL-2026-9"]}
    assert OsvPipeline._resolve_vuln_id(record) == "MAL-2026-9"


def test_resolve_vuln_id_without_mal_unchanged():
    assert OsvPipeline._resolve_vuln_id({"id": "PYSEC-2026-99", "aliases": ["CVE-2026-5"]}) == "CVE-2026-5"
    assert OsvPipeline._resolve_vuln_id({"id": "PYSEC-2026-99", "aliases": []}) == "PYSEC-2026-99"


def test_normalizer_document_id_matches_pipeline():
    # The insert path writes `replace_one({_id: vuln_id}, document)`; the
    # document's own _id must agree or MongoDB rejects the immutable-_id change.
    result = build_document_from_osv(PYSEC_RECORD, ingested_at=datetime.now(tz=UTC))
    assert result is not None
    assert result[0].vuln_id == OsvPipeline._resolve_vuln_id(PYSEC_RECORD) == "MAL-2026-2144"


# --------------------------------------------------------------------------
# 3. Incremental lookback memory
# --------------------------------------------------------------------------

async def test_iter_incremental_skips_already_processed_rows(monkeypatch):
    client = OsvClient()
    try:
        async def fake_rows(ecosystem, since=None):
            # newest-first, like the real CSV
            return [
                ("MAL-2026-2144", "2026-10-21T22:01:01.881791175Z"),
                ("MAL-2026-1000", "2026-10-21T10:00:00Z"),
            ]

        fetched: list[str] = []

        async def fake_fetch(vuln_id):
            fetched.append(vuln_id)
            return {"id": vuln_id}

        monkeypatch.setattr(client, "fetch_modified_ids", fake_rows)
        monkeypatch.setattr(client, "fetch_vulnerability", fake_fetch)

        already = {
            "MAL-2026-1000": "2026-10-21T10:00:00Z",  # same stamp → skip
            "MAL-2026-2144": "2026-03-26T10:03:39Z",  # older stamp → re-fetch
        }
        out = [
            r["id"]
            async for r in client._iter_incremental(
                "PyPI", datetime(2026, 10, 20, tzinfo=UTC), set(), already
            )
        ]
        assert out == ["MAL-2026-2144"]
        assert fetched == ["MAL-2026-2144"]
    finally:
        await client.close()


def test_prune_processed_rows_drops_entries_outside_window():
    now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
    rows = _prune_processed_rows(
        {
            "MAL-NEW": "2026-10-21T22:01:01.881791175Z",
            "MAL-OLD": "2026-10-10T00:00:00Z",
        },
        now=now,
        lookback_hours=48,
    )
    assert rows == [["MAL-NEW", "2026-10-21T22:01:01.881791175Z"]]
