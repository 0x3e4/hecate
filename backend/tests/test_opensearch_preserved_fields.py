"""Full writes of a vulnerability keep the fields only OpenSearch holds.

AI assessments, attack-path narratives and batch references are appended to
the indexed document by scripted updates; MongoDB never sees them. Pipeline
upserts, manual refreshes, deps.dev enrichment and ``reindex-opensearch``
build the document from MongoDB, and a plain ``index`` call replaced it and
dropped them. These tests pin the replacement script and the routing.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.core.config import settings
from app.db import opensearch as os_module
from app.db.opensearch import (
    PRESERVED_VULNERABILITY_FIELDS,
    async_index_document,
    replace_keeping_fields_body,
)


def _run_script(source: dict[str, Any] | None, body: dict[str, Any]) -> dict[str, Any]:
    """Python model of the Painless script: what the stored document becomes."""
    params = body["script"]["params"]
    current = dict(source or {})
    kept = {f: current[f] for f in params["preserve"] if f in current}
    result = dict(params["doc"])
    for key, value in kept.items():
        result.setdefault(key, value)
    return result


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def update(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("update", kwargs))
        return {"result": "updated"}

    def index(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("index", kwargs))
        return {"result": "created"}


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(os_module, "get_client", lambda: client)
    monkeypatch.setattr(os_module, "ensure_vulnerability_index", lambda _name: None)
    return client


def test_the_preserved_fields_are_the_ones_the_save_scripts_write() -> None:
    assert set(PRESERVED_VULNERABILITY_FIELDS) == {
        "ai_assessment",
        "ai_assessments",
        "attack_path",
        "attack_paths",
        "batch_analyses",
    }


def test_body_is_a_scripted_upsert_that_sends_the_document_once() -> None:
    doc = {"vuln_id": "CVE-2026-1", "summary": "new"}
    body = replace_keeping_fields_body(doc)

    assert body["scripted_upsert"] is True
    assert body["upsert"] == {}
    assert body["script"]["lang"] == "painless"
    assert body["script"]["params"] == {"doc": doc, "preserve": list(PRESERVED_VULNERABILITY_FIELDS)}
    # The script itself: drop everything, put the new document, restore kept fields.
    source = body["script"]["source"]
    assert "ctx._source.clear()" in source
    assert "ctx._source.putAll(params.doc)" in source


def test_a_rewrite_keeps_ai_fields_and_drops_stale_data_fields() -> None:
    stored = {
        "vuln_id": "CVE-2026-1",
        "summary": "old",
        "stale_field": "gone after the rewrite",
        "ai_assessment": {"summary": "latest"},
        "ai_assessments": [{"summary": "first"}, {"summary": "latest"}],
        "attack_path": {"summary": "path"},
        "attack_paths": [{"summary": "path"}],
        "batch_analyses": [{"batchId": "batch-1"}],
    }
    result = _run_script(stored, replace_keeping_fields_body({"vuln_id": "CVE-2026-1", "summary": "new"}))

    assert result["summary"] == "new"
    assert "stale_field" not in result
    for field in PRESERVED_VULNERABILITY_FIELDS:
        assert result[field] == stored[field]


def test_a_field_carried_by_the_new_document_wins() -> None:
    stored = {"ai_assessment": {"summary": "old"}}
    body = replace_keeping_fields_body({"ai_assessment": {"summary": "new"}})

    assert _run_script(stored, body)["ai_assessment"] == {"summary": "new"}


def test_a_new_document_is_written_as_is() -> None:
    doc = {"vuln_id": "CVE-2026-2", "summary": "first write"}

    assert _run_script(None, replace_keeping_fields_body(doc)) == doc


async def test_vulnerability_index_writes_go_through_the_replacement_script(fake_client: _FakeClient) -> None:
    doc = {"vuln_id": "CVE-2026-1"}
    await async_index_document(settings.opensearch_index, "CVE-2026-1", doc, wait_for_refresh=False)

    [(method, kwargs)] = fake_client.calls
    assert method == "update"
    assert kwargs["id"] == "CVE-2026-1"
    assert kwargs["body"] == replace_keeping_fields_body(doc)
    assert kwargs["retry_on_conflict"] == 3
    assert kwargs["refresh"] is False


async def test_other_indices_keep_a_plain_index_call(fake_client: _FakeClient) -> None:
    doc = {"batchId": "batch-1"}
    await async_index_document(f"{settings.opensearch_index}-batch-analyses", "batch-1", doc)

    [(method, kwargs)] = fake_client.calls
    assert method == "index"
    assert kwargs["body"] == doc


def test_reindex_cli_sends_update_actions_with_the_replacement_script() -> None:
    from pathlib import Path

    source = Path(__file__).resolve().parents[1].joinpath("app", "cli.py").read_text(encoding="utf-8")
    start = source.index("async def run_opensearch_reindex")
    end = source.find("\nasync def ", start + 1)
    reindex = source[start:] if end == -1 else source[start:end]

    assert '"_op_type": "update"' in reindex
    assert "replace_keeping_fields_body(vuln.opensearch_document())" in reindex
