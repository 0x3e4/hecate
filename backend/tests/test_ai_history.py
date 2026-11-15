"""Earlier analyses in AI prompts, the model on every result, and scan AI events."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from bson import ObjectId

from app.core.config import settings
from app.services import ai_service
from app.services.ai_history import previous_scan_analyses
from app.services.ai_service import (
    PREVIOUS_SUMMARY_LIMIT,
    build_scan_prompts,
    format_previous_analyses_block,
    model_name_for,
)


def test_no_history_adds_nothing() -> None:
    assert format_previous_analyses_block(None) == ""
    assert format_previous_analyses_block([{"summary": "  "}, "x"]) == ""  # type: ignore[list-item]


def test_block_names_date_provider_model_and_context_and_drops_the_footer() -> None:
    block = format_previous_analyses_block([{
        "summary": "## Priority\nHIGH\n\n---\n_Added via Claude - MCP_",
        "generatedAt": "2026-11-01T10:00:00Z",
        "provider": "openai",
        "model": "gpt-5",
        "context": "analysis of an earlier scan of this target",
    }])
    assert "PREVIOUS ANALYSES" in block
    assert "2026-11-01T10:00:00Z, openai / gpt-5" in block
    assert "earlier scan of this target" in block
    assert "Added via" not in block
    assert "current data wins" in block


def test_block_keeps_two_entries_and_cuts_long_summaries() -> None:
    entries = [{"summary": "x" * (PREVIOUS_SUMMARY_LIMIT + 500)} for _ in range(3)]
    block = format_previous_analyses_block(entries)
    assert block.count("### Previous analysis") == 2
    assert "[...]" in block
    assert "x" * (PREVIOUS_SUMMARY_LIMIT + 1) not in block


def test_scan_prompt_carries_the_history_after_the_findings() -> None:
    _, user = build_scan_prompts(
        {"_id": "s1", "target_name": "app"}, [],
        previous_analyses=[{"summary": "Top risk: lodash"}],
    )
    assert user.index("FINDINGS:") < user.index("PREVIOUS ANALYSES")
    assert "Top risk: lodash" in user


def test_model_follows_the_configured_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_model", "gpt-test")
    monkeypatch.setattr(settings, "openai_compatible_model", "")
    assert model_name_for("openai") == "gpt-test"
    assert model_name_for("openai-compatible") is None
    assert model_name_for("unknown") is None


class FakeCollection:
    def __init__(self, doc: dict[str, Any] | None) -> None:
        self.doc = doc
        self.query: dict[str, Any] | None = None

    async def find_one(self, query: dict[str, Any], projection: Any = None, sort: Any = None) -> dict[str, Any] | None:
        self.query = query
        return self.doc


class FakeRepo:
    def __init__(self, doc: dict[str, Any] | None) -> None:
        self.collection = FakeCollection(doc)


async def test_scan_history_prefers_its_own_analyses_newest_first() -> None:
    repo = FakeRepo(None)
    scan = {"target_id": "t", "ai_analyses": [{"summary": "old"}, {"summary": "new"}]}
    history = await previous_scan_analyses(repo, str(ObjectId()), scan)
    assert [h["summary"] for h in history] == ["new", "old"]
    assert repo.collection.query is None  # two own analyses: no lookup needed


async def test_scan_history_falls_back_to_an_earlier_scan_of_the_target() -> None:
    created = datetime(2026, 11, 10, tzinfo=UTC)
    repo = FakeRepo({"ai_analysis": {"summary": "earlier"}, "created_at": created, "commit_sha": "a9f97338fec1beef"})
    scan_id = str(ObjectId())
    history = await previous_scan_analyses(repo, scan_id, {"target_id": "t", "created_at": datetime(2026, 11, 12, tzinfo=UTC)})
    assert history[0]["summary"] == "earlier"
    assert "a9f97338fec1" in history[0]["context"]
    assert repo.collection.query["target_id"] == "t"
    assert repo.collection.query["_id"] == {"$ne": ObjectId(scan_id)}
    assert repo.collection.query["created_at"] == {"$lt": datetime(2026, 11, 12, tzinfo=UTC)}


async def test_scan_ai_job_reports_start_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.v1 import scans as scans_api

    events: list[tuple[str, str, dict[str, Any]]] = []
    monkeypatch.setattr(scans_api, "publish_job_started", lambda name, *a, **kw: events.append(("started", name, kw)))
    monkeypatch.setattr(scans_api, "publish_job_completed", lambda name, *a, **kw: events.append(("completed", name, kw)))
    monkeypatch.setattr(scans_api, "publish_job_failed", lambda name, *a, **kw: events.append(("failed", name, kw)))

    class FailingClient:
        async def analyze_scan(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("provider down")

    await scans_api._run_scan_ai_analysis_background(
        scan_id="s1", run_id="r1", scan={}, findings=[], provider="openai", language=None,
        additional_context=None, triggered_by=None, ai_client=FailingClient(), service=None,  # type: ignore[arg-type]
    )

    assert [(kind, name) for kind, name, _ in events] == [("started", "ai_scan_analysis_s1"), ("failed", "ai_scan_analysis_s1")]
    assert all(kw["runId"] == "r1" for _, _, kw in events)
    assert events[1][2]["error"] == "provider down"


def test_every_result_constructor_sets_the_model() -> None:
    import inspect

    source = inspect.getsource(ai_service.AIClient)
    assert source.count("model=model_name_for(provider)") == 5


def test_a_model_name_from_an_mcp_client_is_trimmed_and_capped() -> None:
    from app.mcp.security import clean_model_name

    assert clean_model_name("  claude-opus-5-5\n") == "claude-opus-5-5"
    assert clean_model_name("   ") is None
    assert clean_model_name(None) is None
    assert len(clean_model_name("x" * 500) or "") == 100
