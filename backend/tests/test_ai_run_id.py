"""Every AI run names itself, so a page can tell its result from the previous one.

SSE keeps only the newest event per job name. A second batch analysis started
while the first one's "completed" event was still there took that event for its
own and showed the old report under the new selection.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import vulnerabilities
from app.core.write_auth import require_ai_write
from app.schemas.ai import AIBatchInvestigationResponse
from app.services import event_bus
from app.services.ai_service import get_ai_client
from app.services.app_settings_service import get_app_settings_service
from app.services.audit_service import get_audit_service
from app.services.inventory_service import get_inventory_service
from app.services.vulnerability_service import get_vulnerability_service


class Service:
    async def get_by_id(self, identifier: str) -> Any:
        return SimpleNamespace(vuln_id=identifier)

    async def save_batch_analysis(self, **_: Any) -> str:
        return "batch-1"


class Inventory:
    async def affected_inventory_for_vuln(self, _: Any) -> list[Any]:
        return []


class AppSettings:
    async def get_ai_batch_max_vulns(self) -> int:
        return 10


class Audit:
    async def record_event(self, *_: Any, **__: Any) -> None:
        return None


class AI:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def analyze_vulnerabilities_batch(self, provider: str, vulns: list[Any], **_: Any) -> AIBatchInvestigationResponse:
        if self.fail:
            raise RuntimeError("provider down")
        return AIBatchInvestigationResponse(
            provider=provider,
            language="en",
            summary="report",
            individualSummaries={},
            generatedAt="2026-11-02T00:00:00Z",
            vulnerabilityCount=len(vulns),
        )


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[event_bus.JobEvent]:
    published: list[event_bus.JobEvent] = []
    monkeypatch.setattr(event_bus, "get_event_bus", lambda: SimpleNamespace(publish=published.append))
    return published


def test_each_batch_submit_returns_the_run_id_its_task_publishes_under(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []

    def fake_task(**kwargs: Any) -> Any:
        started.append(kwargs["run_id"])
        return asyncio.sleep(0)

    monkeypatch.setattr(vulnerabilities, "_run_batch_ai_investigation_background", fake_task)
    app = FastAPI()
    app.include_router(vulnerabilities.router, prefix="/vulnerabilities")
    app.dependency_overrides.update({
        require_ai_write: lambda: None,
        get_vulnerability_service: Service,
        get_ai_client: AI,
        get_audit_service: Audit,
        get_inventory_service: Inventory,
        get_app_settings_service: AppSettings,
    })
    client = TestClient(app)
    body = {"vulnerabilityIds": ["CVE-2026-0001"], "provider": "openai"}

    first = client.post("/vulnerabilities/ai-investigation/batch", json=body).json()
    second = client.post("/vulnerabilities/ai-investigation/batch", json=body).json()

    assert started == [first["runId"], second["runId"]]
    assert first["runId"] != second["runId"]


@pytest.mark.parametrize("fail", [False, True])
async def test_every_event_of_a_batch_run_carries_its_run_id(events: list[event_bus.JobEvent], fail: bool) -> None:
    await vulnerabilities._run_batch_ai_investigation_background(
        vulnerability_ids=["CVE-2026-0001"],
        run_id="run-1",
        vulnerabilities=[SimpleNamespace(vuln_id="CVE-2026-0001")],
        provider="openai",
        language=None,
        additional_context=None,
        triggered_by=None,
        client_ip=None,
        ai_client=AI(fail=fail),
        service=Service(),
        audit_service=Audit(),
    )

    assert [e.event_type for e in events] == ["job_started", "job_failed" if fail else "job_completed"]
    assert [e.metadata.get("runId") for e in events] == ["run-1", "run-1"]
