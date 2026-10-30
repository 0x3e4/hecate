"""What scanned or imported data must not be able to do on the way in and out."""
from __future__ import annotations

from typing import Any

import pytest

from app.services import ai_service
from app.services.scan_parser import parse_trufflehog_json
from app.services.vex_service import VexService


def _redacted(raw: str) -> str:
    report = {
        "results": [
            {
                "DetectorName": "Github",
                "Verified": True,
                "Raw": raw,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
            }
        ]
    }
    findings, _ = parse_trufflehog_json(report, "scan", "target")
    return findings[0].description.rsplit("Redacted: ", 1)[1]


def test_long_secrets_show_the_end_only() -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    assert _redacted(secret) == "...6789"


def test_short_secrets_show_nothing() -> None:
    assert _redacted("hunter2hunter2") == "***"


class FakeFindingRepo:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def bulk_update_vex_by_vulnerability(self, *args: Any, **kwargs: Any) -> int:
        self.calls.append((args, kwargs))
        return 1


async def test_vex_import_ignores_an_id_that_is_a_query_operator() -> None:
    repo = FakeFindingRepo()
    service = VexService(repo, None)  # type: ignore[arg-type]
    document = {"vulnerabilities": [{"id": {"$ne": None}, "analysis": {"state": "not_affected"}}]}
    await service.import_cyclonedx_vex(document, target_id="t")
    assert repo.calls == []


@pytest.mark.parametrize("language", ["en", "de"])
def test_scan_prompts_mark_findings_as_data(language: str) -> None:
    system, _ = ai_service._build_scan_prompts(
        {"target_name": "x", "summary": {}}, [], language, None, "openai"
    )
    assert system.endswith(ai_service._UNTRUSTED_DATA_RULE)
