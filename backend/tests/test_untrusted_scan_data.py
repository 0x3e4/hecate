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


@pytest.mark.parametrize("state", [["not_affected"], {"x": 1}, 7, None])
async def test_vex_import_skips_a_state_that_is_not_a_string(state: Any) -> None:
    repo = FakeFindingRepo()
    service = VexService(repo, None)  # type: ignore[arg-type]
    document = {"vulnerabilities": [{"id": "CVE-2026-1", "analysis": {"state": state}}]}

    result = await service.import_cyclonedx_vex(document, target_id="t")

    assert repo.calls == []
    assert result["skipped"] == 1


@pytest.mark.parametrize("justification", [{"$set": 1}, ["code_not_present"], 42])
async def test_vex_import_stores_only_text_as_justification(justification: Any) -> None:
    repo = FakeFindingRepo()
    service = VexService(repo, None)  # type: ignore[arg-type]
    document = {"vulnerabilities": [{"id": "CVE-2026-1", "analysis": {"state": "not_affected", "justification": justification}}]}

    await service.import_cyclonedx_vex(document, target_id="t")

    assert repo.calls[0][1]["vex_justification"] is None


async def test_vex_import_caps_a_long_justification() -> None:
    repo = FakeFindingRepo()
    service = VexService(repo, None)  # type: ignore[arg-type]
    document = {"vulnerabilities": [{"id": "CVE-2026-1", "analysis": {"state": "not_affected", "detail": "x" * 50_000}}]}

    await service.import_cyclonedx_vex(document, target_id="t")

    assert len(repo.calls[0][1]["vex_justification"]) == 2000


async def test_vex_import_keeps_the_detail_next_to_the_justification() -> None:
    repo = FakeFindingRepo()
    service = VexService(repo, None)  # type: ignore[arg-type]
    analysis = {"state": "not_affected", "justification": "code_not_reachable", "detail": "Only git uses libcurl."}
    document = {"vulnerabilities": [{"id": "CVE-2026-1", "analysis": analysis}]}

    await service.import_cyclonedx_vex(document, target_id="t")

    kwargs = repo.calls[0][1]
    assert kwargs["vex_justification"] == "code_not_reachable"
    assert kwargs["vex_detail"] == "Only git uses libcurl."


class FakeVexScanRepo:
    async def get(self, _scan_id: str) -> dict[str, Any]:
        return {"target_name": "t"}


class FakeVexFindingRepo:
    async def get_vex_findings_by_scan(self, _scan_id: str) -> list[dict[str, Any]]:
        return [
            {"vulnerability_id": "CVE-2026-1", "vex_status": "affected", "package_name": "a", "package_version": "1"},
            {"vulnerability_id": "CVE-2026-2", "vex_status": "under_investigation", "package_name": "b", "package_version": "2"},
        ]


async def test_vex_export_uses_cyclonedx_states() -> None:
    service = VexService(FakeVexFindingRepo(), FakeVexScanRepo())  # type: ignore[arg-type]

    document = await service.export_cyclonedx_vex("s")

    affected, triage = document["vulnerabilities"]
    # CycloneDX knows "exploitable", not "affected"; version statuses have their own enum.
    assert affected["analysis"]["state"] == "exploitable"
    assert affected["affects"][0]["versions"][0]["status"] == "affected"
    assert triage["analysis"]["state"] == "in_triage"
    assert triage["affects"][0]["versions"][0]["status"] == "unknown"


class FakeInventoryRepo:
    def __init__(self) -> None:
        self.inserted: list[dict[str, Any]] = []

    async def get(self, _item_id: str) -> None:
        return None

    async def insert(self, _item_id: str, data: dict[str, Any]) -> None:
        self.inserted.append(data)


async def test_inventory_restore_skips_rows_with_wrong_types() -> None:
    from app.schemas.backup import InventoryBackupPayload
    from app.services.backup_service import BackupService

    repo = FakeInventoryRepo()
    service = BackupService(None, None, repo)  # type: ignore[arg-type]
    service._record_restore = _no_history  # type: ignore[method-assign]
    good = {"name": "nginx", "vendor_slug": "f5", "product_slug": "nginx", "version": "1.27.0"}
    payload = InventoryBackupPayload.model_validate({
        "metadata": {"dataset": "inventory", "exportedAt": "2026-11-02T00:00:00Z", "itemCount": 3},
        "items": [
            {**good, "name": ["nginx"]},
            {**good, "deployment": "mars", "environment": {"x": 1}, "owner": 5, "notes": ["n"]},
            good,
        ],
    })

    summary = await service.restore_inventory(payload)

    assert summary.skipped == 1
    assert summary.inserted == 2
    hostile = repo.inserted[0]
    assert hostile["deployment"] == "onprem"
    assert hostile["environment"] == "prod"
    assert hostile["owner"] is None and hostile["notes"] is None


async def _no_history(*_args: Any, **_kwargs: Any) -> None:
    return None


@pytest.mark.parametrize("language", ["en", "de"])
def test_scan_prompts_mark_findings_as_data(language: str) -> None:
    system, _ = ai_service._build_scan_prompts(
        {"target_name": "x", "summary": {}}, [], language, None, "openai"
    )
    assert system.endswith(ai_service._UNTRUSTED_DATA_RULE)
