"""A scan target without external lookups: kept on the target, set through the
PATCH route and sent to the sidecar with every scanner call."""
from __future__ import annotations

from typing import Any

import pytest

from app.api.v1 import scans as scans_api
from app.models.scan import ScanTargetDocument
from app.repositories.scan_target_repository import ScanTargetRepository
from app.schemas.scan import ScanTargetUpdateRequest
from app.services import scan_service as scan_service_module
from app.services.scan_service import ScanService

from tests.fake_mongo import FakeCollection

TARGET_ID = "https://git.internal.example/team/app"


def _doc() -> ScanTargetDocument:
    return ScanTargetDocument(target_id=TARGET_ID, type="source_repo", name="app", scanners=["trivy"])


async def test_setting_survives_the_next_scans_upsert() -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())
    assert await repo.update_no_external_lookups(TARGET_ID, True)

    await repo.upsert(_doc())
    assert (await repo.get(TARGET_ID))["no_external_lookups"] is True

    assert await repo.update_no_external_lookups(TARGET_ID, False)
    assert (await repo.get(TARGET_ID))["no_external_lookups"] is False


async def test_patch_turns_it_on_and_off() -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())
    service = ScanService.__new__(ScanService)
    service.target_repo = repo

    async def get_target(target_id: str) -> dict[str, Any] | None:
        return await repo.get(target_id)

    service.get_target = get_target  # type: ignore[method-assign]

    def body(**fields: Any) -> ScanTargetUpdateRequest:
        return ScanTargetUpdateRequest.model_validate(fields)

    response = await scans_api.update_target(TARGET_ID, body(noExternalLookups=True), None, service)
    assert response.model_dump(by_alias=True)["noExternalLookups"] is True
    # Another field alone leaves it as it is.
    response = await scans_api.update_target(TARGET_ID, body(group="apps"), None, service)
    assert response.no_external_lookups is True
    response = await scans_api.update_target(TARGET_ID, body(noExternalLookups=False), None, service)
    assert response.no_external_lookups is False


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"results": [], "metadata": {}}


class _Client:
    def __init__(self, sent: list[dict[str, Any]]) -> None:
        self.sent = sent

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def post(self, _url: str, json: dict[str, Any]) -> _Response:
        self.sent.append(json)
        return _Response()


@pytest.mark.parametrize(("enabled", "expected"), [(False, "absent"), (True, True)])
async def test_sidecar_gets_the_flag(monkeypatch: pytest.MonkeyPatch, enabled: bool, expected) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(scan_service_module, "scanner_client", lambda **_kw: _Client(sent))
    service = ScanService.__new__(ScanService)

    await service._call_scanner_sidecar(
        target=TARGET_ID, target_type="source_repo", scanners=["osv-scanner"], no_external_lookups=enabled
    )

    assert sent[0].get("noExternalLookups", "absent") == expected
