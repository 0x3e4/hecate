"""TruffleHog secret verification per scan target: stored on the target, kept
across re-scan upserts, sent to the sidecar only when the target overrides it."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1 import scans as scans_api
from app.models.scan import ScanTargetDocument
from app.schemas.scan import ScanTargetUpdateRequest
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services import scan_service as scan_service_module
from app.services.scan_service import ScanService

from tests.fake_mongo import FakeCollection

TARGET_ID = "https://github.com/example/repo"


def _doc() -> ScanTargetDocument:
    return ScanTargetDocument(target_id=TARGET_ID, type="source_repo", name="repo", scanners=["trufflehog"])


@pytest.mark.parametrize("verify", [True, False])
async def test_choice_survives_the_next_scans_upsert(verify: bool) -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())
    assert await repo.update_trufflehog_verification(TARGET_ID, verify)

    await repo.upsert(_doc())

    assert (await repo.get(TARGET_ID))["trufflehog_verification"] is verify


async def test_none_resets_to_the_scanner_default() -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())
    await repo.update_trufflehog_verification(TARGET_ID, False)

    assert await repo.update_trufflehog_verification(TARGET_ID, None)

    assert (await repo.get(TARGET_ID)).get("trufflehog_verification") is None
    assert not await repo.update_trufflehog_verification("unknown", True)


def _service(repo: ScanTargetRepository) -> ScanService:
    service = ScanService.__new__(ScanService)
    service.target_repo = repo

    async def get_target(target_id: str) -> dict[str, Any] | None:
        return await repo.get(target_id)

    service.get_target = get_target  # type: ignore[method-assign]
    return service


async def test_patch_sets_clears_and_rejects() -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(_doc())
    service = _service(repo)

    def body(**fields: Any) -> ScanTargetUpdateRequest:
        return ScanTargetUpdateRequest.model_validate(fields)

    response = await scans_api.update_target(TARGET_ID, body(trufflehogVerification=False), None, service)
    assert response.trufflehog_verification is False
    assert response.model_dump(by_alias=True)["trufflehogVerification"] is False

    # A PATCH that doesn't mention the field leaves it alone.
    response = await scans_api.update_target(TARGET_ID, body(group="shop"), None, service)
    assert response.trufflehog_verification is False

    response = await scans_api.update_target(TARGET_ID, body(trufflehogVerification=None), None, service)
    assert response.trufflehog_verification is None

    with pytest.raises(ValidationError):
        body(trufflehogVerification="maybe")
    with pytest.raises(HTTPException) as exc:
        await scans_api.update_target(TARGET_ID, body(name="   "), None, service)
    assert exc.value.status_code == 400


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


@pytest.mark.parametrize(("verify", "expected"), [(None, "absent"), (False, False), (True, True)])
async def test_sidecar_payload_carries_only_an_override(monkeypatch: pytest.MonkeyPatch, verify, expected) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(scan_service_module, "scanner_client", lambda **_kw: _Client(sent))
    service = ScanService.__new__(ScanService)

    await service._call_scanner_sidecar(
        target=TARGET_ID, target_type="source_repo", scanners=["trufflehog"], trufflehog_verification=verify
    )

    assert sent[0].get("trufflehogVerification", "absent") == expected
