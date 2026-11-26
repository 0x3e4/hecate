"""Hosts and Kubernetes nodes push SBOMs: an sbom:import token, kind and exposure
on the target, distro-aware matching through the sidecar, exposed targets first."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.core.write_auth import require_target_write_sbom_import
from app.models.scan import ScanTargetDocument
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services import scan_service as scan_service_module
from app.services.api_token_service import ApiTokenService
from app.services.scan_service import ScanService, get_scan_service

from tests.fake_mongo import FakeCollection
from tests.test_api_tokens import FakeRepo

PASSWORD = "admin-password"


def _sbom(name: str = "web-01") -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": name}}, "components": []}


# --- the sbom:import token ------------------------------------------------------------


@pytest.fixture
def gate_client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, ApiTokenService]:
    tokens = ApiTokenService(FakeRepo())  # type: ignore[arg-type]

    async def get_tokens() -> ApiTokenService:
        return tokens

    targets = {
        "sbom-import-web-01": {"_id": "sbom-import-web-01", "type": "sbom-import"},
        "repo-x": {"_id": "repo-x", "type": "source_repo"},
    }

    async def get_target(target_id: str) -> dict[str, Any] | None:
        return targets.get(target_id)

    fake_service = SimpleNamespace(target_repo=SimpleNamespace(get=get_target))
    monkeypatch.setattr(write_auth, "get_api_token_service", get_tokens)
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.dependency_overrides[get_scan_service] = lambda: fake_service

    @app.post("/import-sbom", dependencies=[Depends(require_target_write_sbom_import)])
    async def imported() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app), tokens


async def _token(tokens: ApiTokenService, *scopes: str) -> str:
    from app.schemas.api_token import ApiTokenCreateRequest

    created = await tokens.create_token(ApiTokenCreateRequest(name="hosts", scopes=list(scopes)))
    return created.token


async def test_sbom_token_writes_new_and_sbom_import_targets(gate_client) -> None:
    client, tokens = gate_client
    key = {"X-API-Key": await _token(tokens, "sbom:import")}

    assert client.post("/import-sbom", json={"sbom": _sbom("web-02")}, headers=key).status_code == 200
    assert client.post("/import-sbom", json={"sbom": _sbom("web-01")}, headers=key).status_code == 200
    # Never a repository or image target.
    refused = client.post("/import-sbom", json={"sbom": _sbom(), "targetId": "repo-x"}, headers=key)
    assert refused.status_code == 403


async def test_other_scopes_and_junk_are_refused(gate_client) -> None:
    client, tokens = gate_client
    scan_only = {"X-API-Key": await _token(tokens, "scan:submit")}
    assert client.post("/import-sbom", json={"sbom": _sbom()}, headers=scan_only).status_code == 403
    assert client.post("/import-sbom", json={"sbom": _sbom()}, headers={"X-API-Key": "nope"}).status_code == 401
    # Without a key the password gate applies as before.
    assert client.post("/import-sbom", json={"sbom": _sbom("new")}).status_code == 401
    assert client.post("/import-sbom", json={"sbom": _sbom("new")}, headers={"X-System-Password": PASSWORD}).status_code == 200


# --- kind and exposure ----------------------------------------------------------------


async def test_classification_is_kept_across_upserts_and_cleared_by_none() -> None:
    repo = ScanTargetRepository(FakeCollection())
    await repo.upsert(ScanTargetDocument(target_id="t", type="sbom-import", name="t", kind="host", exposure="internet"))
    await repo.upsert(ScanTargetDocument(target_id="t", type="sbom-import", name="t"))
    stored = await repo.get("t")
    assert (stored["kind"], stored["exposure"]) == ("host", "internet")

    assert await repo.update_classification("t", {"exposure": None, "kind": "kubernetes-node"})
    stored = await repo.get("t")
    assert stored.get("exposure") is None and stored["kind"] == "kubernetes-node"


async def test_affected_rows_carry_classification_internet_first() -> None:
    targets = FakeCollection([
        {"_id": "a", "kind": "host", "exposure": "internal"},
        {"_id": "b", "kind": "kubernetes-node", "exposure": "internet"},
    ])
    service = ScanService.__new__(ScanService)
    service.target_repo = SimpleNamespace(collection=targets)
    rows = [{"targetId": "a", "packageName": "nginx"}, {"targetId": "b", "packageName": "nginx"}, {"targetId": "c"}]

    out = await service._with_target_classification(rows)

    assert [r["targetId"] for r in out] == ["b", "a", "c"]
    assert out[0]["exposure"] == "internet" and out[0]["kind"] == "kubernetes-node"
    assert out[2]["kind"] is None


# --- distro-aware matching through the sidecar ----------------------------------------


class _Response:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.body


class _Client:
    def __init__(self, sent: list[dict[str, Any]], body: dict[str, Any] | Exception) -> None:
        self.sent, self.body = sent, body

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def post(self, url: str, json: dict[str, Any]) -> _Response:
        self.sent.append({"url": url, **json})
        if isinstance(self.body, Exception):
            raise self.body
        return _Response(self.body)


GRYPE_REPORT = {
    "matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "fix": {"versions": ["1.22.1-9+deb12u3"]}},
        "artifact": {"name": "nginx", "version": "1.22.1-9+deb12u2", "type": "deb",
                     "purl": "pkg:deb/debian/nginx@1.22.1-9%2Bdeb12u2"},
    }],
}


async def test_imported_sbom_is_matched_by_the_sidecar(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    body = {"results": [{"scanner": "grype", "format": "grype-json", "report": GRYPE_REPORT, "error": None}]}
    monkeypatch.setattr(scan_service_module, "scanner_client", lambda **_kw: _Client(sent, body))
    monkeypatch.setattr(settings, "sca_sbom_import_scanners", "grype")
    monkeypatch.setattr(settings, "sca_enabled", True)
    service = ScanService.__new__(ScanService)

    findings, answered = await service._scan_imported_sbom(_sbom(), "scan-1", "sbom-import-web-01")

    assert sent[0]["url"].endswith("/scan-sbom") and sent[0]["scanners"] == ["grype"]
    assert answered == ["grype"]
    assert [(f.vulnerability_id, f.package_name, f.scanner) for f in findings] == [
        ("CVE-2026-0001", "nginx", "grype"),
    ]


async def test_sidecar_failure_keeps_the_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_service_module, "scanner_client", lambda **_kw: _Client([], RuntimeError("down")))
    monkeypatch.setattr(settings, "sca_enabled", True)
    service = ScanService.__new__(ScanService)
    assert await service._scan_imported_sbom(_sbom(), "s", "t") == ([], [])

    monkeypatch.setattr(settings, "sca_sbom_import_scanners", "")
    assert await service._scan_imported_sbom(_sbom(), "s", "t") == ([], [])


def test_os_package_matches_give_way_to_the_scanner() -> None:
    from app.services.scan_service import drop_os_package_matches

    components = [
        SimpleNamespace(name="nginx", version="1.22.1-9+deb12u2", purl="pkg:deb/debian/nginx@1.22.1-9%2Bdeb12u2"),
        SimpleNamespace(name="openssl", version="3.0.15-1", purl="pkg:rpm/redhat/openssl@3.0.15-1"),
        SimpleNamespace(name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20"),
        SimpleNamespace(name="mystery", version="1.0", purl=None),
    ]
    findings = [
        SimpleNamespace(package_name="nginx", package_version="1.22.1-9+deb12u2"),
        SimpleNamespace(package_name="openssl", package_version="3.0.15-1"),
        SimpleNamespace(package_name="lodash", package_version="4.17.20"),
        SimpleNamespace(package_name="mystery", package_version="1.0"),
    ]

    kept = drop_os_package_matches(findings, components)

    # Language packages and purl-less components keep Hecate's match.
    assert [f.package_name for f in kept] == ["lodash", "mystery"]
