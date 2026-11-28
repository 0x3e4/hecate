"""POST /scans/upload: a source ZIP as a multipart file instead of base64 in JSON.

A proxy's body limit (Cloudflare: 100 MB) counts the request, and base64 makes
it a third larger than the archive, so the UI and pipelines send the file itself.
"""
from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import scans as scans_api
from app.core import auth_throttle
from app.core.config import settings
from app.services.scan_service import get_scan_service

PASSWORD = "admin-password"
API_KEY = "ci-key-0123456789"
ZIP = b"PK\x03\x04" + b"x" * 100


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    async def submit_scan(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {
            "scan_id": "scan-1",
            "target_id": "check:1",
            "status": "pending",
            "findings_count": 0,
            "sbom_component_count": 0,
            "summary": {},
            "check": True,
        }

    async def get_target(_target_id: str) -> None:
        return None

    service = SimpleNamespace(submit_scan=submit_scan, target_repo=SimpleNamespace(get=get_target))
    monkeypatch.setattr(settings, "sca_enabled", True)
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(settings, "sca_api_key", API_KEY)
    monkeypatch.setattr(settings, "sca_source_archive_max_bytes", 1024)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.include_router(scans_api.router, prefix="/scans")
    app.dependency_overrides[get_scan_service] = lambda: service
    return TestClient(app), calls


def _upload(client: TestClient, data: bytes = ZIP, name: str = "moonli-app.zip", **kwargs: Any):
    return client.post("/scans/upload", files={"file": (name, data, "application/zip")}, **kwargs)


def test_upload_runs_a_check_with_the_file_as_archive(client) -> None:
    http, calls = client
    response = _upload(
        http, params={"scanners": "trivy,grype"}, headers={"X-System-Password": PASSWORD},
    )
    assert response.status_code == 201, response.text
    assert response.json()["check"] is True
    (call,) = calls
    assert base64.b64decode(call["source_archive_base64"]) == ZIP
    assert call["one_time"] is True
    assert call["target_type"] == "source_repo"
    assert call["target"] == "moonli-app"
    assert call["scanners"] == ["trivy", "grype"]
    assert call["source"] == "manual"


def test_target_name_and_repeated_scanner_params(client) -> None:
    http, calls = client
    response = _upload(
        http,
        params=[("targetName", "  My app "), ("scanners", "syft"), ("scanners", "trivy")],
        headers={"X-System-Password": PASSWORD},
    )
    assert response.status_code == 201, response.text
    assert calls[0]["target"] == "My app"
    assert calls[0]["scanners"] == ["syft", "trivy"]


def test_pipeline_key_opens_it_and_marks_ci(client) -> None:
    http, calls = client
    response = _upload(http, params={"commitSha": "abc123"}, headers={"X-API-Key": API_KEY})
    assert response.status_code == 201, response.text
    assert calls[0]["source"] == "ci_cd"
    assert calls[0]["commit_sha"] == "abc123"


def test_wrong_key_does_not_fall_through_to_the_password(client) -> None:
    http, calls = client
    response = _upload(http, headers={"X-API-Key": "wrong", "X-System-Password": PASSWORD})
    assert response.status_code == 401
    assert not calls


def test_no_credential_is_refused(client) -> None:
    http, calls = client
    assert _upload(http).status_code == 401
    assert not calls


def test_limits(client) -> None:
    http, calls = client
    headers = {"X-System-Password": PASSWORD}
    assert _upload(http, data=b"x" * 1025, headers=headers).status_code == 413
    assert _upload(http, data=b"", headers=headers).status_code == 400
    assert _upload(http, params={"scanners": "nope"}, headers=headers).status_code == 400
    assert not calls
