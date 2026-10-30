"""The sidecar answers only to the backend once a secret is set."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main

SECRET = "s3cret"
SCANNER_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(main, "_SCANNER_SECRET", SECRET)
    return TestClient(main.app)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/stats"),
        ("get", "/version"),
        ("post", "/check"),
        ("post", "/prepare-source"),
        ("post", "/cleanup-source"),
        ("post", "/scan"),
    ],
)
@pytest.mark.parametrize("headers", [{}, {"X-Scanner-Secret": "wrong"}])
def test_every_route_needs_the_secret(client: TestClient, method: str, path: str, headers: dict[str, str]) -> None:
    assert client.request(method, path, headers=headers, json={}).status_code == 401


def test_a_new_route_is_covered_without_asking() -> None:
    # The gate sits on the app, so nobody has to remember it on the next route.
    assert any(d.dependency is main._require_scanner_secret for d in main.app.router.dependencies)


def test_the_right_secret_passes(client: TestClient) -> None:
    assert client.get("/stats", headers={"X-Scanner-Secret": SECRET}).status_code == 200


def test_health_stays_open_for_container_probes(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_without_a_secret_the_sidecar_behaves_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "_SCANNER_SECRET", "")
    assert TestClient(main.app).get("/stats").status_code == 200


def test_scanners_do_not_inherit_the_secret() -> None:
    code = "import os, app.main; assert 'SCA_SCANNER_SECRET' not in os.environ; assert app.main._SCANNER_SECRET == 'x'"
    env = {**os.environ, "SCA_SCANNER_SECRET": "x"}
    subprocess.run([sys.executable, "-c", code], cwd=SCANNER_ROOT, env=env, check=True, capture_output=True)
