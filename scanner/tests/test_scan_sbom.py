"""/scan-sbom: an imported SBOM (a host, a Kubernetes node) matched by Grype and/or Trivy."""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from app import main, scanners
from app.models import ScannerResult

SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "nginx", "version": "1.22.1-9"}]}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    seen: list[dict] = []

    async def fake_run_sbom_scanner(name: str, path: str) -> ScannerResult:
        with open(path, encoding="utf-8") as fh:
            seen.append({"name": name, "path": path, "sbom": json.load(fh)})
        return ScannerResult(scanner=name, format=f"{name}-json", report={"matches": []})

    monkeypatch.setattr(main, "run_sbom_scanner", fake_run_sbom_scanner)
    c = TestClient(main.app)
    c.seen = seen
    return c


def test_the_sbom_reaches_each_scanner_and_is_removed(client) -> None:
    response = client.post("/scan-sbom", json={"sbom": SBOM, "scanners": ["grype", "trivy", "grype"]})

    assert response.status_code == 200
    assert [r["scanner"] for r in response.json()["results"]] == ["grype", "trivy"]
    assert all(entry["sbom"] == SBOM for entry in client.seen)
    assert not os.path.exists(client.seen[0]["path"])


@pytest.mark.parametrize("scanners_", [["semgrep"], ["grype", "hecate"], []])
def test_only_sbom_scanners(client, scanners_) -> None:
    assert client.post("/scan-sbom", json={"sbom": SBOM, "scanners": scanners_}).status_code == 400


@pytest.mark.parametrize(
    ("name", "expected"),
    [("grype", ["grype", "sbom:/x/sbom.json", "-o", "json", "--quiet"]),
     ("trivy", ["trivy", "sbom", "--format", "json", "--quiet", "/x/sbom.json"])],
)
async def test_scanner_commands(monkeypatch: pytest.MonkeyPatch, name, expected) -> None:
    calls: list[list[str]] = []

    async def fake_run_command(cmd, timeout=600, env=None):
        calls.append(cmd)
        return "{}", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    result = await scanners.run_sbom_scanner(name, "/x/sbom.json")

    assert calls == [expected]
    assert result.error is None and result.format == f"{name}-json"
