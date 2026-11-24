"""A scan target without external lookups: nothing about the scanned code
(package names, module paths, found secrets) leaves the network."""
from __future__ import annotations

import json

import pytest

from app import scanners
from app.malware_detector import typosquatting


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict] = []

    async def fake_run_command(cmd, timeout=600, env=None):
        calls.append({"cmd": cmd, "env": env})
        if cmd[0] == "osv-scanner":
            return json.dumps({"results": []}), "", 0
        if "app.analyze_cli" in cmd:
            return json.dumps({"sbom": {"components": [{"name": "left-pad", "version": "1.0.0"}]}, "findings": []}), "", 0
        return "{}", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    return calls


@pytest.mark.parametrize("scanner", ["trivy", "syft", "grype"])
async def test_image_tools_get_the_offline_switches(recorded, tmp_path, scanner):
    await scanners.run_scanner(scanner, "x", "source_repo", source_dir=str(tmp_path), no_external_lookups=True)
    env = recorded[-1]["env"]
    assert env["TRIVY_OFFLINE_SCAN"] == "true"
    assert env["GRYPE_EXTERNAL_SOURCES_ENABLE"] == "false"
    assert env["SYFT_JAVA_USE_NETWORK"] == "false"


async def test_tools_keep_their_environment_by_default(recorded, tmp_path):
    await scanners.run_scanner("trivy", "x", "source_repo", source_dir=str(tmp_path))
    assert recorded[-1]["env"] is None
    # The switch is per call: the next scan of another target is online again.
    await scanners.run_scanner("trivy", "x", "source_repo", source_dir=str(tmp_path), no_external_lookups=True)
    await scanners.run_scanner("trivy", "x", "source_repo", source_dir=str(tmp_path))
    assert recorded[-1]["env"] is None


async def test_osv_scanner_matches_against_a_local_database(recorded, tmp_path, monkeypatch):
    pinned: list[str] = []

    async def fake_pin(scan_dir):
        pinned.append(scan_dir)
        return []

    monkeypatch.setattr(scanners, "_pin_requirements_files", fake_pin)
    monkeypatch.delenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", raising=False)

    await scanners.run_scanner("osv-scanner", "x", "source_repo", source_dir=str(tmp_path), no_external_lookups=True)
    cmd, env = recorded[-1]["cmd"], recorded[-1]["env"]
    assert "--offline-vulnerabilities" in cmd and "--download-offline-databases" in cmd
    assert cmd[-1] == str(tmp_path)
    assert env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == "/tmp/hecate-osv-db"
    assert pinned == []  # no PyPI lookups for unpinned requirements

    await scanners.run_scanner("osv-scanner", "x", "source_repo", source_dir=str(tmp_path))
    assert "--offline-vulnerabilities" not in recorded[-1]["cmd"]
    assert pinned == [str(tmp_path)]


async def test_hecate_analyzer_skips_provenance(recorded, tmp_path, monkeypatch):
    asked: list[int] = []

    async def fake_provenance(components):
        asked.append(len(components))

    monkeypatch.setattr(scanners, "check_provenance_batch", fake_provenance)

    await scanners.run_scanner("hecate", "x", "source_repo", source_dir=str(tmp_path), no_external_lookups=True)
    assert asked == []
    assert recorded[-1]["env"]["HECATE_NO_EXTERNAL_LOOKUPS"] == "1"

    await scanners.run_scanner("hecate", "x", "source_repo", source_dir=str(tmp_path))
    assert asked == [1]


async def test_trufflehog_never_verifies(recorded, tmp_path, monkeypatch):
    monkeypatch.delenv("TRUFFLEHOG_NO_VERIFICATION", raising=False)
    await scanners.run_scanner(
        "trufflehog", "x", "source_repo", source_dir=str(tmp_path),
        trufflehog_verification=True, no_external_lookups=True,
    )
    assert "--no-verification" in recorded[-1]["cmd"]


def test_govulncheck_downloads_no_modules(tmp_path):
    token = scanners._no_external_lookups.set(True)
    try:
        env = scanners._govulncheck_env(str(tmp_path))
    finally:
        scanners._no_external_lookups.reset(token)
    assert env["GOPROXY"] == "off"
    assert env["GOSUMDB"] == "off"
    assert scanners._govulncheck_env(str(tmp_path))["GOPROXY"] != "off"


def test_typosquat_check_does_not_ask_the_registry(monkeypatch):
    def no_network(*_a, **_k):
        raise AssertionError("registry contacted")

    monkeypatch.setattr(typosquatting.urllib.request, "urlopen", no_network)
    monkeypatch.setattr(typosquatting, "_registry_cache", {})
    monkeypatch.setattr(typosquatting, "_load_cache", lambda: None)
    monkeypatch.setenv("HECATE_NO_EXTERNAL_LOOKUPS", "1")

    assert typosquatting._package_exists_in_registry("reqeusts", "pypi") is None
    note = typosquatting._registry_note("similar", None)
    assert "registry not consulted" in note


def test_typosquat_candidate_is_reported_with_low_confidence(monkeypatch, tmp_path):
    monkeypatch.setenv("HECATE_NO_EXTERNAL_LOOKUPS", "1")
    monkeypatch.setattr(typosquatting, "_registry_cache", {})
    monkeypatch.setattr(typosquatting, "_load_cache", lambda: None)
    (tmp_path / "requirements.txt").write_text("reqests==2.0\n")

    detections = typosquatting.detect_typosquatting(str(tmp_path))

    hits = [d for d in detections if d.package_name == "reqests"]
    assert hits and hits[0].confidence == "low"
    assert "registry not consulted" in hits[0].evidence
