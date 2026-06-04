"""Tests for the provenance URL hygiene + per-scanner timeout fixes.

Covers:
- provenance._is_checkable_version  (skip non-concrete versions before any HTTP)
- provenance._check_pypi            (PEP 740 via JSON metadata, no /integrity/ 404)
- hecate_analyzer._is_registry_npm_version (drop catalog:/workspace:/etc. specifiers)
- scanners._scanner_timeout         (env override + hyphen normalisation)
"""
from __future__ import annotations

import pytest

from app.provenance import (
    ProvenanceResult,
    _check_pypi,
    _is_checkable_version,
)
from app.hecate_analyzer import _is_registry_npm_version
from app.scanners import _scanner_timeout


# ---------------------------------------------------------------------------
# provenance._is_checkable_version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["1.2.3", "v1.2.3", "2026.4.0", "1.0.0-beta.9", "4.17.21"])
def test_checkable_version_accepts_concrete(version: str) -> None:
    assert _is_checkable_version(version) is True


@pytest.mark.parametrize(
    "version",
    [
        "",
        "*",
        "x",
        "latest",
        "-",
        "any",
        "workspace:*",
        "catalog:frontend",
        "catalog:e2e",
        "npm:alias@1.2.3",
        "link:../local",
        "file:./pkg",
        "portal:../pkg",
        "git+ssh://git@github.com/o/r.git",
        "https://example.com/pkg.tgz",
    ],
)
def test_checkable_version_rejects_specifiers(version: str) -> None:
    assert _is_checkable_version(version) is False


# ---------------------------------------------------------------------------
# hecate_analyzer._is_registry_npm_version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec", ["1.2.3", "^1.2.3", "~2.0.0", ">=1.0.0", "v3.1.4"])
def test_registry_npm_version_keeps_real_specs(spec: str) -> None:
    # Ranges carry information and never contain ':', so they are kept; the
    # provenance layer normalises them down before any lookup.
    assert _is_registry_npm_version(spec) is True


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "*",
        "x",
        "latest",
        "workspace:*",
        "workspace:^1.0.0",
        "catalog:frontend",
        "catalog:",
        "npm:other@1.0.0",
        "link:../sibling",
        "file:./local",
        "portal:../x",
        "git+https://github.com/o/r.git",
        "github:owner/repo",
        "git@github.com:o/r.git",
        "./local/path",
        "../up/one",
        "/abs/path",
    ],
)
def test_registry_npm_version_drops_unresolved(spec: str) -> None:
    assert _is_registry_npm_version(spec) is False


# ---------------------------------------------------------------------------
# provenance._check_pypi  (reads JSON metadata, never hits /integrity/)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Minimal async httpx.AsyncClient stand-in that records GET calls."""

    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self._status_code = status_code
        self.calls: list[str] = []

    async def get(self, url: str, *args, **kwargs) -> _FakeResponse:
        self.calls.append(url)
        return _FakeResponse(self._status_code, self._payload)


@pytest.mark.asyncio
async def test_check_pypi_detects_pep740_from_urls() -> None:
    payload = {
        "info": {"project_urls": {"Source": "https://github.com/o/r"}},
        "urls": [
            {"filename": "pkg-1.0.0.tar.gz", "provenance": None},
            {"filename": "pkg-1.0.0-py3-none-any.whl",
             "provenance": "https://pypi.org/integrity/pkg/1.0.0/pkg-1.0.0-py3-none-any.whl/provenance"},
        ],
    }
    client = _FakeClient(payload)
    result = await _check_pypi(client, "pkg", "1.0.0")
    assert result.verified is True
    assert result.attestation_type == "pep740"
    # Exactly one GET (the JSON metadata) — no separate /integrity/ request.
    assert len(client.calls) == 1
    assert client.calls[0] == "https://pypi.org/pypi/pkg/1.0.0/json"


@pytest.mark.asyncio
async def test_check_pypi_no_attestation_falls_back_to_source_repo() -> None:
    payload = {
        "info": {"project_urls": {"Repository": "https://github.com/o/r"}},
        "urls": [{"filename": "pkg-2.2.2.tar.gz"}],  # no provenance key
    }
    client = _FakeClient(payload)
    result = await _check_pypi(client, "colorclass", "2.2.2")
    assert result.verified is False
    assert result.source_repo == "https://github.com/o/r"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_check_pypi_404_returns_unknown() -> None:
    client = _FakeClient({}, status_code=404)
    result = await _check_pypi(client, "missing", "9.9.9")
    assert result == ProvenanceResult()


# ---------------------------------------------------------------------------
# scanners._scanner_timeout
# ---------------------------------------------------------------------------

def test_scanner_timeout_default_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("GRYPE_TIMEOUT_SECONDS", raising=False)
    assert _scanner_timeout("grype", default=1200) == 1200


def test_scanner_timeout_reads_env_override(monkeypatch) -> None:
    monkeypatch.setenv("GRYPE_TIMEOUT_SECONDS", "1800")
    assert _scanner_timeout("grype", default=1200) == 1800


def test_scanner_timeout_hyphen_normalised(monkeypatch) -> None:
    # osv-scanner -> OSV_SCANNER_TIMEOUT_SECONDS (hyphen normalised to underscore)
    monkeypatch.setenv("OSV_SCANNER_TIMEOUT_SECONDS", "900")
    assert _scanner_timeout("osv-scanner") == 900


@pytest.mark.parametrize("bad", ["0", "-5", "abc", ""])
def test_scanner_timeout_invalid_falls_back(monkeypatch, bad: str) -> None:
    monkeypatch.setenv("SYFT_TIMEOUT_SECONDS", bad)
    assert _scanner_timeout("syft", default=600) == 600
