"""Regression tests for the confirmed findings of the 2026-11 security audit.

1. The SBOM import gate authorized one target while the import wrote another.
2. A repeated scanner name fanned out one sidecar scan per entry.
3. The malware-feed response cache grew with every distinct anonymous query.
4. A credentialed repo URL passed to MCP trigger_scan landed in the public audit log.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from fastapi import Depends, FastAPI, File, UploadFile
from fastapi.testclient import TestClient

from app.api.v1 import malware
from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.core.passwords import hash_password
from app.mcp import audit
from app.services.scan_service import ScanService, get_scan_service, resolve_sbom_import_target

PASSWORD = "admin-password"
MINE = "mine-password"
VICTIM = "victim-password"


def _cyclonedx(name: str) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": name}}, "components": []}


# --------------------------------------------------------------------------
# 1. SBOM import: the gate authorizes the target the import writes
# --------------------------------------------------------------------------

class _Targets:
    def __init__(self) -> None:
        self.docs = {
            "sbom-import-mine": {"target_id": "sbom-import-mine", "write_password_hash": hash_password(MINE, iterations=10)},
            "sbom-import-victim": {"target_id": "sbom-import-victim", "write_password_hash": hash_password(VICTIM, iterations=10)},
        }

    async def get(self, target_id: str) -> dict[str, Any] | None:
        return self.docs.get(target_id)


class _Service:
    def __init__(self) -> None:
        self.target_repo = _Targets()


@pytest.fixture
def gated(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    service = _Service()
    app.dependency_overrides[get_scan_service] = lambda: service

    @app.post("/import", dependencies=[Depends(write_auth.require_target_write_sbom_import)])
    async def imported() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/upload", dependencies=[Depends(write_auth.require_target_write_sbom_upload)])
    async def uploaded(file: UploadFile = File(...)) -> dict[str, str]:
        # The gate read the upload first; the handler must still get all of it.
        return {"name": json.loads(await file.read())["metadata"]["component"]["name"]}

    return TestClient(app)


@pytest.mark.parametrize(
    "body",
    [
        {"sbom": _cyclonedx("victim"), "targetName": "", "target_name": "mine"},
        {"sbom": _cyclonedx("victim"), "targetId": "", "target_id": "sbom-import-mine"},
        {"sbom": {"spdxVersion": "SPDX-2.3", "name": "victim", "packages": []}, "targetName": "", "target_name": "mine"},
    ],
)
def test_an_empty_alias_does_not_borrow_another_targets_password(gated: TestClient, body: dict[str, Any]) -> None:
    assert gated.post("/import", json=body, headers={"X-Target-Password": MINE}).status_code == 401
    assert gated.post("/import", json=body, headers={"X-Target-Password": VICTIM}).status_code == 200


def test_an_import_named_by_its_document_takes_that_targets_password(
    gated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = {"sbom": _cyclonedx("victim")}
    assert gated.post("/import", json=body).status_code == 401
    # Without a system password the old gate authorized "no target" and let this through.
    monkeypatch.setattr(settings, "system_password", "")
    assert gated.post("/import", json=body).status_code == 401
    assert gated.post("/import", json=body, headers={"X-Target-Password": VICTIM}).status_code == 200


def test_an_upload_named_by_its_file_takes_that_targets_password(gated: TestClient) -> None:
    files = {"file": ("bom.json", json.dumps(_cyclonedx("victim")), "application/json")}
    assert gated.post("/upload", files=files, headers={"X-Target-Password": MINE}).status_code == 401
    response = gated.post("/upload", files=files, headers={"X-Target-Password": VICTIM})
    assert response.status_code == 200
    assert response.json() == {"name": "victim"}


def test_the_gate_and_the_import_resolve_the_same_target() -> None:
    victim = _cyclonedx("victim")
    assert resolve_sbom_import_target(victim, None, "", "") == ("victim", "sbom-import-victim")
    assert resolve_sbom_import_target(victim, None, "Mine", None) == ("Mine", "sbom-import-mine")
    assert resolve_sbom_import_target({"metadata": {"component": {"name": 7}}}, "cyclonedx-json", None, None) == (
        "SBOM Import",
        "sbom-import-sbom-import",
    )


# --------------------------------------------------------------------------
# 2. Scan submission: one sidecar call per distinct, known scanner
# --------------------------------------------------------------------------

class _Recorder:
    def __init__(self) -> None:
        self.targets: list[Any] = []
        self.scans: list[Any] = []

    async def upsert(self, doc: Any) -> None:
        self.targets.append(doc)

    async def update_running_state(self, *_args: Any) -> None:
        return None

    async def insert(self, doc: Any) -> str:
        self.scans.append(doc)
        return "scan-1"


@pytest.fixture
def submit(monkeypatch: pytest.MonkeyPatch) -> tuple[ScanService, _Recorder, list[list[str]]]:
    recorder = _Recorder()
    service = ScanService(
        target_repo=recorder, scan_repo=recorder, finding_repo=None, sbom_repo=None, layer_repo=None, audit_service=None
    )
    dispatched: list[list[str]] = []

    async def background(**kwargs: Any) -> None:
        dispatched.append(kwargs["scanners"])

    monkeypatch.setattr(service, "_run_scan_background", background)
    return service, recorder, dispatched


async def test_repeated_scanners_run_once(submit: tuple[ScanService, _Recorder, list[list[str]]]) -> None:
    service, recorder, dispatched = submit
    await service.submit_scan(
        target="https://example.invalid/r.git", target_type="source_repo", scanners=["semgrep"] * 100 + ["trivy", "semgrep"]
    )
    await asyncio.sleep(0)
    assert dispatched == [["semgrep", "trivy"]]
    assert recorder.targets[0].scanners == ["semgrep", "trivy"]


@pytest.mark.parametrize("scanners", [["semgrep", "bogus"], []])
async def test_unknown_or_no_scanners_are_refused(
    submit: tuple[ScanService, _Recorder, list[list[str]]], scanners: list[str]
) -> None:
    service, recorder, dispatched = submit
    with pytest.raises(ValueError):
        await service.submit_scan(target="https://example.invalid/r.git", target_type="source_repo", scanners=scanners)
    assert recorder.targets == [] and dispatched == []


def test_the_request_schema_applies_the_same_scanner_rule() -> None:
    from pydantic import ValidationError

    from app.schemas.scan import SubmitScanRequest

    request = SubmitScanRequest(target="t", type="source_repo", scanners=["grype", "grype", "trivy"])
    assert request.scanners == ["grype", "trivy"]
    assert SubmitScanRequest(target="t", type="source_repo").scanners is None
    with pytest.raises(ValidationError):
        SubmitScanRequest(target="t", type="source_repo", scanners=["grype", "bogus"])


def test_a_blank_sbom_target_is_unset() -> None:
    from app.schemas.scan import ImportSbomRequest

    request = ImportSbomRequest.model_validate({"sbom": {}, "targetName": "  ", "target_name": "mine", "targetId": ""})
    assert request.target_name is None and request.target_id is None
    assert resolve_sbom_import_target(_cyclonedx("victim"), None, "  ", " ") == ("victim", "sbom-import-victim")


# --------------------------------------------------------------------------
# 3. Malware-feed caches stay bounded and drop expired entries
# --------------------------------------------------------------------------

def test_the_feed_cache_keeps_at_most_its_limit() -> None:
    from collections import OrderedDict

    cache: OrderedDict = OrderedDict()
    for n in range(1000):
        malware._cache_put(cache, ("", "", n, 500), n, ttl=60.0, max_entries=8)
    assert len(cache) == 8
    assert list(cache)[-1] == ("", "", 999, 500)


def test_expired_entries_leave_on_the_next_insert(monkeypatch: pytest.MonkeyPatch) -> None:
    import time
    from collections import OrderedDict

    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    cache: OrderedDict = OrderedDict()
    for n in range(5):
        malware._cache_put(cache, (n,), n, ttl=60.0, max_entries=100)
    now[0] += 61
    malware._cache_put(cache, ("fresh",), 0, ttl=60.0, max_entries=100)
    assert list(cache) == [("fresh",)]


# --------------------------------------------------------------------------
# 4. The audit log never stores URL credentials
# --------------------------------------------------------------------------

def test_url_credentials_are_masked_in_audit_inputs() -> None:
    inputs = {
        "target": "https://x-access-token:DUMMYTOKEN123@github.example/org/repo.git",
        "scanners": ["trivy"],
        "nested": {"urls": ["git://user:pw@host/r", "https://plain.example/x"]},
        "api_key": "hct_whatever",
    }
    redacted = audit._redact_sensitive(inputs)
    assert redacted["target"] == "https://***@github.example/org/repo.git"
    assert redacted["nested"] == {"urls": ["git://***@host/r", "https://plain.example/x"]}
    assert redacted["api_key"] == "***"
    assert "DUMMYTOKEN123" not in json.dumps(redacted)


async def test_a_logged_error_is_masked_too(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime

    recorded: list[dict[str, Any]] = []

    class _Audit:
        async def record_event(self, _job: str, **kwargs: Any) -> None:
            recorded.append(kwargs)

    async def get_audit() -> _Audit:
        return _Audit()

    monkeypatch.setattr("app.services.audit_service.get_audit_service", get_audit)
    await audit.log_tool_invocation(
        tool_name="trigger_scan",
        inputs={"target": "https://u:SECRETPAT@host/r.git"},
        success=False,
        error="Failed to clone https://u:SECRETPAT@host/r.git",
        started_at=datetime.now(UTC),
    )
    assert "SECRETPAT" not in json.dumps(recorded, default=str)


class _LogCollection:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs
        self.updates: list[tuple[Any, dict[str, Any]]] = []

    def find(self, query: dict[str, Any], _projection: dict[str, int]):
        docs = [d for d in self.docs if d.get("jobName") == query["jobName"]]

        async def iterate():
            for doc in docs:
                yield doc

        return iterate()

    async def update_one(self, selector: dict[str, Any], update: dict[str, Any]) -> None:
        self.updates.append((selector["_id"], update["$set"]))


@pytest.mark.parametrize("dry_run", [True, False])
async def test_the_cli_scrubs_entries_written_before_the_fix(dry_run: bool) -> None:
    from app.cli import run_scrub_audit_credentials

    leaked = {
        "_id": "a",
        "jobName": "mcp",
        "metadata": {"tool": "trigger_scan", "inputs": {"target": "https://x:DUMMYTOKEN@host/r.git"}},
        "error": "repository URL must not contain credentials",
    }
    clean = {"_id": "b", "jobName": "mcp", "metadata": {"inputs": {"target": "https://host/r.git"}}}
    other = {"_id": "c", "jobName": "nvd", "metadata": {"note": "https://u:p@feed.example"}}
    collection = _LogCollection([leaked, clean, other])

    result = await run_scrub_audit_credentials(dry_run=dry_run, collection=collection)

    assert result["scanned"] == 2 and result["entry_ids"] == ["a"]
    if dry_run:
        assert collection.updates == []
    else:
        assert collection.updates == [
            ("a", {"metadata": {"tool": "trigger_scan", "inputs": {"target": "https://***@host/r.git"}}})
        ]
