"""Checks: scans without a target, kept out of every list, deleted after a while."""
from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import Depends, FastAPI, File, UploadFile
from fastapi.testclient import TestClient

from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.core.passwords import hash_password
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import SubmitScanRequest
from app.services import scan_release
from app.services.scan_checks import CHECK_TARGET_PATTERN, is_check_target, new_check_target_id
from app.services.scan_service import ScanService, get_scan_service

PASSWORD = "admin-password"
OWNER = "owner-password"


@pytest.mark.parametrize(
    ("target_id", "expected"),
    [
        ("check:0123abcd", True),
        ("one-time-upload:0123abcd", True),
        ("ghcr.io/0x3e4/hecate-docs", False),
        ("https://github.com/0x3e4/hecate", False),
        ("sbom-import-check", False),
        ("x-check:1", False),
        (None, False),
    ],
)
def test_is_check_target(target_id: Any, expected: bool) -> None:
    assert is_check_target(target_id) is expected


def test_new_check_ids_are_checks_and_unique() -> None:
    a, b = new_check_target_id(), new_check_target_id()
    assert a != b and is_check_target(a) and is_check_target(b)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, False),
        ({"check": True}, True),
        ({"oneTime": True}, True),
        ({"sourceArchiveBase64": "UEsDBA=="}, True),
    ],
)
def test_request_is_check(kwargs: dict[str, Any], expected: bool) -> None:
    assert SubmitScanRequest(target="t", type="source_repo", **kwargs).is_check is expected


# --------------------------------------------------------------------------
# Lists leave checks out
# --------------------------------------------------------------------------

class _Capture:
    """Records the filters a repository sends."""

    def __init__(self) -> None:
        self.queries: list[dict[str, Any]] = []

    async def count_documents(self, query: dict[str, Any]) -> int:
        self.queries.append(query)
        return 0

    def find(self, query: dict[str, Any], *_args: Any) -> "_Capture":
        self.queries.append(query)
        return self

    def sort(self, *_args: Any) -> "_Capture":
        return self

    def skip(self, *_args: Any) -> "_Capture":
        return self

    def limit(self, *_args: Any) -> "_Capture":
        return self

    def aggregate(self, pipeline: list[dict[str, Any]]) -> "_Capture":
        self.queries.append(pipeline[0]["$match"])
        return self

    def __aiter__(self):
        async def empty():
            return
            yield  # pragma: no cover
        return empty()


def _excludes_checks(condition: Any) -> bool:
    pattern = condition["$not"]
    assert isinstance(pattern, re.Pattern)
    return bool(pattern.match("check:abc")) and not pattern.match("ghcr.io/org/app")


async def test_scan_list_without_target_leaves_checks_out() -> None:
    capture = _Capture()
    await ScanRepository(capture).list_all()
    assert all(_excludes_checks(q["target_id"]) for q in capture.queries)


async def test_scan_list_for_one_target_is_unchanged() -> None:
    capture = _Capture()
    await ScanRepository(capture).list_all(target_id="ghcr.io/org/app", status="completed")
    assert capture.queries[0] == {"target_id": "ghcr.io/org/app", "status": "completed"}


async def test_latest_scan_per_target_leaves_checks_out() -> None:
    capture = _Capture()
    await ScanRepository(capture).get_latest_completed_scan_ids()
    assert _excludes_checks(capture.queries[0]["target_id"])


async def test_findings_by_vulnerability_leave_checks_out() -> None:
    capture = _Capture()
    repo = ScanFindingRepository(capture)
    await repo.find_by_cve("CVE-2026-1")
    await repo.find_by_vulnerability_ids(["CVE-2026-1"])
    assert capture.queries and all(_excludes_checks(q["target_id"]) for q in capture.queries)


async def test_expired_checks_query() -> None:
    capture = _Capture()
    now = datetime(2026, 11, 23, tzinfo=UTC)
    await ScanRepository(capture).list_expired_checks(now)
    assert capture.queries[0] == {
        "check": True,
        "expires_at": {"$lte": now},
        "status": {"$nin": ["pending", "running"]},
    }


# --------------------------------------------------------------------------
# Submission
# --------------------------------------------------------------------------

class _Recorder:
    def __init__(self) -> None:
        self.targets: list[Any] = []
        self.scans: list[Any] = []
        self.running: list[str] = []

    async def upsert(self, doc: Any) -> None:
        self.targets.append(doc)

    async def get(self, _target_id: str) -> None:
        return None

    async def update_running_state(self, target_id: str, *_args: Any) -> None:
        self.running.append(target_id)

    async def insert(self, doc: Any) -> str:
        self.scans.append(doc)
        return "scan-1"


@pytest.fixture
def submit(monkeypatch: pytest.MonkeyPatch) -> tuple[ScanService, _Recorder, list[dict[str, Any]]]:
    recorder = _Recorder()
    service = ScanService(
        target_repo=recorder, scan_repo=recorder, finding_repo=None, sbom_repo=None, layer_repo=None, audit_service=None
    )
    dispatched: list[dict[str, Any]] = []

    async def background(**kwargs: Any) -> None:
        dispatched.append(kwargs)

    monkeypatch.setattr(service, "_run_scan_background", background)
    return service, recorder, dispatched


async def test_a_check_creates_no_target_and_expires(
    submit: tuple[ScanService, _Recorder, list[dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "sca_check_retention_days", 3)
    service, recorder, dispatched = submit
    before = datetime.now(tz=UTC)
    result = await service.submit_scan(
        target="ghcr.io/org/app:1.0", target_type="container_image", scanners=["trivy"], one_time=True
    )
    await asyncio.sleep(0)

    assert recorder.targets == []
    scan = recorder.scans[0]
    assert scan.check is True and is_check_target(scan.target_id)
    assert before + timedelta(days=3) <= scan.expires_at <= datetime.now(tz=UTC) + timedelta(days=3)
    assert result["check"] is True and result["target_id"] == scan.target_id
    assert result["expires_at"] == scan.expires_at
    assert dispatched[0]["target_id"] == scan.target_id


async def test_a_scan_still_registers_its_target(submit: tuple[ScanService, _Recorder, list[dict[str, Any]]]) -> None:
    service, recorder, _ = submit
    result = await service.submit_scan(target="ghcr.io/org/app:1.0", target_type="container_image", scanners=["trivy"])
    assert len(recorder.targets) == 1
    assert recorder.scans[0].check is False and recorder.scans[0].expires_at is None
    assert result["check"] is False and not is_check_target(result["target_id"])


# --------------------------------------------------------------------------
# Gates: a check writes into no target, so no target password opens it
# --------------------------------------------------------------------------

class _Targets:
    def __init__(self) -> None:
        owned = {"write_password_hash": hash_password(OWNER, iterations=10)}
        self.docs = {
            "ghcr.io/org/app": {"target_id": "ghcr.io/org/app", **owned},
            "sbom-import-app": {"target_id": "sbom-import-app", **owned},
        }

    async def get(self, target_id: str) -> dict[str, Any] | None:
        return self.docs.get(target_id)


class _Service:
    def __init__(self) -> None:
        self.target_repo = _Targets()

    @staticmethod
    def _derive_target_id(target: str, _target_type: str) -> str:
        return target.split(":")[0]


@pytest.fixture
def gated(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    service = _Service()
    app.dependency_overrides[get_scan_service] = lambda: service

    @app.post("/manual", dependencies=[Depends(write_auth.require_target_write_manual_scan)])
    async def manual() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/import", dependencies=[Depends(write_auth.require_target_write_sbom_import)])
    async def imported() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/upload", dependencies=[Depends(write_auth.require_target_write_sbom_upload)])
    async def uploaded(file: UploadFile = File(...)) -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def test_a_rescan_of_an_owned_target_takes_its_password(gated: TestClient) -> None:
    body = {"target": "ghcr.io/org/app:1.0", "type": "container_image"}
    assert gated.post("/manual", json=body, headers={"X-Target-Password": OWNER}).status_code == 200


@pytest.mark.parametrize("flag", [{"check": True}, {"oneTime": True}, {"sourceArchiveBase64": "UEsDBA=="}])
def test_a_check_is_not_opened_by_a_target_password(gated: TestClient, flag: dict[str, Any]) -> None:
    body = {"target": "ghcr.io/org/app:1.0", "type": "container_image", **flag}
    assert gated.post("/manual", json=body, headers={"X-Target-Password": OWNER}).status_code == 401
    assert gated.post("/manual", json=body, headers={"X-System-Password": PASSWORD}).status_code == 200


def test_an_sbom_check_is_not_opened_by_a_target_password(gated: TestClient) -> None:
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "app"}}, "components": []}
    assert gated.post("/import", json={"sbom": sbom}, headers={"X-Target-Password": OWNER}).status_code == 200
    body = {"sbom": sbom, "check": True}
    assert gated.post("/import", json=body, headers={"X-Target-Password": OWNER}).status_code == 401
    assert gated.post("/import", json=body, headers={"X-System-Password": PASSWORD}).status_code == 200

    files = {"file": ("bom.json", '{"bomFormat": "CycloneDX"}', "application/json")}
    params = {"targetName": "app", "check": "true"}
    assert gated.post("/upload", params=params, files=files, headers={"X-Target-Password": OWNER}).status_code == 401
    assert gated.post("/upload", params=params, files=files, headers={"X-System-Password": PASSWORD}).status_code == 200


# --------------------------------------------------------------------------
# Expiry and what a check cannot be
# --------------------------------------------------------------------------

async def test_purge_deletes_expired_checks_and_survives_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Scans:
        async def list_expired_checks(self, _now: datetime) -> list[str]:
            return ["a", "b", "c"]

    service = ScanService(
        target_repo=None, scan_repo=_Scans(), finding_repo=None, sbom_repo=None, layer_repo=None, audit_service=None
    )
    deleted: list[str] = []

    async def delete_scan(scan_id: str) -> bool:
        if scan_id == "b":
            raise RuntimeError("boom")
        deleted.append(scan_id)
        return True

    monkeypatch.setattr(service, "delete_scan", delete_scan)
    assert await service.purge_expired_checks() == 2
    assert deleted == ["a", "c"]


async def test_deleting_a_check_leaves_targets_alone() -> None:
    class _Rows:
        async def delete_by_scan(self, _scan_id: str) -> int:
            return 1

    class _Scans:
        async def get(self, _scan_id: str) -> dict[str, Any]:
            return {"_id": "s", "target_id": "check:abc"}

        async def delete(self, _scan_id: str) -> bool:
            return True

    class _NoTargets:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"target_repo.{name} called for a check")

    service = ScanService(
        target_repo=_NoTargets(), scan_repo=_Scans(), finding_repo=_Rows(), sbom_repo=_Rows(), layer_repo=_Rows(),
        audit_service=None,
    )
    assert await service.delete_scan("s") is True


async def test_a_check_cannot_be_a_release() -> None:
    class _Scans:
        async def get(self, _scan_id: str) -> dict[str, Any]:
            return {"_id": "s", "status": "completed", "target_id": "check:abc"}

    with pytest.raises(scan_release.ReleaseError) as exc:
        await scan_release.mark_release(_Scans(), "507f1f77bcf86cd799439011", "1.0")
    assert exc.value.status == 409


def test_check_pattern_matches_the_prefix_only() -> None:
    assert CHECK_TARGET_PATTERN.match("check:") and not CHECK_TARGET_PATTERN.match("ghcr.io/check:1")


# --------------------------------------------------------------------------
# MCP trigger_scan
# --------------------------------------------------------------------------

@pytest.fixture
def trigger_scan(monkeypatch: pytest.MonkeyPatch):
    from mcp.server.fastmcp import FastMCP

    from app.mcp import auth as mcp_auth
    from app.mcp.tools import scans as scan_tools

    submitted: list[dict[str, Any]] = []
    expires = datetime(2026, 11, 30, tzinfo=UTC)

    class _Service:
        async def submit_scan(self, **kwargs: Any) -> dict[str, Any]:
            submitted.append(kwargs)
            check = kwargs.get("one_time", False)
            return {
                "scan_id": "507f1f77bcf86cd799439011",
                "target_id": "check:abc" if check else "nginx",
                "check": check,
                "expires_at": expires if check else None,
            }

    async def get_scan_service() -> _Service:
        return _Service()

    async def no_audit(**_kwargs: Any) -> None:
        return None

    class _AllowAll:
        def check(self, _client: str) -> bool:
            return True

    monkeypatch.setattr("app.services.scan_service.get_scan_service", get_scan_service)
    monkeypatch.setattr(scan_tools, "log_tool_invocation", no_audit)
    monkeypatch.setattr(scan_tools, "get_rate_limiter", lambda: _AllowAll())
    mcp = FastMCP("test")
    scan_tools.register(mcp)
    fn = next(tool.fn for tool in mcp._tool_manager.list_tools() if tool.name == "trigger_scan")
    token = mcp_auth.mcp_token_scope.set("mcp:read mcp:write")
    yield fn, submitted
    mcp_auth.mcp_token_scope.reset(token)


async def test_mcp_trigger_scan_runs_a_check(trigger_scan) -> None:
    fn, submitted = trigger_scan
    result = await fn(target="ghcr.io/vendor/tool:2.1.0", check=True)
    assert submitted[0]["one_time"] is True and submitted[0]["source"] == "mcp"
    assert result["check"] is True
    assert result["expiresAt"] == "2026-11-30T00:00:00+00:00"
    assert result["reportPath"] == "/scans/check/507f1f77bcf86cd799439011"


async def test_mcp_trigger_scan_without_check_registers_a_target(trigger_scan) -> None:
    fn, submitted = trigger_scan
    result = await fn(target="nginx:latest")
    assert submitted[0]["one_time"] is False
    assert result["check"] is False and "reportPath" not in result and "expiresAt" not in result
