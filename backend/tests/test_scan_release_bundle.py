"""Release markers on scans and the evidence bundle."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import scans as scans_api
from app.core import write_auth
from app.services import evidence_bundle
from app.services.scan_release import ReleaseError, clear_release, list_releases, mark_release

SCAN_ID = "6650f0c0a1b2c3d4e5f60718"
OTHER_ID = "6650f0c0a1b2c3d4e5f60719"


class FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def sort(self, *_a: Any) -> FakeCursor:
        return self

    def limit(self, _n: int) -> FakeCursor:
        return self

    def __aiter__(self) -> Any:
        async def gen() -> Any:
            for doc in self.docs:
                yield dict(doc)
        return gen()


class FakeCollection:
    def __init__(self, docs: dict[str, dict[str, Any]]) -> None:
        self.docs = docs

    async def find_one(self, query: dict[str, Any], _projection: Any = None) -> dict[str, Any] | None:
        for sid, doc in self.docs.items():
            if (
                doc.get("target_id") == query["target_id"]
                and (doc.get("release") or {}).get("label") == query["release.label"]
                and sid != str(query["_id"]["$ne"])
            ):
                return {"_id": sid}
        return None

    async def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> None:
        doc = self.docs[str(query["_id"])]
        for key in update.get("$unset", {}):
            doc.pop(key, None)

    def find(self, query: dict[str, Any], _projection: Any = None) -> FakeCursor:
        return FakeCursor([
            {"_id": sid, **doc} for sid, doc in self.docs.items()
            if doc.get("target_id") == query["target_id"] and doc.get("release")
        ])


class FakeScanRepo:
    def __init__(self) -> None:
        self.docs = {
            SCAN_ID: {"target_id": "t", "status": "completed"},
            OTHER_ID: {"target_id": "t", "status": "running"},
        }
        self.collection = FakeCollection(self.docs)

    async def get(self, scan_id: str) -> dict[str, Any] | None:
        doc = self.docs.get(scan_id)
        return {"_id": scan_id, **doc} if doc else None

    async def update_fields(self, scan_id: str, fields: dict[str, Any]) -> None:
        self.docs[scan_id].update(fields)


async def test_mark_and_clear_a_release() -> None:
    repo = FakeScanRepo()
    scan = await mark_release(repo, SCAN_ID, "  1.4.2 ", "First CRA release")
    assert scan["release"]["label"] == "1.4.2"
    assert scan["release"]["note"] == "First CRA release"
    marked_at = repo.docs[SCAN_ID]["release"]["marked_at"]
    # Editing the label keeps the original date.
    await mark_release(repo, SCAN_ID, "1.4.2-hotfix")
    assert repo.docs[SCAN_ID]["release"]["marked_at"] == marked_at
    releases = await list_releases(repo, "t")
    assert [r["release"]["label"] for r in releases] == ["1.4.2-hotfix"]

    scan = await clear_release(repo, SCAN_ID)
    assert "release" not in scan and "release" not in repo.docs[SCAN_ID]


@pytest.mark.parametrize(
    ("scan_id", "label", "status"),
    [
        (SCAN_ID, "", 400),
        (SCAN_ID, "x" * 65, 400),
        (OTHER_ID, "1.0", 409),  # not completed
        ("6650f0c0a1b2c3d4e5f6071a", "1.0", 404),
    ],
)
async def test_invalid_release_markers_are_refused(scan_id: str, label: str, status: int) -> None:
    with pytest.raises(ReleaseError) as exc:
        await mark_release(FakeScanRepo(), scan_id, label)
    assert exc.value.status == status


async def test_a_label_is_unique_per_target() -> None:
    repo = FakeScanRepo()
    repo.docs[OTHER_ID].update({"status": "completed", "release": {"label": "2.0"}})
    with pytest.raises(ReleaseError) as exc:
        await mark_release(repo, SCAN_ID, "2.0")
    assert exc.value.status == 409


def _route_dependencies(path: str, method: str) -> set[Any]:
    for route in scans_api.router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return {d.call for d in route.dependant.dependencies}
    raise AssertionError(f"{method} {path} not registered")


def test_release_routes_take_the_target_write_gate() -> None:
    assert write_auth.require_target_write_scan in _route_dependencies("/{scan_id}/release", "PUT")
    assert write_auth.require_target_write_scan in _route_dependencies("/{scan_id}/release", "DELETE")
    # The bundle is a read like the SBOM / VEX exports.
    assert not {
        write_auth.require_target_write_scan, write_auth.require_admin_write,
    } & _route_dependencies("/{scan_id}/evidence-bundle", "GET")


def test_releases_route_is_declared_before_the_bare_target_route() -> None:
    paths = [getattr(r, "path", "") for r in scans_api.router.routes]
    assert paths.index("/targets/{target_id:path}/releases") < paths.index("/targets/{target_id:path}")


class DeleteService:
    def __init__(self, release: bool) -> None:
        self.release = release
        self.deleted: list[str] = []

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        return {"_id": scan_id, "release": {"label": "1.0"} if self.release else None}

    async def delete_scan(self, scan_id: str) -> bool:
        self.deleted.append(scan_id)
        return True


@pytest.mark.parametrize("release", [True, False])
def test_deleting_a_release_scan_is_refused(release: bool) -> None:
    service = DeleteService(release)
    app = FastAPI()
    app.include_router(scans_api.router, prefix="/scans")
    app.dependency_overrides[scans_api.get_scan_service] = lambda: service
    app.dependency_overrides[write_auth.require_admin_write] = lambda: None
    response = TestClient(app).delete(f"/scans/{SCAN_ID}")
    if release:
        assert response.status_code == 409
        assert service.deleted == []
    else:
        assert response.status_code == 204
        assert service.deleted == [SCAN_ID]


# ---------------------------------------------------------------- bundle


def test_bundle_bytes_hold_a_manifest_with_hashes() -> None:
    files = [("sbom/a.cdx.json", b'{"bomFormat": "CycloneDX"}'), ("findings-summary.json", b"{}")]
    data = evidence_bundle.build_bundle_bytes(files, {"format": "hecate-evidence-bundle"})
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = set(zf.namelist())
        assert names == {"sbom/a.cdx.json", "findings-summary.json", "manifest.json", "SHA256SUMS"}
        manifest = json.loads(zf.read("manifest.json"))
        for entry in manifest["files"]:
            assert entry["sha256"] == hashlib.sha256(zf.read(entry["path"])).hexdigest()
            assert entry["bytes"] == len(zf.read(entry["path"]))
        sums = zf.read("SHA256SUMS").decode()
        assert f"{hashlib.sha256(files[0][1]).hexdigest()}  sbom/a.cdx.json" in sums


def test_bundle_size_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence_bundle, "MAX_UNCOMPRESSED_BYTES", 10)
    with pytest.raises(evidence_bundle.BundleTooLarge):
        evidence_bundle.build_bundle_bytes([("a", b"x" * 11)], {})


class BundleScanRepo:
    async def get(self, scan_id: str) -> dict[str, Any] | None:
        if scan_id != SCAN_ID:
            return None
        return {
            "_id": SCAN_ID, "target_id": "https://github.com/acme/shop", "target_name": "acme/shop",
            "status": "completed", "commit_sha": "deadbeef", "summary": {"high": 1, "total": 1},
            "release": {"label": "1.4.2", "note": None},
        }


class BundleTargetRepo:
    async def get(self, _tid: str) -> dict[str, Any]:
        return {"name": "acme/shop", "type": "source_repo"}


class BundleFindingRepo:
    findings = [
        {"vulnerability_id": "CVE-2024-1", "package_name": "lodash", "package_version": "4.17.20",
         "severity": "high", "vex_status": "not_affected", "vex_justification": "code_not_present"},
        {"vulnerability_id": "CVE-2024-2", "package_name": "lodash", "package_version": "4.17.20",
         "severity": "medium"},
        {"vulnerability_id": None, "package_name": "app.py", "package_type": "sast-finding"},
    ]

    async def list_by_scan(self, _sid: str, **_kw: Any) -> tuple[int, list[dict[str, Any]]]:
        return len(self.findings), [dict(f) for f in self.findings]

    async def get_vex_findings_by_scan(self, _sid: str) -> list[dict[str, Any]]:
        return [dict(f) for f in self.findings if f.get("vex_status")]


class BundleSbomRepo:
    async def list_all_by_scan(self, _sid: str) -> list[dict[str, Any]]:
        return [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20", "licenses": ["MIT"]}]


class BundleRepos:
    scan_repo = BundleScanRepo()
    target_repo = BundleTargetRepo()
    finding_repo = BundleFindingRepo()
    sbom_repo = BundleSbomRepo()


async def test_evidence_bundle_contents() -> None:
    data, filename = await evidence_bundle.build_evidence_bundle(BundleRepos(), SCAN_ID)  # type: ignore[misc]
    assert filename == "shop-1.4.2-evidence.zip"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        assert "sbom/shop-1.4.2.cdx.json" in names and "sbom/shop-1.4.2.spdx.json" in names
        assert {"vex/vex.cdx.json", "vex/vex.openvex.json", "findings-summary.json"} <= set(names)
        csaf_name = next(n for n in names if n.startswith("vex/hecate-vex-"))
        assert json.loads(zf.read(csaf_name))["document"]["category"] == "csaf_vex"
        assert json.loads(zf.read("sbom/shop-1.4.2.spdx.json"))["spdxVersion"].startswith("SPDX-")
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["release"]["label"] == "1.4.2"
        assert manifest["scan"]["commitSha"] == "deadbeef"
        assert manifest["target"]["name"] == "acme/shop"
        assert {e["path"] for e in manifest["files"]} == set(names) - {"manifest.json", "SHA256SUMS"}
        for entry in manifest["files"]:
            assert entry["sha256"] == hashlib.sha256(zf.read(entry["path"])).hexdigest()
        summary = json.loads(zf.read("findings-summary.json"))
        assert summary["vulnerabilityFindings"] == 2
        assert summary["vexStatusCounts"] == {"not_affected": 1, "unassessed": 1}
        assert summary["otherFindings"]["sast-finding"] == 1
    assert await evidence_bundle.build_evidence_bundle(BundleRepos(), "6650f0c0a1b2c3d4e5f6071a") is None
