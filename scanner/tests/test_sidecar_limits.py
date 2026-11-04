"""The sidecar's own bounds: concurrent /scan work, extraction space, credentials on disk."""
from __future__ import annotations

import base64
import io
import json
import zipfile
from collections import namedtuple

import pytest

from app import main, scanners

_Usage = namedtuple("_Usage", "total used free")


def _archive(size: int) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/app.py", b"x" * size)
    return base64.b64encode(buffer.getvalue()).decode()


def test_an_archive_bigger_than_the_free_space_is_refused(monkeypatch):
    monkeypatch.setattr(scanners.shutil, "disk_usage", lambda _path: _Usage(10_000, 9_000, 1_000))

    with pytest.raises(RuntimeError, match="free space"):
        scanners.extract_source_archive(_archive(5_000))
    assert scanners._reserved_extraction_bytes == 0


def test_extractions_in_progress_count_against_the_free_space(monkeypatch):
    monkeypatch.setattr(scanners.shutil, "disk_usage", lambda _path: _Usage(10_000, 4_000, 6_000))
    monkeypatch.setattr(scanners, "_reserved_extraction_bytes", 4_000)

    with pytest.raises(RuntimeError, match="free space"):
        scanners.extract_source_archive(_archive(3_000))


def test_a_finished_extraction_releases_its_reservation(monkeypatch):
    import shutil

    monkeypatch.setattr(scanners.shutil, "disk_usage", lambda _path: _Usage(10**9, 0, 10**9))

    tmp_dir = scanners.extract_source_archive(_archive(1_000))
    try:
        assert scanners._reserved_extraction_bytes == 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.mark.parametrize(("raw", "expected"), [(None, 20), ("3", 3), ("0", 20), ("x", 20)])
def test_the_scan_slot_count_comes_from_the_environment(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("SCANNER_MAX_CONCURRENT_SCANS", raising=False)
    else:
        monkeypatch.setenv("SCANNER_MAX_CONCURRENT_SCANS", raw)
    assert main._max_concurrent_scans() == expected


async def test_a_repeated_scanner_runs_once_per_request(monkeypatch):
    ran: list[str] = []

    async def fake_run_scanner(name, *_args, **_kwargs):
        ran.append(name)
        return scanners.ScannerResult(scanner=name, format="x", report={})

    async def fake_digest(_target):
        return "sha256:0", None

    monkeypatch.setattr(main, "run_scanner", fake_run_scanner)
    monkeypatch.setattr(main, "get_image_digest", fake_digest)

    request = main.ScanRequest(target="registry.example/a:1", type="container_image", scanners=["trivy", "trivy", "syft"])
    await main.scan(request)

    assert ran == ["trivy", "syft"]


def test_git_credentials_stay_off_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(scanners.Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(scanners, "_GIT_AUTH_MAP", {})

    scanners.setup_auth("git.corp.example:s3cret-token,docker.io:me:dckr_pat")

    assert not (tmp_path / ".git-credentials").exists()
    assert not (tmp_path / ".gitconfig").exists()
    assert scanners._git_auth_args_for("https://git.corp.example/r.git")
    auths = json.loads((tmp_path / ".docker" / "config.json").read_text())["auths"]
    assert {"git.corp.example", "docker.io", "https://index.docker.io/v1/"} <= set(auths)
