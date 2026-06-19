"""Tests for the clone-once-per-scan shared source checkout lifecycle.

Covers the sidecar side of the fix that stopped a source-repo scan from cloning
the same repo once per scanner (up to 7 concurrent clones):
- /prepare-source registers a checkout and returns a token (200-with-error on
  clone failure, not a 4xx)
- /scan resolves a token to source_dir, NEVER deletes the token dir, refcounts it
- /cleanup-source removes the checkout (idempotent)
- the idle reaper removes only unreferenced, aged-out checkouts
- _clone_repo honours GIT_CLONE_TIMEOUT_SECONDS
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.models import ScanMetadata, ScannerResult


@pytest.fixture
def client(monkeypatch, tmp_path):
    """TestClient with _clone_repo and run_scanner stubbed so no real git/scan runs."""
    main._source_checkouts.clear()

    created_dirs: list[str] = []

    async def fake_clone(url: str) -> str:
        d = tmp_path / f"checkout-{len(created_dirs)}"
        d.mkdir()
        created_dirs.append(str(d))
        return str(d)

    async def fake_run_scanner(scanner_name, target, target_type, source_dir=None):
        # Record which dir each scanner saw so tests can assert sharing.
        fake_run_scanner.seen.append((scanner_name, source_dir))
        return ScannerResult(scanner=scanner_name, format="trivy-json", report={}, error=None)

    fake_run_scanner.seen = []

    async def fake_commit_sha(source_dir):
        return "deadbeef"

    monkeypatch.setattr(main, "_clone_repo", fake_clone)
    monkeypatch.setattr(main, "run_scanner", fake_run_scanner)
    monkeypatch.setattr(main, "get_git_commit_sha", fake_commit_sha)

    c = TestClient(main.app)
    c.created_dirs = created_dirs
    c.seen = fake_run_scanner.seen
    yield c
    main._source_checkouts.clear()


def test_prepare_source_registers_token(client):
    resp = client.post("/prepare-source", json={"target": "https://x/r.git", "type": "source_repo"})
    assert resp.status_code == 200
    token = resp.json()["sourceToken"]
    assert token
    assert token in main._source_checkouts
    entry = main._source_checkouts[token]
    assert entry["refcount"] == 0
    assert entry["dir"] in client.created_dirs


def test_prepare_source_rejects_non_source_repo(client):
    resp = client.post("/prepare-source", json={"target": "img:latest", "type": "container_image"})
    assert resp.status_code == 400


def test_prepare_source_clone_failure_is_200_with_error(client, monkeypatch):
    async def boom(url):
        raise RuntimeError("Failed to clone https://x/r.git: fatal: not found")

    monkeypatch.setattr(main, "_clone_repo", boom)
    resp = client.post("/prepare-source", json={"target": "https://x/r.git", "type": "source_repo"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["sourceToken"] is None
    assert "Failed to clone" in body["error"]
    assert main._source_checkouts == {}


def test_scan_with_token_shares_dir_and_does_not_delete_it(client):
    token = client.post(
        "/prepare-source", json={"target": "https://x/r.git", "type": "source_repo"}
    ).json()["sourceToken"]
    checkout_dir = main._source_checkouts[token]["dir"]

    resp = client.post(
        "/scan",
        json={"target": "https://x/r.git", "type": "source_repo",
              "scanners": ["trivy", "grype", "syft"], "sourceToken": token},
    )
    assert resp.status_code == 200
    # All scanners saw the SAME shared checkout dir.
    seen_dirs = {d for _, d in client.seen}
    assert seen_dirs == {checkout_dir}
    # The token dir is NOT deleted by /scan (ownership stays with /cleanup-source)
    # and the refcount is back to 0 after the call.
    assert token in main._source_checkouts
    assert main._source_checkouts[token]["refcount"] == 0


def test_scan_with_unknown_token_400(client):
    resp = client.post(
        "/scan",
        json={"target": "https://x/r.git", "type": "source_repo",
              "scanners": ["trivy"], "sourceToken": "does-not-exist"},
    )
    assert resp.status_code == 400


def test_cleanup_source_removes_checkout_and_is_idempotent(client):
    token = client.post(
        "/prepare-source", json={"target": "https://x/r.git", "type": "source_repo"}
    ).json()["sourceToken"]

    r1 = client.post("/cleanup-source", json={"sourceToken": token})
    assert r1.status_code == 200 and r1.json()["removed"] is True
    assert token not in main._source_checkouts

    # Second call is a no-op (removed=false), never errors.
    r2 = client.post("/cleanup-source", json={"sourceToken": token})
    assert r2.status_code == 200 and r2.json()["removed"] is False


@pytest.mark.asyncio
async def test_reaper_skips_referenced_and_fresh_but_reaps_aged_unreferenced(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_CHECKOUT_TTL_SECONDS", "100")
    main._source_checkouts.clear()
    for name in ("aged", "fresh", "inuse"):
        (tmp_path / name).mkdir()
    now = time.monotonic()
    main._source_checkouts.update({
        "aged":  {"dir": str(tmp_path / "aged"),  "created_at": now - 1000, "refcount": 0},
        "fresh": {"dir": str(tmp_path / "fresh"), "created_at": now,         "refcount": 0},
        "inuse": {"dir": str(tmp_path / "inuse"), "created_at": now - 1000, "refcount": 1},
    })

    removed = await main._reap_source_checkouts_once()

    assert removed == 1
    assert "aged" not in main._source_checkouts          # unreferenced + aged -> reaped
    assert not (tmp_path / "aged").exists()
    assert "fresh" in main._source_checkouts             # too young -> kept
    assert "inuse" in main._source_checkouts             # refcount > 0 -> never reaped
    assert (tmp_path / "inuse").exists()
    main._source_checkouts.clear()


def test_ttl_env_handling(monkeypatch):
    monkeypatch.delenv("SOURCE_CHECKOUT_TTL_SECONDS", raising=False)
    assert main._source_checkout_ttl() == 7200
    monkeypatch.setenv("SOURCE_CHECKOUT_TTL_SECONDS", "1800")
    assert main._source_checkout_ttl() == 1800
    for bad in ("0", "-5", "abc", ""):
        monkeypatch.setenv("SOURCE_CHECKOUT_TTL_SECONDS", bad)
        assert main._source_checkout_ttl() == 7200


def test_clone_repo_uses_configurable_timeout(monkeypatch):
    """_clone_repo passes GIT_CLONE_TIMEOUT_SECONDS (default 300) to _run_command
    and clones shallow with --no-tags --single-branch."""
    import asyncio
    import shutil

    import app.scanners as scanners

    captured = {}

    async def fake_run_command(cmd, timeout=600):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return "", "", 0  # rc 0 -> success

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    monkeypatch.setenv("GIT_CLONE_TIMEOUT_SECONDS", "450")

    checkout = asyncio.run(scanners._clone_repo("https://x/r.git"))
    shutil.rmtree(checkout, ignore_errors=True)  # mkdtemp'd a real (empty) dir

    assert captured["timeout"] == 450
    assert "--no-tags" in captured["cmd"]
    assert "--single-branch" in captured["cmd"]
    assert "--depth" in captured["cmd"]
