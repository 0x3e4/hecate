"""govulncheck runner: module discovery, command, environment, errors."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from app import scanners


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_find_go_modules_skips_vendor_testdata_hidden(tmp_path: Path) -> None:
    _write(tmp_path / "go.mod", "module example.com/root\n")
    _write(tmp_path / "tools" / "go.mod", "module example.com/root/tools\n")
    _write(tmp_path / "vendor" / "x" / "go.mod", "module vendored\n")
    _write(tmp_path / "pkg" / "testdata" / "go.mod", "module fixture\n")
    _write(tmp_path / ".github" / "go.mod", "module hidden\n")
    _write(tmp_path / "_examples" / "go.mod", "module underscore\n")
    _write(tmp_path / "node_modules" / "a" / "go.mod", "module npm\n")

    dirs, truncated = scanners._find_go_modules(str(tmp_path), limit=10)
    assert dirs == [".", "tools"]
    assert truncated is False


def test_find_go_modules_caps_and_reports_truncation(tmp_path: Path) -> None:
    for i in range(5):
        _write(tmp_path / f"m{i}" / "go.mod", f"module example.com/m{i}\n")
    dirs, truncated = scanners._find_go_modules(str(tmp_path), limit=3)
    assert dirs == ["m0", "m1", "m2"]
    assert truncated is True


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlinks")
def test_find_go_modules_ignores_symlinked_go_mod(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _write(outside / "go.mod", "module outside\n")
    repo = tmp_path / "repo"
    (repo / "a").mkdir(parents=True)
    os.symlink(outside / "go.mod", repo / "a" / "go.mod")
    os.symlink(outside, repo / "linked")
    dirs, _ = scanners._find_go_modules(str(repo), limit=10)
    assert dirs == []


def test_go_module_path_reads_module_line(tmp_path: Path) -> None:
    _write(tmp_path / "go.mod", "// comment\nmodule \"example.com/quoted\" // trailing\n\ngo 1.24\n")
    assert scanners._go_module_path(tmp_path / "go.mod") == "example.com/quoted"
    assert scanners._go_module_path(tmp_path / "missing.mod") is None


def test_go_module_path_is_linear_on_blank_runs(tmp_path: Path) -> None:
    # A still-valid go.mod: a long blank run before the module line. The old
    # MULTILINE ^\s* regex took ~7.5 s at 64k newlines and grew quadratically.
    _write(tmp_path / "go.mod", "\n" * 1_000_000 + "// c\nmodule example.com/m\n\ngo 1.22\n")
    start = time.monotonic()
    assert scanners._go_module_path(tmp_path / "go.mod") == "example.com/m"
    assert time.monotonic() - start < 2.0


def test_go_module_path_skips_overlong_lines(tmp_path: Path) -> None:
    _write(tmp_path / "go.mod", "module " + "a" * 5000 + "\nmodule example.com/ok\n")
    assert scanners._go_module_path(tmp_path / "go.mod") == "example.com/ok"


def test_decode_json_stream_handles_indented_objects() -> None:
    stream = (
        json.dumps({"config": {"protocol_version": "v1.0.0"}}, indent=2)
        + "\n"
        + json.dumps({"finding": {"osv": "GO-2024-0001"}}, indent=2)
    )
    messages, error = scanners._decode_json_stream(stream)
    assert error is None
    assert [next(iter(m)) for m in messages] == ["config", "finding"]

    messages, error = scanners._decode_json_stream('{"config": {}} {broken')
    assert len(messages) == 1
    assert error and error.startswith("Invalid JSON output")


def test_govulncheck_env_isolates_go_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    monkeypatch.delenv("GOPROXY", raising=False)
    monkeypatch.delenv("GOVULNCHECK_CACHE_DIR", raising=False)
    env = scanners._govulncheck_env(str(tmp_path))
    assert "GOFLAGS" not in env
    assert env["GOTOOLCHAIN"] == "local"
    assert env["GOPROXY"] == "https://proxy.golang.org"
    assert "direct" not in env["GOPROXY"]
    for key in ("GOPATH", "GOMODCACHE", "GOCACHE", "XDG_CONFIG_HOME"):
        assert env[key].startswith(str(tmp_path))

    monkeypatch.setenv("GOPROXY", "https://goproxy.corp.example")
    assert scanners._govulncheck_env(str(tmp_path))["GOPROXY"] == "https://goproxy.corp.example"


def test_govulncheck_db_only_accepts_url_schemes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOVULNCHECK_DB", "file:///srv/vulndb")
    assert scanners._govulncheck_db() == "file:///srv/vulndb"
    monkeypatch.setenv("GOVULNCHECK_DB", "-json")
    assert scanners._govulncheck_db() is None
    monkeypatch.delenv("GOVULNCHECK_DB")
    assert scanners._govulncheck_db() is None


def test_container_images_are_refused() -> None:
    result = asyncio.run(scanners._run_govulncheck("alpine:3", "container_image"))
    assert result.error and "source repository" in result.error


def test_runs_once_per_module_with_safe_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "go.mod", "module example.com/root\n")
    _write(tmp_path / "svc" / "go.mod", "module example.com/svc\n")
    calls: list[tuple[list[str], int, dict[str, str] | None]] = []

    async def fake_run_command(cmd, timeout=600, env=None):
        calls.append((cmd, timeout, env))
        if cmd[-2].endswith("svc"):
            return "", "go: go.mod requires go >= 1.99 (running go 1.27.3; GOTOOLCHAIN=local)\n", 1
        return json.dumps({"finding": {"osv": "GO-2024-0001", "trace": [{"module": "m"}]}}, indent=2), "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    monkeypatch.setenv("GOVULNCHECK_TIMEOUT_SECONDS", "900")
    monkeypatch.delenv("GOVULNCHECK_DB", raising=False)

    result = asyncio.run(scanners._run_govulncheck("https://example.com/r.git", "source_repo", str(tmp_path)))

    assert result.error is None
    assert len(calls) == 2
    cmd, timeout, env = calls[0]
    assert cmd[:2] == ["govulncheck", "-json"]
    assert cmd[-3] == "-C" and cmd[-1] == "./..."
    assert cmd[-2] == str(tmp_path)
    assert 0 < timeout <= 900
    assert env is not None and env["GOTOOLCHAIN"] == "local"
    modules = result.report["modules"]
    assert [m["dir"] for m in modules] == [".", "svc"]
    assert modules[0]["module"] == "example.com/root"
    assert modules[0]["error"] is None and modules[0]["messages"][0]["finding"]["osv"] == "GO-2024-0001"
    assert modules[1]["error"].startswith("go: go.mod requires go >= 1.99")


def test_all_modules_failing_sets_the_scanner_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "go.mod", "module example.com/root\n")

    async def fake_run_command(cmd, timeout=600, env=None):
        return "", "panic: runtime error\n\ngoroutine 1 [running]:\nmain.main()\n", 2

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    result = asyncio.run(scanners._run_govulncheck("https://example.com/r.git", "source_repo", str(tmp_path)))
    assert result.error == "govulncheck failed: .: panic: runtime error"
    assert "goroutine" not in result.error


def test_time_budget_skips_remaining_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "a" / "go.mod", "module a\n")
    _write(tmp_path / "b" / "go.mod", "module b\n")
    clock = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0])

    async def fake_run_command(cmd, timeout=600, env=None):
        return "", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    class _FakeTime:
        @staticmethod
        def monotonic() -> float:
            return next(clock, 1000.0)

    monkeypatch.setattr(scanners, "time", _FakeTime)
    monkeypatch.setenv("GOVULNCHECK_TIMEOUT_SECONDS", "60")
    result = asyncio.run(scanners._run_govulncheck("https://example.com/r.git", "source_repo", str(tmp_path)))
    modules = result.report["modules"]
    assert modules[0]["error"] is None
    assert modules[1]["error"].startswith("skipped")


def test_no_go_module_is_an_empty_report(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", "{}")
    result = asyncio.run(scanners._run_govulncheck("https://example.com/r.git", "source_repo", str(tmp_path)))
    assert result.error is None
    assert result.report == {"modules": [], "truncated": False}


def test_force_rmtree_removes_read_only_module_cache(tmp_path: Path) -> None:
    cache = tmp_path / "work" / "gopath" / "pkg" / "mod" / "example.com" / "m@v1.0.0"
    _write(cache / "m.go", "package m\n")
    os.chmod(cache / "m.go", 0o444)
    os.chmod(cache, 0o555)
    scanners._force_rmtree(str(tmp_path / "work"))
    assert not (tmp_path / "work").exists()


def test_govulncheck_is_a_valid_sidecar_scanner() -> None:
    from app.main import VALID_SCANNERS

    assert "govulncheck" in VALID_SCANNERS
