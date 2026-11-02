"""A scanned tree is attacker-controlled. These pin what it must not be able to do.

An uploaded archive can carry a ``.git/config`` whose ``core.fsmonitor`` runs a
shell command as soon as a tool calls ``git ls-files``, and Semgrep does. A cloned
repository can carry symlinks and malformed lockfiles.
"""
from __future__ import annotations

import base64
import io
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from app import analyze_cli, scanners
from app.hecate_analyzer import parse_yarn_lock, run_analysis
from app.safe_files import MAX_PARSED_FILE_BYTES, read_text_limited

posix_git = pytest.mark.skipif(
    os.name != "posix" or shutil.which("git") is None, reason="needs git on a POSIX shell"
)


def _archive(files: dict[str, bytes]) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return base64.b64encode(buffer.getvalue()).decode()


def _extracted(files: dict[str, bytes]) -> Path:
    return Path(scanners.extract_source_archive(_archive(files)))


def test_git_metadata_is_not_extracted() -> None:
    root = _extracted({
        "a.py": b"x = 1\n",
        ".gitignore": b"*.pyc\n",
        ".git/config": b"[core]\n\tfsmonitor = touch /tmp/x\n",
        "sub/.git": b"gitdir: /etc\n",
        "sub/.GIT/config": b"[core]\n",
    })
    try:
        assert (root / "a.py").exists()
        assert (root / ".gitignore").exists()
        assert not (root / ".git").exists()
        assert not (root / "sub/.git").exists()
        assert not (root / "sub/.GIT").exists()
    finally:
        shutil.rmtree(root)


def test_archive_of_git_metadata_alone_counts_as_empty() -> None:
    with pytest.raises(RuntimeError, match="empty"):
        scanners.extract_source_archive(_archive({".git/config": b"[core]\n"}))


def test_extracted_size_is_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanners, "_MAX_EXTRACTED_BYTES", 10)
    with pytest.raises(RuntimeError, match="too large"):
        scanners.extract_source_archive(_archive({"a": b"x" * 11}))


def test_member_count_is_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanners, "_MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(RuntimeError, match="too many"):
        scanners.extract_source_archive(_archive({"a": b"1", "b": b"2"}))


def test_git_hardening_is_in_the_process_environment() -> None:
    assert os.environ["GIT_CONFIG_COUNT"] == "3"
    pairs = {os.environ[f"GIT_CONFIG_KEY_{i}"]: os.environ[f"GIT_CONFIG_VALUE_{i}"] for i in range(3)}
    assert pairs["core.fsmonitor"] == "false"
    assert pairs["safe.bareRepository"] == "explicit"


def _hostile_repo(path: Path, marker: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(path), "add", "a.py"], check=True)
    with (path / ".git/config").open("a") as config:
        config.write(f'[core]\n\tfsmonitor = "touch {marker} #"\n')


@posix_git
def test_repository_config_cannot_run_a_fsmonitor_hook(tmp_path: Path) -> None:
    marker = tmp_path / "hook-ran"
    repo = tmp_path / "repo"
    _hostile_repo(repo, marker)

    bare_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
    subprocess.run(["git", "-C", str(repo), "ls-files"], env=bare_env, capture_output=True)
    assert marker.exists(), "the test repository has to be able to fire the hook"
    marker.unlink()

    subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True)
    assert not marker.exists()


@posix_git
def test_bare_repository_layout_in_the_tree_root_is_ignored(tmp_path: Path) -> None:
    marker = tmp_path / "hook-ran"
    root = tmp_path / "tree"
    (root / "objects").mkdir(parents=True)
    (root / "refs").mkdir()
    (root / "HEAD").write_text("ref: refs/heads/main\n")
    (root / "config").write_text(
        f'[core]\n\tbare = false\n\tworktree = {root}\n\tfsmonitor = "touch {marker} #"\n'
    )
    subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
def test_read_text_limited_refuses_symlinks(tmp_path: Path) -> None:
    secret = tmp_path / "outside"
    secret.write_text("secret")
    link = tmp_path / "Dockerfile"
    link.symlink_to(secret)
    with pytest.raises(OSError):
        read_text_limited(link)


@pytest.mark.skipif(os.name != "posix", reason="needs /dev/zero")
def test_read_text_limited_refuses_devices(tmp_path: Path) -> None:
    link = tmp_path / "Dockerfile"
    link.symlink_to("/dev/zero")
    with pytest.raises(OSError):
        read_text_limited(link)


def test_read_text_limited_refuses_oversized_files(tmp_path: Path) -> None:
    big = tmp_path / "yarn.lock"
    with big.open("wb") as handle:
        handle.truncate(MAX_PARSED_FILE_BYTES + 1)
    with pytest.raises(OSError):
        read_text_limited(big)


def test_read_text_limited_reads_regular_files(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_text("hello")
    assert read_text_limited(path) == "hello"


def test_every_parser_read_goes_through_the_helper() -> None:
    app_dir = Path(scanners.__file__).parent
    offenders = [
        f"{path.name}:{number}"
        for path in [app_dir / "hecate_analyzer.py", app_dir / "scanners.py", *(app_dir / "malware_detector").glob("*.py")]
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if 'read_text(errors="replace")' in line or "ET.parse(" in line
    ]
    assert offenders == []


POM = """<project><groupId>org.example</groupId><artifactId>demo</artifactId>
<dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency></dependencies>
</project>"""


def test_a_pom_is_still_read(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(POM)
    names = [component["name"] for component in run_analysis(str(tmp_path))["components"]]
    assert any("slf4j-api" in name for name in names)


def test_a_manifest_with_a_dtd_is_skipped(tmp_path: Path) -> None:
    from app.safe_files import parse_xml_limited

    pom = tmp_path / "pom.xml"
    pom.write_text('<?xml version="1.0"?><?pi x?><!DOCTYPE p [<!ENTITY a "1">]>' + POM)
    with pytest.raises(OSError, match="DTD"):
        parse_xml_limited(pom)
    names = [component["name"] for component in run_analysis(str(tmp_path))["components"]]
    assert not any("slf4j" in name for name in names)


def test_an_oversized_manifest_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app import safe_files

    monkeypatch.setattr(safe_files, "MAX_PARSED_FILE_BYTES", 10)
    pom = tmp_path / "pom.xml"
    pom.write_text(POM)
    with pytest.raises(OSError, match="too large"):
        safe_files.parse_xml_limited(pom)


def test_a_malformed_lockfile_costs_one_parser_only(tmp_path: Path) -> None:
    (tmp_path / "composer.lock").write_text("[]")
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"left-pad": "1.3.0"}}')
    names = [component["name"] for component in run_analysis(str(tmp_path))["components"]]
    assert "left-pad" in names


def test_detection_still_runs_when_sbom_analysis_blows_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(_: str) -> dict:
        raise ValueError("boom")

    monkeypatch.setattr(analyze_cli, "run_analysis", explode)
    monkeypatch.setattr(analyze_cli, "run_detection", lambda _: [{"id": "HEC-001"}])
    result = analyze_cli.analyze(str(tmp_path))
    assert result["findings"] == [{"id": "HEC-001"}]
    assert "boom" in result["errors"][0]


def test_long_yarn_lines_cost_no_regex_time(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("a" + " " * 200_000 + "\n")
    started = time.monotonic()
    parse_yarn_lock(str(tmp_path))
    assert time.monotonic() - started < 1


async def test_analyzer_runs_as_a_child_process(tmp_path: Path) -> None:
    (tmp_path / "composer.lock").write_text("[]")
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"left-pad": "1.3.0"}}')
    result = await scanners._run_hecate_analyzer("t", "source_repo", str(tmp_path))
    assert result.error is None
    assert "left-pad" in [component["name"] for component in result.report["components"]]


async def test_analyzer_timeout_kills_the_child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def run_slow(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
        assert cmd[:3] == [sys.executable, "-m", "app.analyze_cli"]
        raise RuntimeError(f"Scanner timed out after {timeout}s")

    monkeypatch.setattr(scanners, "_run_command", run_slow)
    result = await scanners._run_hecate_analyzer("t", "source_repo", str(tmp_path))
    assert result.error and "timed out" in result.error
    assert result.report == {}
