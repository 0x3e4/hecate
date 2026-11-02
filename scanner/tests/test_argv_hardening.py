"""Argv hardening for image-scanner subprocesses + symlink-safe requirements pinning.

The scan target is validated before it reaches these tools, but the ``--``
end-of-options separator is a second guard: even an unvalidated value that
starts with ``-`` must land as a positional argument, never as a flag.
"""
from __future__ import annotations

import os

import pytest

from app import scanners


@pytest.fixture
def captured(monkeypatch):
    calls: list[list[str]] = []

    async def fake_run_command(cmd, timeout=600):
        calls.append(list(cmd))
        # Non-zero rc + empty stdout makes the grype SBOM pre-build fall back
        # to scanning the image directly, so that argv is exercised too.
        if cmd[0] == "syft" and any(a.startswith("cyclonedx-json=") for a in cmd):
            return "", "", 1
        return "{}", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    return calls


def _assert_target_after_separator(cmd: list[str], target: str) -> None:
    assert "--" in cmd, cmd
    assert cmd[-1] == target, cmd
    assert cmd.index("--") == len(cmd) - 2, cmd


EVIL = "--output=/tmp/pwn"


async def test_trivy_image_target_after_separator(captured):
    await scanners._run_trivy(EVIL, "container_image")
    _assert_target_after_separator(captured[-1], EVIL)


async def test_syft_image_target_after_separator(captured):
    await scanners._run_syft(EVIL, "container_image")
    _assert_target_after_separator(captured[-1], EVIL)


async def test_grype_prebuild_and_fallback_target_after_separator(captured):
    await scanners._run_grype(EVIL, "container_image")
    syft_cmd, grype_cmd = captured[0], captured[-1]
    assert syft_cmd[0] == "syft" and grype_cmd[0] == "grype"
    _assert_target_after_separator(syft_cmd, EVIL)
    _assert_target_after_separator(grype_cmd, EVIL)


async def test_dockle_target_after_separator(captured):
    await scanners._run_dockle(EVIL, "container_image")
    _assert_target_after_separator(captured[-1], EVIL)


# --------------------------------------------------------------------------
# _pin_requirements_files must not write through a symlink out of the checkout
# --------------------------------------------------------------------------

async def test_pin_requirements_skips_symlink_out_of_tree(tmp_path, monkeypatch):
    async def fake_latest(_name):
        return "9.9.9"

    monkeypatch.setattr(scanners, "_get_latest_pypi_version", fake_latest)

    outside = tmp_path / "outside.txt"
    outside.write_text("requests\n")
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "requirements.txt").write_text("flask\n")
    try:
        os.symlink(outside, checkout / "requirements-dev.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this platform")

    modified = await scanners._pin_requirements_files(str(checkout))

    assert modified == ["requirements.txt"]
    assert (checkout / "requirements.txt").read_text() == "flask==9.9.9\n"
    assert outside.read_text() == "requests\n"  # target of the symlink untouched


async def test_devskim_writes_its_report_outside_the_checkout(tmp_path, monkeypatch):
    # The repository is attacker-controlled: a symlink at the report's name would
    # make DevSkim write its SARIF through it, onto a file outside the checkout.
    checkout = tmp_path / "repo"
    checkout.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    try:
        os.symlink(victim, checkout / ".devskim-output.sarif")
    except OSError:
        pass  # Windows without the symlink privilege: the path check below still applies
    seen: dict[str, str] = {}

    async def fake_run_command(cmd, timeout=600):
        out = cmd[cmd.index("-O") + 1]
        seen["out"] = out
        with open(out, "w", encoding="utf-8") as handle:
            handle.write('{"runs": []}')
        return "", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)

    result = await scanners._run_devskim("https://example.org/r.git", "source_repo", source_dir=str(checkout))

    assert result.error is None
    assert result.report == {"runs": []}
    assert not os.path.realpath(seen["out"]).startswith(os.path.realpath(checkout))
    assert victim.read_text() == "untouched"
    assert not os.path.exists(os.path.dirname(seen["out"]))


async def test_pinning_asks_pypi_about_a_bounded_number_of_names(tmp_path, monkeypatch):
    # A hostile requirements.txt can list a million bare names; each one used to
    # cost a sequential PyPI request inside the sidecar process.
    asked: list[str] = []

    async def fake_latest(name):
        asked.append(name)
        return "1.0"

    monkeypatch.setattr(scanners, "_get_latest_pypi_version", fake_latest)
    (tmp_path / "requirements.txt").write_text("\n".join(f"pkg{n}" for n in range(2000)) + "\n")

    await scanners._pin_requirements_files(str(tmp_path))

    assert len(asked) == scanners._MAX_PINNED_PACKAGES
    lines = (tmp_path / "requirements.txt").read_text().splitlines()
    assert lines[0] == "pkg0==1.0"
    assert lines[-1] == "pkg1999"


async def test_pinning_stops_when_its_time_budget_runs_out(tmp_path, monkeypatch):
    asked: list[str] = []

    async def fake_latest(name):
        asked.append(name)
        return "1.0"

    monkeypatch.setattr(scanners, "_get_latest_pypi_version", fake_latest)
    monkeypatch.setattr(scanners, "_PIN_BUDGET_SECONDS", -1)
    (tmp_path / "requirements.txt").write_text("flask\nrequests\n")

    await scanners._pin_requirements_files(str(tmp_path))

    assert asked == []


async def test_pinning_skips_an_oversized_requirements_file(tmp_path, monkeypatch):
    async def fake_latest(name):
        raise AssertionError("an oversized file must not be parsed")

    monkeypatch.setattr(scanners, "_get_latest_pypi_version", fake_latest)
    monkeypatch.setattr("app.safe_files.MAX_PARSED_FILE_BYTES", 10)
    (tmp_path / "requirements.txt").write_text("flask\nrequests\n")

    assert await scanners._pin_requirements_files(str(tmp_path)) == []


def test_scanner_auth_is_only_sent_over_https(monkeypatch):
    monkeypatch.setattr(scanners, "_GIT_AUTH_MAP", {"git.corp.example": ("ci", "s3cret-token")})

    assert scanners._git_auth_args_for("https://git.corp.example/team/repo.git")
    assert scanners._git_auth_args_for("http://git.corp.example/team/repo.git") == []
    assert scanners._git_auth_args_for("git://git.corp.example/team/repo.git") == []


async def test_the_git_auth_header_never_reaches_the_log(monkeypatch, caplog):
    import base64
    import logging

    monkeypatch.setattr(scanners, "_GIT_AUTH_MAP", {"git.corp.example": ("ci", "s3cret-token")})
    cmd = ["git", *scanners._git_auth_args_for("https://git.corp.example/r.git"), "ls-remote", "--", "https://git.corp.example/r.git"]
    secret = base64.b64encode(b"ci:s3cret-token").decode()
    assert any(secret in arg for arg in cmd)

    with caplog.at_level(logging.DEBUG, logger=scanners.logger.name):
        await scanners._run_command(["python", "-c", "pass", *cmd[1:3]], timeout=30)

    assert secret not in caplog.text
    assert "<redacted>" in caplog.text


async def test_concurrent_dive_runs_do_not_share_files(monkeypatch):
    import asyncio
    import json

    archives: list[str] = []

    async def fake_run_command(cmd, timeout=600):
        if cmd[0] == "skopeo":
            archives.append(cmd[-1].removeprefix("docker-archive:"))
            await asyncio.sleep(0)
            return "", "", 0
        out = cmd[cmd.index("--json") + 1]
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"image": cmd[1]}))
        return "", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)

    first, second = await asyncio.gather(
        scanners._run_dive("registry.example/a:1", "container_image"),
        scanners._run_dive("registry.example/b:1", "container_image"),
    )

    assert len(set(archives)) == 2
    assert first.report["image"] != second.report["image"]
    assert not any(os.path.exists(os.path.dirname(path)) for path in archives)
