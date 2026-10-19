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
