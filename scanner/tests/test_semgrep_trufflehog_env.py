"""Semgrep runs with its own HOME under the temp dir; TruffleHog's verification can be switched off."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from app import scanners


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict] = []

    async def fake_run_command(cmd, timeout=600, env=None):
        calls.append({"cmd": cmd, "env": env})
        if cmd[0] == "semgrep":
            # What semgrep does with HOME: settings, log and caches below it.
            home = env["HOME"]
            os.makedirs(os.path.join(home, ".semgrep"), exist_ok=True)
            with open(os.path.join(home, ".semgrep", "settings.yml"), "w") as fh:
                fh.write("has_shown_metrics_notification: true\n")
            return json.dumps({"results": [], "errors": []}), "", 0
        return "", "", 0

    monkeypatch.setattr(scanners, "_run_command", fake_run_command)
    return calls


async def test_semgrep_gets_its_own_home_under_the_temp_dir(recorded, tmp_path):
    result = await scanners._run_semgrep("https://example.invalid/r.git", "source_repo", source_dir=str(tmp_path))

    assert result.error is None
    env = recorded[0]["env"]
    home = env["HOME"]
    assert os.path.dirname(home) == tempfile.gettempdir()
    assert os.path.basename(home).startswith("hecate-semgrep-")
    assert env["XDG_CONFIG_HOME"] == os.path.join(home, ".config")
    assert env["XDG_CACHE_HOME"] == os.path.join(home, ".cache")
    assert home != os.environ.get("HOME")
    # Removed after the run, with what semgrep wrote into it.
    assert not os.path.exists(home)


async def test_each_semgrep_run_has_a_fresh_home(recorded, tmp_path):
    await scanners._run_semgrep("x", "source_repo", source_dir=str(tmp_path))
    await scanners._run_semgrep("x", "source_repo", source_dir=str(tmp_path))
    assert recorded[0]["env"]["HOME"] != recorded[1]["env"]["HOME"]


async def test_semgrep_home_keeps_the_rest_of_the_environment(recorded, tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "off")
    await scanners._run_semgrep("x", "source_repo", source_dir=str(tmp_path))
    assert recorded[0]["env"]["SEMGREP_SEND_METRICS"] == "off"


async def test_semgrep_skips_images_without_creating_a_home(recorded):
    before = set(os.listdir(tempfile.gettempdir()))
    result = await scanners._run_semgrep("nginx:latest", "container_image")
    assert result.error and recorded == []
    assert not {n for n in set(os.listdir(tempfile.gettempdir())) - before if n.startswith("hecate-semgrep-")}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, False), ("", False), ("0", False), ("false", False), ("no", False), ("1", True), ("true", True), (" Yes ", True), ("ON", True)],
)
async def test_trufflehog_verification_switch(recorded, tmp_path, monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("TRUFFLEHOG_NO_VERIFICATION", raising=False)
    else:
        monkeypatch.setenv("TRUFFLEHOG_NO_VERIFICATION", value)

    await scanners._run_trufflehog("x", "source_repo", source_dir=str(tmp_path))

    cmd = recorded[0]["cmd"]
    assert ("--no-verification" in cmd) is expected
    # The path stays the last argument.
    assert cmd[-1] == str(tmp_path)
    assert cmd[:4] == ["trufflehog", "filesystem", "--json", "--no-update"]
