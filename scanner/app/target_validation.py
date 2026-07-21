"""Validation of user-supplied scan targets before they reach any subprocess.

A scan ``target`` flows straight into an argv list — ``git clone <url>``,
``git ls-remote <url>``, ``skopeo inspect docker://<ref>``, ``trivy image
<ref>`` and so on. Because the value is attacker-controllable (anyone who can
register a scan target), an unguarded target is a command/argument/transport
injection vector even though every subprocess is spawned with an argv list
(no shell):

  * a leading ``-`` is parsed by the tool as a CLI option
    (``--upload-pack=…``, ``-oProxyCommand=…``) → argument injection;
  * git's transport-helper syntax ``ext::sh -c '…'`` runs an arbitrary
    command; ``file://`` / local paths read the container filesystem;
  * shell/control characters have no place in a URL or image reference.

This module is the single boundary that rejects a hostile target for *every*
downstream tool in one place. It complements — but does not replace — the
``--`` end-of-options separator and the ``GIT_ALLOW_PROTOCOL`` allow-list pin
applied to the git subprocesses in ``scanners.py`` (defence in depth).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Network transports we are willing to hand to git. Deliberately excludes
# ``ext``/``fd``/``file`` and any other local/helper transport.
_ALLOWED_GIT_SCHEMES = {"http", "https", "git", "ssh"}

# Conservative image-reference charset: registry[:port]/namespace/name[:tag]
# [@sha256:…]. No shell metacharacters, no leading ``-`` (enforced separately).
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")


class UnsafeScanTarget(ValueError):
    """Raised when a scan target could inject into a subprocess invocation."""


def _has_space_or_control(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 0x20 for ch in value)


def validate_source_repo_target(target: str) -> None:
    """Raise :class:`UnsafeScanTarget` unless *target* is a safe git URL."""
    t = (target or "").strip()
    if not t:
        raise UnsafeScanTarget("empty repository URL")
    if t.startswith("-"):
        raise UnsafeScanTarget("repository URL must not start with '-'")
    if "::" in t:
        raise UnsafeScanTarget(
            "repository URL must not contain '::' (git transport-helper syntax)"
        )
    if _has_space_or_control(t):
        raise UnsafeScanTarget(
            "repository URL must not contain whitespace or control characters"
        )
    parsed = urlparse(t)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_GIT_SCHEMES:
        raise UnsafeScanTarget(
            "repository URL scheme must be one of "
            f"{sorted(_ALLOWED_GIT_SCHEMES)} (got {parsed.scheme!r})"
        )
    if not parsed.hostname:
        raise UnsafeScanTarget("repository URL must include a host")


def validate_container_image_target(target: str) -> None:
    """Raise :class:`UnsafeScanTarget` unless *target* is a safe image ref."""
    t = (target or "").strip()
    if not t:
        raise UnsafeScanTarget("empty image reference")
    if t.startswith("-"):
        raise UnsafeScanTarget("image reference must not start with '-'")
    if "://" in t or "::" in t:
        raise UnsafeScanTarget(
            "image reference must not contain a URL scheme or '::'"
        )
    if _has_space_or_control(t):
        raise UnsafeScanTarget(
            "image reference must not contain whitespace or control characters"
        )
    if not _IMAGE_REF_RE.match(t):
        raise UnsafeScanTarget("image reference contains disallowed characters")


def validate_scan_target(target: str, target_type: str) -> None:
    """Validate *target* according to *target_type*.

    Unknown types (e.g. ``sbom-import``) never reach a subprocess and are left
    untouched.
    """
    if target_type == "source_repo":
        validate_source_repo_target(target)
    elif target_type == "container_image":
        validate_container_image_target(target)
