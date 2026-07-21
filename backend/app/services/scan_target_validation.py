"""Validation of user-supplied scan targets at the API boundary.

A scan ``target`` is eventually handed to a subprocess argv on the scanner
sidecar (``git clone <url>``, ``skopeo inspect docker://<ref>``, ``trivy image
<ref>`` …). Rejecting a hostile target here — before it is ever stored on a
``ScanTargetDocument`` or dispatched — gives the user a clear 400 and keeps the
malicious value out of the database entirely.

This mirrors ``scanner/app/target_validation.py`` (the two run in separate
containers with no shared import path, so the small module is intentionally
duplicated; keep the two in sync). The scanner copy is the authoritative
security boundary — it also pins ``GIT_ALLOW_PROTOCOL`` and inserts ``--`` into
the git argv — this copy is the early, user-facing guard.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_ALLOWED_GIT_SCHEMES = {"http", "https", "git", "ssh"}
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
