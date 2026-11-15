"""Whether a person's VEX assessment of a finding needs another look."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, date, datetime
from typing import Any


def _norm(version: Any) -> str:
    v = (version or "").strip() if isinstance(version, str) else ""
    return v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v


def review_state(finding: Mapping[str, Any], today: date | None = None) -> tuple[bool, str | None]:
    """``(needs_review, reason)``; reason is ``version_changed`` or ``review_due``.

    The version check compares the version the status was assessed at with
    the finding's own; the flag carry-forward stored keeps a change seen in
    an earlier scan. A re-review date that has passed flags it too.
    """
    if not finding.get("vex_status"):
        return False, None
    assessed = finding.get("vex_assessed_version")
    if assessed and _norm(assessed) != _norm(finding.get("package_version")):
        return True, "version_changed"
    due = finding.get("vex_review_due")
    if isinstance(due, str) and due:
        today = today or datetime.now(tz=UTC).date()
        try:
            if date.fromisoformat(due[:10]) < today:
                return True, "review_due"
        except ValueError:
            pass
    if finding.get("vex_needs_review"):
        return True, "version_changed"
    return False, None
