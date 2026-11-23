"""Checks: scans without a target, kept out of every list, deleted after a while.

A check runs like any scan but registers no target. Its scan, findings and SBOM
rows carry a pseudo target id starting with ``check:``, and every query that
reads across targets (scan list, latest scan per target, consolidated findings
and SBOM, coverage, the "Affected in your scans" block, the MAL-* watcher, VEX
rules) leaves those out. The report is reachable by scan id only. Scans made by
the older one-time upload (``one-time-upload:``) count as checks too, so they
drop out of the lists without a migration; they have no expiry and stay until
deleted.

The scan document carries ``check: True`` and ``expires_at``; the
``sca_check_cleanup`` job deletes expired checks with their rows.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from uuid import uuid4

from app.core.config import settings

CHECK_TARGET_PREFIX = "check:"
LEGACY_ONE_TIME_PREFIX = "one-time-upload:"
CHECK_TARGET_PATTERN = re.compile(r"^(?:check|one-time-upload):")


def is_check_target(target_id: object) -> bool:
    return isinstance(target_id, str) and CHECK_TARGET_PATTERN.match(target_id) is not None


def not_check_target() -> dict[str, object]:
    """A MongoDB condition on ``target_id`` that excludes checks."""
    return {"$not": CHECK_TARGET_PATTERN}


def new_check_target_id() -> str:
    return f"{CHECK_TARGET_PREFIX}{uuid4().hex}"


def check_expires_at(now: datetime) -> datetime:
    return now + timedelta(days=max(1, settings.sca_check_retention_days))
