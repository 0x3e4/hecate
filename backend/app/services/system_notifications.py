"""Which systems and findings a ``system`` notification rule is about.

A ``system`` rule (``rule_type="system"``) watches the inventory's systems for
three events, listed in its ``event_types``:

- ``system_stale``: a system that reported before has sent no SBOM or scanner
  report for ``INVENTORY_SYSTEM_STALE_DAYS``. The moment it went stale is its
  last report plus that window; the scheduler sends what went stale since the
  rule's last evaluation (``last_evaluated_at``, claimed atomically, the first
  evaluation only sets it), so each silence is reported once, and again only
  after the system reported and fell silent anew. Systems that never reported
  are left out: a server list names many hosts that are not meant to push.
- ``system_findings``: a report brought findings the system's previous report
  did not have (same vulnerability in the same package counts as known, also
  at another version). Dismissed findings and ones whose VEX status is
  ``not_affected`` or ``fixed`` are not news. A first report counts in full.
- ``system_retired``: a server list in replace mode retired systems.

A rule narrows the systems with ``system_ids``, ``system_groups`` (any of) and
``system_exposure``; ``scan_severity_threshold`` is the lowest severity of a
new finding that is reported. Everything here is pure; sending lives in
``NotificationService``.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.schemas.inventory_system import InventorySystemResponse

SYSTEM_EVENTS = ("system_stale", "system_findings", "system_retired")

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
_RESOLVED_VEX = {"not_affected", "fixed"}


def system_matches(system: InventorySystemResponse, rule: dict[str, Any]) -> bool:
    ids = rule.get("system_ids") or []
    if ids and system.id not in ids:
        return False
    groups = {g.casefold() for g in rule.get("system_groups") or [] if isinstance(g, str)}
    if groups and not groups & {g.casefold() for g in system.groups}:
        return False
    exposure = rule.get("system_exposure")
    return not exposure or system.exposure == exposure


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def stale_moment(system: InventorySystemResponse, stale_days: int) -> datetime | None:
    """When the system went (or goes) stale; ``None`` for retired or never-reporting systems."""
    if system.retired_at is not None or system.last_report_at is None:
        return None
    return _aware(system.last_report_at) + timedelta(days=stale_days)


def went_stale(system: InventorySystemResponse, since: datetime, until: datetime, stale_days: int) -> bool:
    moment = stale_moment(system, stale_days)
    return moment is not None and _aware(since) < moment <= _aware(until)


def finding_key(finding: dict[str, Any]) -> tuple[str, str]:
    vuln = finding.get("vulnerability_id") or finding.get("title") or ""
    return str(vuln).upper(), str(finding.get("package_name") or "").casefold()


def is_open(finding: dict[str, Any]) -> bool:
    return not finding.get("dismissed") and finding.get("vex_status") not in _RESOLVED_VEX


def severity_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity") or "unknown").lower(), 0)


def new_findings(
    current: list[dict[str, Any]], previous: list[dict[str, Any]], threshold: str | None,
) -> list[dict[str, Any]]:
    """Open findings of the current report the previous one did not have, worst first, one per key."""
    known = {finding_key(f) for f in previous}
    floor = _SEVERITY_RANK.get(threshold or "", 0)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in current:
        key = finding_key(finding)
        if key in known or not key[0] or not is_open(finding) or severity_rank(finding) < floor:
            continue
        kept = found.get(key)
        if kept is None or severity_rank(finding) > severity_rank(kept):
            found[key] = finding
    return sorted(found.values(), key=lambda f: (-severity_rank(f), -(f.get("cvss_score") or 0), finding_key(f)))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts
