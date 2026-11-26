"""Notification rules on inventory systems: stopped reporting, new findings, retired by a list."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException

from app.api.v1.notifications import _check_rule
from app.core.config import settings
from app.repositories import notification_rule_repository
from app.repositories.notification_rule_repository import NotificationRuleRepository
from app.schemas.inventory_system import InventorySystemCreateRequest, InventorySystemResponse
from app.schemas.notification import NotificationRuleCreate
from app.services import inventory_system_service
from app.services.inventory_system_lists import parse_system_list
from app.services.inventory_system_service import get_inventory_system_service
from app.services.notification_service import NotificationService
from app.services.scan_service import ScanService
from app.services.system_notifications import new_findings, system_matches, went_stale

from tests.fake_mongo import FakeCollection

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _system(**fields: Any) -> InventorySystemResponse:
    return InventorySystemResponse.model_validate({
        "id": "s1", "name": "web-01", "createdAt": NOW, "updatedAt": NOW, **fields,
    })


# ---------------------------------------------------------------- pure rules


@pytest.mark.parametrize(
    ("rule", "fields", "expected"),
    [
        ({}, {}, True),
        ({"system_ids": ["s1"]}, {}, True),
        ({"system_ids": ["s2"]}, {}, False),
        ({"system_groups": ["EDGE"]}, {"groups": ["edge", "vienna"]}, True),
        ({"system_groups": ["db"]}, {"groups": ["edge"]}, False),
        ({"system_exposure": "internet"}, {"exposure": "internet"}, True),
        ({"system_exposure": "internet"}, {"exposure": None}, False),
        ({"system_exposure": "internet", "system_groups": ["edge"]}, {"exposure": "internet", "groups": []}, False),
    ],
)
def test_a_rule_narrows_the_systems(rule: dict[str, Any], fields: dict[str, Any], expected: bool) -> None:
    assert system_matches(_system(**fields), rule) is expected


def test_a_system_goes_stale_once_its_window_has_passed() -> None:
    last = NOW - timedelta(days=3, hours=1)  # stale since an hour ago with a 3-day window
    system = _system(lastReportAt=last)
    assert went_stale(system, NOW - timedelta(hours=2), NOW, 3)
    assert not went_stale(system, NOW - timedelta(minutes=30), NOW, 3)  # already reported in an earlier window
    assert not went_stale(_system(lastReportAt=NOW - timedelta(days=1)), NOW - timedelta(hours=2), NOW, 3)
    # Never reported, or retired: never "stopped reporting".
    assert not went_stale(_system(), NOW - timedelta(days=30), NOW, 3)
    assert not went_stale(_system(lastReportAt=last, retiredAt=NOW), NOW - timedelta(hours=2), NOW, 3)


def _finding(vuln: str, package: str = "openssl", version: str = "3.0.1", severity: str = "high", **extra: Any) -> dict[str, Any]:
    return {"vulnerability_id": vuln, "package_name": package, "package_version": version, "severity": severity, **extra}


def test_new_findings_are_what_the_previous_report_did_not_have() -> None:
    previous = [_finding("CVE-1"), _finding("CVE-2", "zlib")]
    current = [
        _finding("cve-1", version="3.0.2"),  # same vulnerability, same package, newer version: known
        _finding("CVE-2", "ZLIB"),  # package names compare case-insensitively
        _finding("CVE-3", severity="critical", cvss_score=9.8),
        _finding("CVE-3", "libssl3", severity="medium"),  # another package: its own finding
        _finding("CVE-4", severity="low"),
        _finding("CVE-5", dismissed=True),
        _finding("CVE-6", vex_status="not_affected"),
        _finding("CVE-7", vex_status="fixed"),
        _finding("CVE-8", vex_status="under_investigation", severity="high", cvss_score=7.5),
        _finding("CVE-3", severity="high"),  # the same key twice: the worse one is kept
    ]
    found = new_findings(current, previous, None)
    assert [(f["vulnerability_id"], f["package_name"], f["severity"]) for f in found] == [
        ("CVE-3", "openssl", "critical"), ("CVE-8", "openssl", "high"),
        ("CVE-3", "libssl3", "medium"), ("CVE-4", "openssl", "low"),
    ]
    assert [f["vulnerability_id"] for f in new_findings(current, previous, "high")] == ["CVE-3", "CVE-8"]
    assert len(new_findings(current, [], "critical")) == 1


def test_rule_validation() -> None:
    def rule(**fields: Any) -> NotificationRuleCreate:
        return NotificationRuleCreate.model_validate({"name": "r", "ruleType": "system", **fields})

    _check_rule(rule(eventTypes=["system_stale", "system_findings"], systemExposure="internet"))
    for bad in ([], ["scan_completed"], ["system_stale", "nope"]):
        with pytest.raises(HTTPException):
            _check_rule(rule(eventTypes=bad))
    with pytest.raises(ValueError):
        rule(eventTypes=["system_stale"], systemExposure="dmz")


# ---------------------------------------------------------------- sending


@pytest.fixture
def rules(monkeypatch: pytest.MonkeyPatch) -> NotificationRuleRepository:
    repo = NotificationRuleRepository(FakeCollection())

    async def create(cls: Any = None) -> NotificationRuleRepository:
        return repo

    monkeypatch.setattr(notification_rule_repository.NotificationRuleRepository, "create", classmethod(create))
    monkeypatch.setattr(settings, "notifications_enabled", True)
    return repo


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    async def send(self: NotificationService, title: str, body: str, *, notify_type: str = "info", tag: str | None = None) -> bool:
        out.append({"title": title, "body": body, "type": notify_type, "tag": tag})
        return True

    async def no_template(self: NotificationService, event_key: str, tag: str | None) -> None:
        return None

    monkeypatch.setattr(NotificationService, "send", send)
    monkeypatch.setattr(NotificationService, "_resolve_template", no_template)
    return out


async def _add_rule(repo: NotificationRuleRepository, rule_id: str, events: list[str], **fields: Any) -> None:
    await repo.insert(rule_id, {
        "name": rule_id, "enabled": True, "rule_type": "system", "apprise_tag": "ops",
        "event_types": events, "last_evaluated_at": None, **fields,
    })


async def _reporting_system(name: str, last_report: datetime, **fields: Any) -> str:
    svc = get_inventory_system_service()
    target_id = f"sbom-import-{name}"
    (await svc.target_repo()).collection.docs.append({"_id": target_id, "type": "sbom-import", "name": name, "last_scan_at": last_report})
    created = await svc.create_system(InventorySystemCreateRequest(name=name, **fields))
    assert created.target_id == target_id
    return created.id


async def test_stopped_reporting_is_sent_once_after_the_first_evaluation(
    rules: NotificationRuleRepository, sent: list[dict[str, Any]],
) -> None:
    stale_days = settings.inventory_system_stale_days
    await _reporting_system("web-01", NOW - timedelta(days=stale_days, hours=1), kind="host", exposure="internet")
    await _reporting_system("db-01", NOW - timedelta(days=stale_days, hours=2), kind="host", exposure="internal")
    await _reporting_system("web-02", NOW - timedelta(hours=5), exposure="internet")
    await get_inventory_system_service().create_system(InventorySystemCreateRequest(name="never-01", exposure="internet"))
    await _add_rule(rules, "all", ["system_stale"])
    await _add_rule(rules, "internet", ["system_stale"], system_exposure="internet")
    await _add_rule(rules, "findings-only", ["system_findings"])

    service = NotificationService()
    # The first evaluation only sets the watermark, however much is stale already.
    assert await service.evaluate_system_stale_rules(NOW - timedelta(hours=3)) == 0
    assert sent == []

    assert await service.evaluate_system_stale_rules(NOW) == 2
    by_tag_title = sorted(m["title"] for m in sent)
    assert by_tag_title == [
        "⏸ Hecate — 1 system stopped reporting",
        "⏸ Hecate — 2 systems stopped reporting",
    ]
    everything = next(m for m in sent if "2 systems" in m["title"])
    assert "web-01" in everything["body"] and "db-01" in everything["body"]
    assert "never-01" not in everything["body"] and "web-02" not in everything["body"]
    assert everything["tag"] == "ops" and everything["type"] == "warning"
    assert (await rules.get("findings-only"))["last_evaluated_at"] is None

    # Already reported: the next run sends nothing.
    assert await service.evaluate_system_stale_rules(NOW + timedelta(minutes=30)) == 0


async def test_new_findings_on_a_report(rules: NotificationRuleRepository, sent: list[dict[str, Any]]) -> None:
    web = await _reporting_system("web-01", NOW, exposure="internet", groups=["edge"])
    db = await _reporting_system("db-01", NOW, exposure="internal")
    await _add_rule(rules, "edge-high", ["system_findings"], system_groups=["edge"], scan_severity_threshold="high")
    loads: list[str] = []

    def loader(current: list[dict[str, Any]], previous: list[dict[str, Any]] | None) -> Any:
        async def load() -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
            loads.append("x")
            return current, previous
        return load

    service = NotificationService()
    # A system no rule covers: the findings are never even read.
    assert await service.notify_system_report(system_id=db, scan_id="s9", load_findings=loader([_finding("CVE-9")], None)) == 0
    assert loads == []

    # Only a low finding is new: below the rule's threshold.
    assert await service.notify_system_report(
        system_id=web, scan_id="s2", load_findings=loader([_finding("CVE-1"), _finding("CVE-2", severity="low")], [_finding("CVE-1")]),
    ) == 0
    assert sent == []

    current = [_finding("CVE-1"), _finding("CVE-3", severity="critical", fix_version="3.0.9"), _finding("CVE-4", "curl")]
    assert await service.notify_system_report(
        system_id=web, scan_id="s3", load_findings=loader(current, [_finding("CVE-1")]),
    ) == 1
    message = sent[-1]
    assert message["title"] == "\U0001f5a5 Hecate — 2 new findings on web-01"
    assert "new since the previous report): 2 (C:1 H:1 M:0 L:0)" in message["body"]
    assert "CVE-3 — critical — openssl 3.0.1 (fix 3.0.9)" in message["body"]
    assert message["type"] == "failure"

    # A first report counts in full.
    await service.notify_system_report(system_id=web, scan_id="s1", load_findings=loader([_finding("CVE-1")], None))
    assert "(first report): 1" in sent[-1]["body"]
    assert (await rules.get("edge-high"))["last_triggered_at"] is not None


async def test_a_replace_list_reports_what_it_retired(
    rules: NotificationRuleRepository, sent: list[dict[str, Any]],
) -> None:
    svc = get_inventory_system_service()
    await svc.apply_list(parse_system_list("web-01\nweb-02\ndb-01\n", "text"), source="cmdb", mode="merge")
    await _add_rule(rules, "retired", ["system_retired"])
    await svc.apply_list(parse_system_list("web-01\n", "text"), source="cmdb", mode="replace", force=True)
    await asyncio.gather(*inventory_system_service._notification_tasks)
    assert len(sent) == 1
    assert sent[0]["title"] == "\U0001f5c4 Hecate — 2 systems retired by cmdb"
    assert "web-02 (last report: never)" in sent[0]["body"] and "db-01" in sent[0]["body"]

    # A preview retires nothing and sends nothing.
    preview = await svc.apply_list(
        parse_system_list("other\n", "text"), source="cmdb", mode="replace", dry_run=True, force=True,
    )
    assert preview.retired == ["web-01"]
    assert len(inventory_system_service._notification_tasks) == 0 and len(sent) == 1


async def test_nothing_is_sent_with_notifications_off(
    rules: NotificationRuleRepository, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "notifications_enabled", False)
    await _add_rule(rules, "all", ["system_stale", "system_findings", "system_retired"])
    service = NotificationService()
    assert await service.evaluate_system_stale_rules(NOW) == 0
    assert (await rules.get("all"))["last_evaluated_at"] is None
    assert await service.notify_systems_retired(source="cmdb", names=["x"]) == 0


class _Findings:
    def __init__(self) -> None:
        self.read: list[str] = []

    async def list_brief_by_scan(self, scan_id: str, limit: int = 50_000) -> list[dict[str, Any]]:
        self.read.append(scan_id)
        return [_finding("CVE-1")] if scan_id == "old" else [_finding("CVE-1"), _finding("CVE-2")]


async def test_an_import_hands_the_reports_to_the_notifier(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    class Notifier:
        async def notify_system_report(self, **kwargs: Any) -> int:
            current, previous = await kwargs["load_findings"]()
            calls.append({**kwargs, "current": current, "previous": previous})
            return 1

    monkeypatch.setattr(settings, "notifications_enabled", True)
    monkeypatch.setattr("app.services.scan_service.get_notification_service", lambda: Notifier())
    scans = ScanService.__new__(ScanService)
    scans.finding_repo = _Findings()
    scans._schedule_system_report_notification("sys-1", "new", "old")
    scans._schedule_system_report_notification("sys-1", "first", None)
    from app.services import scan_service

    await asyncio.gather(*scan_service._release_info_tasks)
    assert [(c["system_id"], c["scan_id"], len(c["current"]), c["previous"] is None) for c in calls] == [
        ("sys-1", "new", 2, False), ("sys-1", "first", 2, True),
    ]
    assert scans.finding_repo.read == ["new", "old", "first"]
