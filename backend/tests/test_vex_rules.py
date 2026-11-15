"""Automatic VEX rules, review evidence, and who may overwrite whose status."""
from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from bson import ObjectId
from fake_mongo import FakeCollection

from app.repositories.scan_finding_repository import (
    ScanFindingRepository,
    carried_vex_fields,
    is_automated_vex_actor,
    records_assessment,
)
from app.schemas.vex_rule import VexRuleAction, VexRuleConditions, VexRuleRequest
from app.services.vex_review import review_state
from app.services.vex_rule_service import (
    PRESETS,
    ParsedRule,
    RuleContext,
    conditions_match,
    plan_rule_updates,
    vulnerability_platforms,
)

LINUX_IMAGE = {"target_id": "ghcr.io/acme/web", "name": "web", "type": "container_image", "group": "Shop"}


def _finding(**kw: Any) -> dict[str, Any]:
    base = {
        "_id": kw.pop("_id", "f1"),
        "vulnerability_id": "CVE-2026-1",
        "package_name": "lodash",
        "package_version": "4.17.20",
        "package_type": "npm",
        "severity": "medium",
        "dependency_scope": "dev",
        "vex_status": None,
        "vex_updated_by": None,
        "dismissed": False,
        "dismissed_by": None,
    }
    base.update(kw)
    return base


def _cond(**kw: Any) -> VexRuleConditions:
    return VexRuleConditions.model_validate(kw)


def _rule(rule_id: str = "r1", dismiss: bool = False, **conditions: Any) -> ParsedRule:
    return ParsedRule(
        id=rule_id,
        name=f"Rule {rule_id}",
        conditions=_cond(**conditions),
        action=VexRuleAction(vex_status="not_affected", vex_justification="code_not_reachable",
                             vex_detail="dev only", dismiss=dismiss),
    )


# ---------------------------------------------------------------- conditions


def test_empty_conditions_never_match() -> None:
    assert not conditions_match(_cond(), _finding(), RuleContext(target=LINUX_IMAGE))


@pytest.mark.parametrize(
    ("conditions", "finding", "expected"),
    [
        ({"target_pattern": "ghcr.io/acme/*"}, {}, True),
        ({"target_pattern": "WEB"}, {}, True),  # name, case-insensitive
        ({"target_pattern": "other/*"}, {}, False),
        ({"target_group": "shop"}, {}, True),
        ({"target_group": "other"}, {}, False),
        ({"target_types": ["container_image"]}, {}, True),
        ({"target_types": ["source_repo"]}, {}, False),
        ({"dependency_scopes": ["dev"]}, {}, True),
        ({"dependency_scopes": ["runtime"]}, {}, False),
        ({"dependency_scopes": ["unknown"]}, {"dependency_scope": None}, True),
        ({"package_pattern": "lod*"}, {}, True),
        ({"package_pattern": "react*"}, {}, False),
        ({"ecosystems": ["npm"]}, {}, True),
        ({"ecosystems": ["pypi"]}, {}, False),
        ({"max_severity": "medium"}, {}, True),
        ({"max_severity": "low"}, {}, False),
        ({"max_severity": "critical"}, {"severity": "unknown"}, False),  # unknown never matches a cap
        ({"cwe_ids": ["400", "CWE-1333"]}, {}, True),
        ({"cwe_ids": ["CWE-79"]}, {}, False),
        ({"dependency_scopes": ["dev"], "cwe_ids": ["CWE-79"]}, {}, False),  # AND
    ],
)
def test_each_condition(conditions: dict[str, Any], finding: dict[str, Any], expected: bool) -> None:
    ctx = RuleContext(target=LINUX_IMAGE, vuln_cwes={"CVE-2026-1": {"CWE-400"}})
    assert conditions_match(_cond(**conditions), _finding(**finding), ctx) is expected


def test_ecosystem_prefers_the_sbom_purl_type() -> None:
    ctx = RuleContext(target=LINUX_IMAGE, purl_types={("lodash", "4.17.20"): "npm"})
    assert conditions_match(_cond(ecosystems=["npm"]), _finding(package_type="library"), ctx)
    assert not conditions_match(_cond(ecosystems=["npm"]), _finding(package_type="library"), RuleContext(target=LINUX_IMAGE))


# ---------------------------------------------------------------- platform


def _match(criteria: str, vulnerable: bool) -> dict[str, Any]:
    return {"criteria": criteria, "vulnerable": vulnerable}


WINDOWS_RUNNING_ON = {"cpe_configurations": [{"nodes": [
    {"operator": "OR", "matches": [_match("cpe:2.3:a:acme:agent:*:*:*:*:*:node.js:*:*", True)]},
    {"operator": "OR", "matches": [_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False)]},
]}]}
WINDOWS_OS = {"cpe_configurations": [{"nodes": [
    {"operator": "OR", "matches": [_match("cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*", True)]},
]}]}


def test_platforms_from_cpe_configurations() -> None:
    assert vulnerability_platforms(WINDOWS_RUNNING_ON) == {"windows"}
    assert vulnerability_platforms(WINDOWS_OS) == {"windows"}
    apple = {"cpe_configurations": [{"nodes": [
        {"matches": [_match("cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", True),
                     _match("cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*", True)]},
    ]}]}
    assert vulnerability_platforms(apple) == {"macos", "ios"}


@pytest.mark.parametrize(
    "doc",
    [
        {},  # no configurations at all
        {"cpe_configurations": []},
        # an application without a platform node runs anywhere
        {"cpe_configurations": [{"nodes": [{"matches": [_match("cpe:2.3:a:acme:agent:*:*:*:*:*:*:*:*", True)]}]}]},
        # one Windows configuration and one unrestricted one
        {"cpe_configurations": WINDOWS_RUNNING_ON["cpe_configurations"] + [
            {"nodes": [{"matches": [_match("cpe:2.3:a:acme:agent:*:*:*:*:*:*:*:*", True)]}]},
        ]},
        # running on Windows or Linux
        {"cpe_configurations": [{"nodes": [
            {"matches": [_match("cpe:2.3:a:acme:agent:*:*:*:*:*:*:*:*", True)]},
            {"matches": [_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False),
                         _match("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", False)]},
        ]}]},
        # negated node
        {"cpe_configurations": [{"nodes": [
            {"matches": [_match("cpe:2.3:a:acme:agent:*:*:*:*:*:*:*:*", True)]},
            {"negate": True, "matches": [_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False)]},
        ]}]},
        # no explicit vulnerable flag: the data says nothing
        {"cpe_configurations": [{"nodes": [
            {"matches": [{"criteria": "cpe:2.3:a:acme:agent:*:*:*:*:*:*:*:*"}]},
            {"matches": [_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False)]},
        ]}]},
        # Android is not treated as a different OS from Linux
        {"cpe_configurations": [{"nodes": [{"matches": [_match("cpe:2.3:o:google:android:*:*:*:*:*:*:*:*", True)]}]}]},
    ],
)
def test_platforms_fail_closed(doc: dict[str, Any]) -> None:
    assert vulnerability_platforms(doc) is None


def test_platform_condition_needs_a_linux_target_and_a_restricted_vulnerability() -> None:
    cond = _cond(platform_mismatch=True)
    windows = {"CVE-2026-1": frozenset({"windows"})}
    assert conditions_match(cond, _finding(), RuleContext(target=LINUX_IMAGE, target_os="linux", vuln_platforms=windows))
    # target OS unknown (e.g. a source repository or a Windows image)
    assert not conditions_match(cond, _finding(), RuleContext(target=LINUX_IMAGE, target_os=None, vuln_platforms=windows))
    # vulnerability not restricted / not loaded
    assert not conditions_match(cond, _finding(), RuleContext(target=LINUX_IMAGE, target_os="linux",
                                                              vuln_platforms={"CVE-2026-1": None}))
    assert not conditions_match(cond, _finding(), RuleContext(target=LINUX_IMAGE, target_os="linux"))


# ---------------------------------------------------------------- applying


@pytest.mark.parametrize(
    "actor",
    ["user", "Claude - MCP", "vex-import", "vex-source", "reachability:govulncheck", "carry-forward"],
)
def test_rules_never_overwrite_other_writers(actor: str) -> None:
    finding = _finding(vex_status="affected", vex_updated_by=actor)
    updates, applied, cleared = plan_rule_updates([finding], [_rule()], RuleContext(target=LINUX_IMAGE))
    assert (updates, applied, cleared) == ([], 0, 0)


def test_rule_fills_empty_findings_and_is_idempotent() -> None:
    finding = _finding()
    updates, applied, _ = plan_rule_updates([finding], [_rule(dependency_scopes=["dev"])], RuleContext(target=LINUX_IMAGE))
    assert applied == 1
    (_, fields), = updates
    assert fields["vex_status"] == "not_affected"
    assert fields["vex_updated_by"] == "vex-rule:r1"
    assert fields["vex_justification"] == "code_not_reachable"
    finding.update(fields)
    again, applied, cleared = plan_rule_updates([finding], [_rule(dependency_scopes=["dev"])], RuleContext(target=LINUX_IMAGE))
    assert (again, applied, cleared) == ([], 0, 0)


def test_first_matching_rule_wins_and_a_rule_may_take_over_another_rules_finding() -> None:
    finding = _finding(vex_status="under_investigation", vex_updated_by="vex-rule:old")
    rules = [_rule("a", package_pattern="react*"), _rule("b", dependency_scopes=["dev"]), _rule("c", ecosystems=["npm"])]
    updates, applied, _ = plan_rule_updates([finding], rules, RuleContext(target=LINUX_IMAGE))
    assert applied == 1 and updates[0][1]["vex_updated_by"] == "vex-rule:b"


def test_status_is_cleared_when_its_rule_no_longer_matches() -> None:
    finding = _finding(vex_status="not_affected", vex_updated_by="vex-rule:r1", dependency_scope="runtime",
                       dismissed=True, dismissed_by="vex-rule:r1")
    updates, applied, cleared = plan_rule_updates([finding], [_rule(dependency_scopes=["dev"])], RuleContext(target=LINUX_IMAGE))
    assert (applied, cleared) == (0, 1)
    fields = updates[0][1]
    assert fields["vex_status"] is None and fields["vex_updated_by"] is None
    assert fields["dismissed"] is False


def test_dismiss_action_never_touches_a_personal_dismissal() -> None:
    rule = _rule(dismiss=True, dependency_scopes=["dev"])
    updates, _, _ = plan_rule_updates([_finding()], [rule], RuleContext(target=LINUX_IMAGE))
    assert updates[0][1]["dismissed"] is True and updates[0][1]["dismissed_by"] == "vex-rule:r1"
    mine = _finding(dismissed=True, dismissed_by="user")
    updates, _, _ = plan_rule_updates([mine], [rule], RuleContext(target=LINUX_IMAGE))
    assert "dismissed" not in updates[0][1]


async def test_retiring_a_rule_clears_only_its_own_statuses() -> None:
    coll = FakeCollection([
        _finding(_id="a", vex_status="not_affected", vex_updated_by="vex-rule:r1", dismissed=True, dismissed_by="vex-rule:r1"),
        _finding(_id="b", vex_status="not_affected", vex_updated_by="vex-rule:r2"),
        _finding(_id="c", vex_status="affected", vex_updated_by="user"),
    ])
    repo = ScanFindingRepository(coll)  # type: ignore[arg-type]
    assert await repo.clear_vex_actor("vex-rule:r1") == 1
    assert coll.by_id("a")["vex_status"] is None and coll.by_id("a")["dismissed"] is False
    assert coll.by_id("b")["vex_status"] == "not_affected"
    assert coll.by_id("c")["vex_status"] == "affected"


def test_presets_are_valid_and_carry_conditions() -> None:
    for preset in PRESETS:
        request = VexRuleRequest(name=preset["name"], conditions=preset["conditions"], action=preset["action"])
        assert not request.conditions.is_empty()
        assert request.enabled is False


def test_rule_schema_validation() -> None:
    cond = _cond(cwe_ids=["400", "cwe-1333", "CWE-400"], ecosystems=["NPM"])
    assert cond.cwe_ids == ["CWE-400", "CWE-1333"]
    assert cond.ecosystems == ["npm"]
    with pytest.raises(ValueError):
        _cond(cwe_ids=["XSS"])
    with pytest.raises(ValueError):
        VexRuleAction(vex_status="not_affected", vex_justification="because")


# ---------------------------------------------------------------- precedence helpers


def test_actor_classes() -> None:
    assert is_automated_vex_actor("vex-source")
    assert is_automated_vex_actor("vex-rule:abc")
    assert is_automated_vex_actor("reachability:govulncheck")
    assert not is_automated_vex_actor("user")
    assert records_assessment("user") and records_assessment("Claude - MCP")
    assert not records_assessment("vex-import") and not records_assessment("vex-rule:x")


# ---------------------------------------------------------------- carry-forward + review


def test_carry_forward_keeps_automated_actors() -> None:
    for actor in ("vex-source", "vex-rule:r1", "reachability:govulncheck"):
        fields = carried_vex_fields({"vex_status": "not_affected", "vex_updated_by": actor}, {"package_version": "2"})
        assert fields["vex_updated_by"] == actor
        assert fields["vex_needs_review"] is False


def test_carry_forward_flags_a_version_change_since_the_assessment() -> None:
    old = {"vex_status": "not_affected", "vex_updated_by": "user", "package_version": "1.0.0",
           "vex_assessed_version": "1.0.0", "vex_review_due": "2027-01-01"}
    same = carried_vex_fields(old, {"package_version": "v1.0.0"})
    assert same["vex_updated_by"] == "carry-forward"
    assert same["vex_needs_review"] is False and same["vex_assessed_version"] == "1.0.0"
    assert same["vex_review_due"] == "2027-01-01"
    moved = carried_vex_fields(old, {"package_version": "1.1.0"})
    assert moved["vex_needs_review"] is True and moved["vex_assessed_version"] == "1.0.0"
    # a status from before the field existed: its finding's version stands in
    legacy = carried_vex_fields({"vex_status": "fixed", "vex_updated_by": "user", "package_version": "3"},
                                {"package_version": "4"})
    assert legacy["vex_needs_review"] is True and legacy["vex_assessed_version"] == "3"
    # once flagged, it stays flagged until someone saves the status again
    sticky = carried_vex_fields({**old, "vex_needs_review": True}, {"package_version": "1.0.0"})
    assert sticky["vex_needs_review"] is True


async def test_carry_forward_end_to_end() -> None:
    coll = FakeCollection([
        _finding(_id="old1", scan_id="s1", vex_status="not_affected", vex_updated_by="user",
                 vex_assessed_version="4.17.20"),
        _finding(_id="old2", scan_id="s1", vulnerability_id="CVE-2026-2", vex_status="not_affected",
                 vex_updated_by="vex-rule:r1"),
        _finding(_id="new1", scan_id="s2", package_version="4.17.21"),
        _finding(_id="new2", scan_id="s2", vulnerability_id="CVE-2026-2"),
        _finding(_id="new3", scan_id="s2", vulnerability_id="CVE-2026-3"),
    ])
    repo = ScanFindingRepository(coll)  # type: ignore[arg-type]
    assert await repo.carry_forward_vex("s1", "s2") == 2
    assert coll.by_id("new1")["vex_needs_review"] is True
    assert coll.by_id("new1")["vex_updated_by"] == "carry-forward"
    assert coll.by_id("new2")["vex_updated_by"] == "vex-rule:r1"
    assert coll.by_id("new3")["vex_status"] is None


async def test_a_rule_dismissal_stays_the_rules_across_a_rescan() -> None:
    # Carry-forward used to stamp every dismissal "carry-forward", so retiring
    # the rule (or the finding no longer matching) never un-hid it again.
    coll = FakeCollection([
        _finding(_id="old1", scan_id="s1", vex_status="not_affected", vex_updated_by="vex-rule:r1",
                 dismissed=True, dismissed_by="vex-rule:r1", dismissed_reason="Dev DoS"),
        _finding(_id="old2", scan_id="s1", vulnerability_id="CVE-2026-2", dismissed=True, dismissed_by="user"),
        _finding(_id="new1", scan_id="s2"),
        _finding(_id="new2", scan_id="s2", vulnerability_id="CVE-2026-2"),
    ])
    repo = ScanFindingRepository(coll)  # type: ignore[arg-type]
    await repo.carry_forward_vex("s1", "s2")
    assert await repo.carry_forward_dismissed("s1", "s2") == 2
    assert coll.by_id("new1")["dismissed_by"] == "vex-rule:r1"
    assert coll.by_id("new2")["dismissed_by"] == "carry-forward"

    await repo.clear_vex_actor("vex-rule:r1")
    assert coll.by_id("new1")["dismissed"] is False
    assert coll.by_id("new2")["dismissed"] is True


async def test_saving_a_status_records_the_assessed_version_and_clears_the_flag() -> None:
    oid = ObjectId()
    coll = FakeCollection([_finding(_id=oid, target_id="t", package_version="1.2.3", vex_status="not_affected",
                                    vex_updated_by="carry-forward", vex_assessed_version="1.0", vex_needs_review=True)])
    repo = ScanFindingRepository(coll)  # type: ignore[arg-type]
    assert await repo.update_vex_status(str(oid), "not_affected", vex_review_due="2027-06-30")
    doc = coll.by_id(oid)
    assert doc["vex_assessed_version"] == "1.2.3"
    assert doc["vex_needs_review"] is False
    assert doc["vex_review_due"] == "2027-06-30"
    assert doc["vex_updated_by"] == "user"
    # an import is no person's assessment
    assert await repo.bulk_update_vex_by_vulnerability_ids("t", ["CVE-2026-1"], "fixed") == 1
    doc = coll.by_id(oid)
    assert doc["vex_updated_by"] == "vex-import"
    assert doc["vex_assessed_version"] is None and doc["vex_review_due"] is None
    # clearing removes the review evidence too
    assert await repo.update_vex_status(str(oid), None)
    assert coll.by_id(oid)["vex_assessed_version"] is None


def test_review_state() -> None:
    today = date(2026, 11, 15)
    base = {"vex_status": "not_affected", "package_version": "2.0"}
    assert review_state({**base, "vex_assessed_version": "2.0"}, today) == (False, None)
    assert review_state({**base, "vex_assessed_version": "1.0"}, today) == (True, "version_changed")
    assert review_state({**base, "vex_review_due": "2026-11-14"}, today) == (True, "review_due")
    assert review_state({**base, "vex_review_due": "2026-11-15"}, today) == (False, None)
    assert review_state({**base, "vex_needs_review": True}, today) == (True, "version_changed")
    assert review_state({"vex_status": None, "vex_needs_review": True}, today) == (False, None)


async def test_a_vex_source_replaces_a_rule_status_but_not_a_manual_one() -> None:
    coll = FakeCollection([
        _finding(_id="rule", target_id="t", vex_status="not_affected", vex_updated_by="vex-rule:r1"),
        _finding(_id="mine", target_id="t", package_name="other", vex_status="affected", vex_updated_by="user"),
    ])
    repo = ScanFindingRepository(coll)  # type: ignore[arg-type]
    assert await repo.apply_vex_from_source("t", ["CVE-2026-1"], "fixed") == 1
    assert coll.by_id("rule")["vex_updated_by"] == "vex-source"
    assert coll.by_id("mine")["vex_status"] == "affected"


class _Repo:
    def __init__(self, **items: Any) -> None:
        self.__dict__.update(items)


async def test_service_applies_rules_to_the_latest_scan() -> None:
    from app.services.vex_rule_service import VexRuleService

    findings = FakeCollection([
        _finding(_id="dev", scan_id="s2", package_type="library"),
        _finding(_id="run", scan_id="s2", package_name="express", dependency_scope="runtime"),
        _finding(_id="old", scan_id="s1"),
    ])
    sbom = FakeCollection([{"scan_id": "s2", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}])

    async def list_enabled() -> list[dict[str, Any]]:
        return [{"_id": "r1", "name": "dev npm", "enabled": True,
                 "conditions": {"dependency_scopes": ["dev"], "ecosystems": ["npm"]},
                 "action": {"vex_status": "not_affected", "vex_justification": "code_not_reachable"}}]

    async def get_target(_tid: str) -> dict[str, Any]:
        return LINUX_IMAGE

    async def latest(_tid: str) -> dict[str, Any]:
        return {"_id": "s2"}

    service = VexRuleService(
        _Repo(list_enabled=list_enabled),  # type: ignore[arg-type]
        ScanFindingRepository(findings),  # type: ignore[arg-type]
        _Repo(get_latest_by_target=latest),
        _Repo(get=get_target),
        _Repo(collection=sbom),
    )
    assert await service.apply_to_target("ghcr.io/acme/web") == {"applied": 1, "cleared": 0}
    assert findings.by_id("dev")["vex_updated_by"] == "vex-rule:r1"
    assert findings.by_id("run")["vex_status"] is None
    assert findings.by_id("old")["vex_status"] is None  # history stays as it was
