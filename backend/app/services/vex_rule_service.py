"""Automatic VEX triage rules ("auto-VEX").

A rule sets a VEX status on findings that match all of its conditions. Rules
run on the latest completed scan of a target: after every scan (behind
carry-forward and VEX sources), at the end of an SBOM import, after a VEX
source fetch, and on demand for every target.

Precedence: a rule only fills a finding that has no VEX status or one a VEX
rule set (actor ``vex-rule:<id>``). Hand-set, imported, MCP, carried-forward
manual, VEX-source and reachability statuses always win; a VEX source also
replaces a rule's status. When a rule no longer matches, is disabled or is
deleted, the statuses it set (and only those still carrying its actor) are
cleared again. The first matching rule wins, ordered by priority, then age.

Platform condition (fail closed): it matches only when *every* CPE
configuration of the vulnerability is restricted to Windows or an Apple OS
(the vulnerable match itself is ``cpe:2.3:o:microsoft:windows*`` /
``o:apple:macos|mac_os_x|mac_os|iphone_os|ipados``, or the configuration has
a non-vulnerable "running on" node made only of such OS CPEs) **and** the
target is a container image whose latest SBOM holds Linux distribution
packages (purl type deb, apk, rpm or alpm). No CPE configuration, a negated
node, nested nodes in the platform node, any other platform, or a target
that is not a recognisably Linux image: no match.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.scan_finding_repository import (
    VEX_RULE_ACTOR_PREFIX,
    ScanFindingRepository,
    vex_rule_actor,
)
from app.repositories.vex_rule_repository import VexRuleRepository
from app.schemas.vex_rule import VexRuleAction, VexRuleConditions

log = structlog.get_logger()

SEVERITY_RANK = {"negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Resource exhaustion and algorithmic complexity: the usual DoS / ReDoS CWEs.
DOS_CWES = (
    "CWE-400", "CWE-405", "CWE-407", "CWE-674", "CWE-770", "CWE-776",
    "CWE-834", "CWE-835", "CWE-1050", "CWE-1333",
)

PRESETS: tuple[dict[str, Any], ...] = (
    {
        "key": "dev-dos",
        "name": "DoS and ReDoS in dev dependencies",
        "description": (
            "Resource exhaustion and regular-expression DoS (CWE-400, 405, 407, 674, 770, 776, 834, 835, "
            "1050, 1333) in a development, test or build dependency. Such a package does not run in the "
            "shipped artifact, and at build time it does not read attacker-controlled input."
        ),
        "conditions": {"dependency_scopes": ["dev"], "cwe_ids": list(DOS_CWES)},
        "action": {
            "vex_status": "not_affected",
            "vex_justification": "code_not_reachable",
            "vex_detail": "Denial of service in a development dependency: it is not part of the shipped artifact.",
        },
    },
    {
        "key": "dev-triage",
        "name": "Dev dependencies to triage",
        "description": (
            "Every other vulnerability in a development dependency is marked under investigation, so it "
            "stays visible but sorts apart from runtime findings. Put it below more specific rules."
        ),
        "conditions": {"dependency_scopes": ["dev"]},
        "action": {
            "vex_status": "under_investigation",
            "vex_detail": "Development dependency: check whether it handles untrusted input during the build.",
        },
        "priority": 900,
    },
    {
        "key": "platform-mismatch",
        "name": "Windows and Apple OS vulnerabilities in Linux images",
        "description": (
            "Vulnerabilities whose every vulnerable configuration needs Windows, macOS or iOS, found in a "
            "Linux container image. Matches only when the CPE data says so for certain."
        ),
        "conditions": {"platform_mismatch": True, "target_types": ["container_image"]},
        "action": {
            "vex_status": "not_affected",
            "vex_justification": "requires_environment",
            "vex_detail": "Affects only Windows or Apple operating systems; this is a Linux image.",
        },
    },
)

# Scanner package types -> purl type, for findings whose package is not in the SBOM.
_PACKAGE_TYPE_ECOSYSTEM = {
    "npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
    "pip": "pypi", "python": "pypi", "python-pkg": "pypi", "pipenv": "pypi", "poetry": "pypi",
    "uv": "pypi", "pypi": "pypi",
    "gomod": "golang", "gobinary": "golang", "go-module": "golang", "go": "golang", "golang": "golang",
    "cargo": "cargo", "rust-crate": "cargo", "rustbinary": "cargo",
    "composer": "composer", "php-composer": "composer",
    "jar": "maven", "pom": "maven", "gradle": "maven", "java-archive": "maven", "maven": "maven",
    "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "packages-lock": "nuget",
    "gem": "gem", "bundler": "gem", "gemspec": "gem",
    "deb": "deb", "debian": "deb", "ubuntu": "deb", "dpkg": "deb",
    "apk": "apk", "alpine": "apk", "wolfi": "apk", "chainguard": "apk",
    "rpm": "rpm", "redhat": "rpm", "centos": "rpm", "rocky": "rpm", "alma": "rpm", "amazon": "rpm",
    "fedora": "rpm", "oracle": "rpm", "suse": "rpm", "photon": "rpm", "cbl-mariner": "rpm",
    "pub": "pub", "hex": "hex", "swift": "swift", "cocoapods": "cocoapods", "conan": "conan",
}

_LINUX_PURL_TYPES = ("deb", "apk", "rpm", "alpm")


# ---------------------------------------------------------------- platform


def _os_family(criteria: Any) -> str | None:
    """Windows / Apple OS family of an ``o:`` CPE, else None."""
    if not isinstance(criteria, str):
        return None
    parts = criteria.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[2] != "o":
        return None
    vendor, product = parts[3].lower(), parts[4].lower()
    if vendor == "microsoft" and product.startswith("windows"):
        return "windows"
    if vendor == "apple" and product in ("macos", "mac_os_x", "mac_os", "mac_os_x_server"):
        return "macos"
    if vendor == "apple" and product in ("iphone_os", "ipados", "ios"):
        return "ios"
    return None


def _walk_matches(node: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for match in node.get("matches") or []:
        if isinstance(match, Mapping):
            yield match
    for child in node.get("nodes") or []:
        if isinstance(child, Mapping):
            yield from _walk_matches(child)


def _any_negated(node: Mapping[str, Any]) -> bool:
    if node.get("negate"):
        return True
    return any(_any_negated(c) for c in node.get("nodes") or [] if isinstance(c, Mapping))


def _configuration_families(configuration: Mapping[str, Any]) -> set[str] | None:
    """OS families one configuration is restricted to, or None when unsure."""
    nodes = [n for n in configuration.get("nodes") or [] if isinstance(n, Mapping)]
    if not nodes or any(_any_negated(n) for n in nodes):
        return None
    vulnerable = [m for n in nodes for m in _walk_matches(n) if m.get("vulnerable") is True]
    if not vulnerable:
        return None  # without an explicit vulnerable match the data says nothing
    families = {_os_family(m.get("criteria")) for m in vulnerable}
    if None not in families:
        return families  # the operating system itself is the vulnerable product
    if len(nodes) < 2:
        return None
    for node in nodes:
        if node.get("nodes"):
            continue
        matches = [m for m in node.get("matches") or [] if isinstance(m, Mapping)]
        if not matches or any(m.get("vulnerable") is not False for m in matches):
            continue
        platform = {_os_family(m.get("criteria")) for m in matches}
        if None not in platform:
            return platform  # "running on" node: only Windows / Apple OS CPEs
    return None


def vulnerability_platforms(doc: Mapping[str, Any]) -> frozenset[str] | None:
    """The OS families every vulnerable configuration needs, or None (fail closed)."""
    configurations = doc.get("cpe_configurations") or doc.get("cpeConfigurations") or []
    if not isinstance(configurations, list) or not configurations:
        return None
    families: set[str] = set()
    for configuration in configurations:
        if not isinstance(configuration, Mapping):
            return None
        found = _configuration_families(configuration)
        if not found:
            return None
        families |= found
    return frozenset(families)


# ---------------------------------------------------------------- matching


@dataclass
class RuleContext:
    target: Mapping[str, Any]
    target_os: str | None = None
    vuln_cwes: dict[str, set[str]] = field(default_factory=dict)
    vuln_platforms: dict[str, frozenset[str] | None] = field(default_factory=dict)
    purl_types: dict[tuple[str, str], str] = field(default_factory=dict)


def _wildcard(pattern: str, *values: Any) -> bool:
    pat = pattern.casefold()
    return any(isinstance(v, str) and fnmatch.fnmatchcase(v.casefold(), pat) for v in values)


def finding_ecosystem(finding: Mapping[str, Any], purl_types: Mapping[tuple[str, str], str]) -> str | None:
    found = purl_types.get((finding.get("package_name") or "", finding.get("package_version") or ""))
    if found:
        return found
    ptype = (finding.get("package_type") or "").strip().lower()
    return _PACKAGE_TYPE_ECOSYSTEM.get(ptype)


def conditions_match(conditions: VexRuleConditions, finding: Mapping[str, Any], ctx: RuleContext) -> bool:
    if conditions.is_empty():
        return False  # a rule must narrow something down
    target = ctx.target
    if conditions.target_pattern and not _wildcard(
        conditions.target_pattern, target.get("target_id"), target.get("name")
    ):
        return False
    if conditions.target_group and (target.get("group") or "").casefold() != conditions.target_group.casefold():
        return False
    if conditions.target_types and target.get("type") not in conditions.target_types:
        return False
    if conditions.dependency_scopes:
        scope = finding.get("dependency_scope") or "unknown"
        if scope not in conditions.dependency_scopes:
            return False
    if conditions.package_pattern and not _wildcard(conditions.package_pattern, finding.get("package_name")):
        return False
    if conditions.ecosystems and finding_ecosystem(finding, ctx.purl_types) not in conditions.ecosystems:
        return False
    if conditions.max_severity:
        rank = SEVERITY_RANK.get((finding.get("severity") or "").lower())
        if rank is None or rank > SEVERITY_RANK[conditions.max_severity]:
            return False
    vuln_id = (finding.get("vulnerability_id") or "").upper()
    if conditions.cwe_ids and not ctx.vuln_cwes.get(vuln_id, set()) & set(conditions.cwe_ids):
        return False
    if conditions.platform_mismatch:
        if ctx.target_os != "linux":
            return False
        platforms = ctx.vuln_platforms.get(vuln_id)
        if not platforms or "linux" in platforms:
            return False
    return True


@dataclass
class ParsedRule:
    id: str
    name: str
    conditions: VexRuleConditions
    action: VexRuleAction

    @property
    def actor(self) -> str:
        return vex_rule_actor(self.id)


def parse_rule(doc: Mapping[str, Any]) -> ParsedRule | None:
    try:
        return ParsedRule(
            id=str(doc["_id"]),
            name=str(doc.get("name") or doc["_id"]),
            conditions=VexRuleConditions.model_validate(doc.get("conditions") or {}),
            action=VexRuleAction.model_validate(doc.get("action") or {}),
        )
    except Exception:
        log.warning("vex_rules.invalid_rule", rule_id=str(doc.get("_id")), exc_info=True)
        return None


def _is_rule_actor(actor: Any) -> bool:
    return isinstance(actor, str) and actor.startswith(VEX_RULE_ACTOR_PREFIX)


def plan_rule_updates(
    findings: Iterable[Mapping[str, Any]],
    rules: list[ParsedRule],
    ctx: RuleContext,
    now: datetime | None = None,
) -> tuple[list[tuple[Any, dict[str, Any]]], int, int]:
    """Compute ``(updates, applied, cleared)`` for one scan's findings."""
    now = now or datetime.now(tz=UTC)
    updates: list[tuple[Any, dict[str, Any]]] = []
    applied = cleared = 0
    for finding in findings:
        actor = finding.get("vex_updated_by")
        if finding.get("vex_status") and not _is_rule_actor(actor):
            continue  # someone (or something) else owns this status
        rule = next((r for r in rules if conditions_match(r.conditions, finding, ctx)), None)
        fields: dict[str, Any] = {}
        if rule:
            wanted = {
                "vex_status": rule.action.vex_status,
                "vex_justification": rule.action.vex_justification,
                "vex_detail": rule.action.vex_detail,
                "vex_updated_by": rule.actor,
            }
            if any(finding.get(k) != v for k, v in wanted.items()):
                fields.update(wanted)
                fields.update({
                    "vex_response": None, "vex_updated_at": now,
                    "vex_assessed_version": None, "vex_review_due": None, "vex_needs_review": False,
                })
                applied += 1
            dismissed_by = finding.get("dismissed_by")
            if rule.action.dismiss:
                if not finding.get("dismissed") or (_is_rule_actor(dismissed_by) and dismissed_by != rule.actor):
                    fields.update({
                        "dismissed": True, "dismissed_by": rule.actor,
                        "dismissed_reason": rule.name, "dismissed_at": now,
                    })
            elif finding.get("dismissed") and _is_rule_actor(dismissed_by):
                fields.update({"dismissed": False, "dismissed_by": None, "dismissed_reason": None, "dismissed_at": None})
        else:
            if _is_rule_actor(actor):
                fields.update({
                    "vex_status": None, "vex_justification": None, "vex_detail": None, "vex_response": None,
                    "vex_updated_by": None, "vex_updated_at": now,
                    "vex_assessed_version": None, "vex_review_due": None, "vex_needs_review": False,
                })
                cleared += 1
            if finding.get("dismissed") and _is_rule_actor(finding.get("dismissed_by")):
                fields.update({"dismissed": False, "dismissed_by": None, "dismissed_reason": None, "dismissed_at": None})
        if fields:
            updates.append((finding["_id"], fields))
    return updates, applied, cleared


# ---------------------------------------------------------------- service


class VexRuleService:
    def __init__(
        self,
        rule_repo: VexRuleRepository,
        finding_repo: ScanFindingRepository,
        scan_repo: Any,
        target_repo: Any,
        sbom_repo: Any,
    ) -> None:
        self.rule_repo = rule_repo
        self.finding_repo = finding_repo
        self.scan_repo = scan_repo
        self.target_repo = target_repo
        self.sbom_repo = sbom_repo

    async def _enabled_rules(self) -> list[ParsedRule]:
        rules = [parse_rule(doc) for doc in await self.rule_repo.list_enabled()]
        return [r for r in rules if r is not None]

    async def _vulnerability_info(
        self, vuln_ids: set[str], need_cwes: bool, need_platforms: bool,
    ) -> tuple[dict[str, set[str]], dict[str, frozenset[str] | None]]:
        cwes: dict[str, set[str]] = {}
        platforms: dict[str, frozenset[str] | None] = {}
        if not vuln_ids or not (need_cwes or need_platforms):
            return cwes, platforms
        from app.db.mongo import get_database

        projection: dict[str, int] = {}
        if need_cwes:
            projection["cwes"] = 1
        if need_platforms:
            projection["cpe_configurations"] = 1
        db = await get_database()
        collection = db[settings.mongo_vulnerabilities_collection]
        ids = sorted(vuln_ids)
        for start in range(0, len(ids), 500):
            cursor = collection.find({"_id": {"$in": ids[start:start + 500]}}, projection).max_time_ms(10_000)
            async for doc in cursor:
                vid = str(doc["_id"]).upper()
                if need_cwes:
                    cwes[vid] = {str(c).strip().upper() for c in doc.get("cwes") or [] if isinstance(c, str)}
                if need_platforms:
                    platforms[vid] = vulnerability_platforms(doc)
        return cwes, platforms

    async def _target_os(self, scan_id: str, target: Mapping[str, Any]) -> str | None:
        if target.get("type") != "container_image":
            return None
        hit = await self.sbom_repo.collection.find_one(
            {"scan_id": scan_id, "purl": {"$regex": f"^pkg:({'|'.join(_LINUX_PURL_TYPES)})/"}},
            {"_id": 1},
        )
        return "linux" if hit else None

    async def _purl_types(self, scan_id: str) -> dict[tuple[str, str], str]:
        types: dict[tuple[str, str], str] = {}
        cursor = self.sbom_repo.collection.find(
            {"scan_id": scan_id, "purl": {"$ne": None}}, {"name": 1, "version": 1, "purl": 1},
        )
        async for doc in cursor:
            purl = doc.get("purl") or ""
            if purl.startswith("pkg:") and "/" in purl:
                types.setdefault((doc.get("name") or "", doc.get("version") or ""), purl[4:].split("/", 1)[0].lower())
        return types

    async def apply_to_scan(
        self, scan_id: str, target: Mapping[str, Any], rules: list[ParsedRule] | None = None,
    ) -> dict[str, int]:
        """Apply the enabled rules to one scan's findings."""
        if rules is None:
            rules = await self._enabled_rules()
        findings = await self.finding_repo.list_for_vex_rules(scan_id)
        if not findings:
            return {"applied": 0, "cleared": 0}
        ctx = RuleContext(target=target)
        if rules:
            need_cwes = any(r.conditions.cwe_ids for r in rules)
            need_platforms = any(r.conditions.platform_mismatch for r in rules)
            vuln_ids = {(f.get("vulnerability_id") or "").upper() for f in findings} - {""}
            ctx.vuln_cwes, ctx.vuln_platforms = await self._vulnerability_info(vuln_ids, need_cwes, need_platforms)
            if need_platforms:
                ctx.target_os = await self._target_os(scan_id, target)
            if any(r.conditions.ecosystems for r in rules):
                ctx.purl_types = await self._purl_types(scan_id)
        updates, applied, cleared = plan_rule_updates(findings, rules, ctx)
        await self.finding_repo.write_vex_rule_updates(updates)
        if applied or cleared:
            log.info("vex_rules.applied", scan_id=scan_id, applied=applied, cleared=cleared)
        return {"applied": applied, "cleared": cleared}

    async def apply_to_target(self, target_id: str, rules: list[ParsedRule] | None = None) -> dict[str, int] | None:
        """Apply the rules to the target's latest completed scan."""
        target = await self.target_repo.get(target_id)
        if not target:
            return None
        scan = await self.scan_repo.get_latest_by_target(target_id)
        if not scan:
            return None
        return await self.apply_to_scan(str(scan["_id"]), target, rules)

    async def apply_all(self) -> dict[str, int]:
        """Apply the rules to the latest completed scan of every target."""
        rules = await self._enabled_rules()
        totals = {"targets": 0, "scans": 0, "applied": 0, "cleared": 0}
        for target_id in await self.target_repo.list_ids():
            totals["targets"] += 1
            result = await self.apply_to_target(target_id, rules)
            if result is None:
                continue
            totals["scans"] += 1
            totals["applied"] += result["applied"]
            totals["cleared"] += result["cleared"]
        return totals

    async def retire_rule(self, rule_id: str) -> int:
        """Clear every status and dismissal a (deleted or disabled) rule set."""
        return await self.finding_repo.clear_vex_actor(vex_rule_actor(rule_id))

    async def finding_counts(self) -> dict[str, int]:
        """Per rule id: findings in the latest scan of each target carrying its status."""
        counts: dict[str, int] = {}
        try:
            latest = await self.scan_repo.get_latest_completed_scan_ids()
            if not latest:
                return counts
            pipeline = [
                {"$match": {"scan_id": {"$in": latest}, "vex_updated_by": {"$regex": f"^{VEX_RULE_ACTOR_PREFIX}"}}},
                {"$group": {"_id": "$vex_updated_by", "count": {"$sum": 1}}},
            ]
            async for doc in self.finding_repo.collection.aggregate(pipeline):
                counts[str(doc["_id"])[len(VEX_RULE_ACTOR_PREFIX):]] = int(doc.get("count", 0))
        except Exception:
            log.warning("vex_rules.count_failed", exc_info=True)
        return counts


async def get_vex_rule_service() -> VexRuleService:
    from app.repositories.scan_repository import ScanRepository
    from app.repositories.scan_sbom_repository import ScanSbomRepository
    from app.repositories.scan_target_repository import ScanTargetRepository

    return VexRuleService(
        await VexRuleRepository.create(),
        await ScanFindingRepository.create(),
        await ScanRepository.create(),
        await ScanTargetRepository.create(),
        await ScanSbomRepository.create(),
    )
