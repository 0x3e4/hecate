"""Go reachability from govulncheck, and the VEX statements it backs.

govulncheck (scanner ``govulncheck``) reports every Go vulnerability-database
entry at one of three levels per module:

- ``symbol``: a vulnerable function is reachable from the scanned code (the
  call trace is in the finding). Only these become govulncheck findings.
- ``package``: the vulnerable package is imported, no vulnerable symbol is
  called.
- ``module``: the module is in the build list, the vulnerable package is not
  imported at all.

For the last two the other scanners (Trivy, Grype, OSV-Scanner, ...) still
report the CVE, because they only compare versions. ``apply_reachability_vex``
marks those findings ``not_affected`` with actor ``reachability:govulncheck``
(``vulnerable_code_not_in_execute_path`` / ``vulnerable_code_not_present``),
and only where the finding has no VEX status, one this actor set, or one a VEX
rule (``vex-rule:<id>``) set: evidence beats a generic triage rule. A status set
by hand, imported, written over MCP or taken from a VEX source always wins.
The scan flow runs it after carry-forward and before ``apply_vex_sources``
(which runs the VEX rules), so a rule never fills a finding reachability
already decided. A status of its own is cleared again when a later scan shows
the symbol is called, or no longer reports the entry at all; a rule's status is
never cleared here.

Standard-library entries are skipped: in source mode govulncheck judges the
stdlib by the Go toolchain inside the scanner image, not by the project's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger()

GOVULNCHECK_ACTOR = "reachability:govulncheck"
REACHABILITY_ACTOR_PREFIX = "reachability:"
VEX_RULE_ACTOR_PREFIX = "vex-rule:"

# Pseudo-modules govulncheck uses for the Go distribution itself.
_STDLIB_MODULES = frozenset({"stdlib", "toolchain"})
# Finding types that are not a module dependency of the analysed source
# (a committed Go binary is judged by its own build, not by this source).
_BINARY_PACKAGE_TYPES = frozenset({"gobinary", "go-binary", "binary"})
# Directories govulncheck does not analyse; a finding from a lockfile below
# one of them is not covered by its answer.
_SKIPPED_PATH_SEGMENTS = frozenset({"testdata", "node_modules"})

_LEVEL_RANK = {"module": 0, "package": 1, "symbol": 2}

JUSTIFICATION_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
JUSTIFICATION_NOT_PRESENT = "vulnerable_code_not_present"


def is_reachability_actor(actor: Any) -> bool:
    return isinstance(actor, str) and actor.startswith(REACHABILITY_ACTOR_PREFIX)


def _is_rule_actor(actor: Any) -> bool:
    return isinstance(actor, str) and actor.startswith(VEX_RULE_ACTOR_PREFIX)


@dataclass
class GoVulnEntry:
    """One Go vulnerability-database entry as govulncheck saw it, per module path."""

    osv_id: str
    module: str
    version: str = ""
    level: str = "module"
    fixed_version: str | None = None
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    details: str | None = None
    url: str | None = None
    references: list[str] = field(default_factory=list)
    packages: set[str] = field(default_factory=set)
    traces: list[list[dict[str, Any]]] = field(default_factory=list)
    module_dirs: set[str] = field(default_factory=set)

    @property
    def ids(self) -> set[str]:
        return {self.osv_id.upper(), *(a.upper() for a in self.aliases)}

    @property
    def primary_id(self) -> str:
        """CVE alias, else GHSA alias, else the GO id."""
        for prefix in ("CVE-", "GHSA-"):
            for alias in sorted(self.aliases):
                if alias.upper().startswith(prefix):
                    return alias.upper() if prefix == "CVE-" else alias
        return self.osv_id


@dataclass
class GovulncheckSummary:
    entries: dict[tuple[str, str], GoVulnEntry] = field(default_factory=dict)
    module_errors: list[str] = field(default_factory=list)
    truncated: bool = False
    modules_scanned: int = 0

    @property
    def complete(self) -> bool:
        """Every Go module of the tree was analysed without an error."""
        return not self.truncated and not self.module_errors and self.modules_scanned > 0


def _frame_label(frame: dict[str, Any]) -> str:
    package = str(frame.get("package") or frame.get("module") or "")
    function = str(frame.get("function") or "")
    receiver = str(frame.get("receiver") or "").lstrip("*")
    name = f"{receiver}.{function}" if receiver and function else function
    label = f"{package}.{name}" if name else package
    position = frame.get("position") if isinstance(frame.get("position"), dict) else None
    if position and position.get("filename"):
        label += f" ({position['filename']}:{position.get('line', 0)})"
    return label


def summarize_govulncheck(report: dict[str, Any]) -> GovulncheckSummary:
    """Fold the sidecar's govulncheck report into one entry per (GO id, module)."""
    summary = GovulncheckSummary(truncated=bool(report.get("truncated")))
    modules = report.get("modules") if isinstance(report, dict) else None
    if not isinstance(modules, list):
        return summary
    for module in modules:
        if not isinstance(module, dict):
            continue
        rel_dir = str(module.get("dir") or ".")
        summary.modules_scanned += 1
        if module.get("error"):
            summary.module_errors.append(f"{rel_dir}: {module['error']}")
        osvs: dict[str, dict[str, Any]] = {}
        messages = module.get("messages") if isinstance(module.get("messages"), list) else []
        for message in messages:
            if isinstance(message, dict) and isinstance(message.get("osv"), dict):
                entry_id = message["osv"].get("id")
                if isinstance(entry_id, str) and entry_id:
                    osvs[entry_id] = message["osv"]
        for message in messages:
            finding = message.get("finding") if isinstance(message, dict) else None
            if not isinstance(finding, dict):
                continue
            osv_id = finding.get("osv")
            trace = finding.get("trace")
            if not isinstance(osv_id, str) or not osv_id or not isinstance(trace, list) or not trace:
                continue
            first = trace[0] if isinstance(trace[0], dict) else {}
            module_path = str(first.get("module") or "")
            if not module_path or module_path in _STDLIB_MODULES:
                continue
            level = "symbol" if first.get("function") else ("package" if first.get("package") else "module")
            key = (osv_id, module_path)
            entry = summary.entries.get(key)
            if entry is None:
                osv = osvs.get(osv_id, {})
                db_specific = osv.get("database_specific") if isinstance(osv.get("database_specific"), dict) else {}
                entry = GoVulnEntry(
                    osv_id=osv_id,
                    module=module_path,
                    version=str(first.get("version") or ""),
                    aliases=[a for a in (osv.get("aliases") or []) if isinstance(a, str)],
                    summary=osv.get("summary") if isinstance(osv.get("summary"), str) else None,
                    details=osv.get("details") if isinstance(osv.get("details"), str) else None,
                    url=db_specific.get("url") if isinstance(db_specific.get("url"), str) else None,
                    references=[
                        r["url"] for r in (osv.get("references") or [])
                        if isinstance(r, dict) and isinstance(r.get("url"), str)
                    ],
                )
                summary.entries[key] = entry
            entry.module_dirs.add(rel_dir)
            if _LEVEL_RANK[level] > _LEVEL_RANK[entry.level]:
                entry.level = level
            if finding.get("fixed_version") and not entry.fixed_version:
                entry.fixed_version = str(finding["fixed_version"])
            if first.get("package"):
                entry.packages.add(str(first["package"]))
            if level == "symbol" and len(entry.traces) < 5:
                entry.traces.append([f for f in trace if isinstance(f, dict)])
    return summary


def describe_entry(entry: GoVulnEntry) -> str:
    """Description of a govulncheck (symbol-level) finding: the call paths."""
    parts: list[str] = []
    if entry.details:
        parts.append(entry.details.strip())
    if entry.traces:
        parts.append("Reachable through:")
        for trace in entry.traces:
            # Frames run from the vulnerable symbol to the entry point.
            parts.append("  " + " <- ".join(_frame_label(f) for f in trace))
    return "\n".join(parts)


# --- VEX ----------------------------------------------------------------------


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _covered_path(package_path: Any) -> bool:
    if not package_path:
        return True
    segments = str(package_path).replace("\\", "/").split("/")
    return not any(
        seg in _SKIPPED_PATH_SEGMENTS or (seg.startswith((".", "_")) and seg not in (".", ".."))
        for seg in segments[:-1]
    )


def plan_reachability_vex(
    findings: list[dict[str, Any]],
    summary: GovulncheckSummary,
) -> tuple[list[tuple[Any, str, str]], list[Any]]:
    """Decide which findings get a reachability statement and which lose one.

    Returns ``(to_set, to_clear)``: ``to_set`` holds ``(finding _id,
    justification, detail)``, ``to_clear`` the ids whose own statement goes.
    Findings with a status someone else set are never in either list; a VEX
    rule's status may be replaced (``to_set``) but is never cleared.
    """
    by_id_and_module: dict[tuple[str, str], GoVulnEntry] = {}
    for entry in summary.entries.values():
        for vuln_id in entry.ids:
            key = (vuln_id, _norm(entry.module))
            known = by_id_and_module.get(key)
            if known is None or _LEVEL_RANK[entry.level] > _LEVEL_RANK[known.level]:
                by_id_and_module[key] = entry

    to_set: list[tuple[Any, str, str]] = []
    to_clear: list[Any] = []
    for finding in findings:
        if finding.get("scanner") == "govulncheck":
            continue
        status = finding.get("vex_status")
        own = is_reachability_actor(finding.get("vex_updated_by")) and status is not None
        rule_set = _is_rule_actor(finding.get("vex_updated_by")) and status is not None
        if status is not None and not own and not rule_set:
            continue
        entry = by_id_and_module.get((_norm(finding.get("vulnerability_id")).upper(), _norm(finding.get("package_name"))))
        applicable = (
            entry is not None
            and _norm(finding.get("package_type")) not in _BINARY_PACKAGE_TYPES
            and _covered_path(finding.get("package_path"))
        )
        if applicable and entry is not None and entry.level != "symbol":
            if summary.complete:
                justification = (
                    JUSTIFICATION_NOT_IN_EXECUTE_PATH if entry.level == "package" else JUSTIFICATION_NOT_PRESENT
                )
                to_set.append((finding["_id"], justification, _detail(entry)))
            continue
        if not own:
            continue
        # Its own statement goes when the symbol is called now, or when a
        # complete run no longer reports the entry for this module.
        if (applicable and entry is not None and entry.level == "symbol") or summary.complete:
            to_clear.append(finding["_id"])
    return to_set, to_clear


def _detail(entry: GoVulnEntry) -> str:
    where = f"{entry.module}@{entry.version}" if entry.version else entry.module
    if entry.level == "package":
        packages = ", ".join(sorted(entry.packages)[:3]) or entry.module
        return (
            f"govulncheck ({entry.osv_id}): {packages} is imported, but no vulnerable "
            f"symbol is reachable from the scanned code ({where})."
        )
    return (
        f"govulncheck ({entry.osv_id}): {where} is required, but the vulnerable "
        "package is not imported by the scanned code."
    )


async def apply_reachability_vex(collection: Any, scan_id: str, summary: GovulncheckSummary) -> dict[str, int]:
    """Write the statements ``plan_reachability_vex`` decides on for one scan.

    ``collection`` is the scan-findings collection. Each write repeats the
    "empty or our own" guard, so a status someone sets meanwhile is kept.
    """
    ids: set[str] = set()
    for entry in summary.entries.values():
        ids |= entry.ids
        ids |= {i.lower() for i in entry.ids}
        ids |= set(entry.aliases)
    query: dict[str, Any] = {
        "scan_id": scan_id,
        "$or": [{"vulnerability_id": {"$in": sorted(ids)}}, {"vex_updated_by": GOVULNCHECK_ACTOR}],
    }
    projection = {
        "_id": 1, "scanner": 1, "vulnerability_id": 1, "package_name": 1, "package_type": 1,
        "package_path": 1, "vex_status": 1, "vex_updated_by": 1,
    }
    findings = [doc async for doc in collection.find(query, projection)]
    to_set, to_clear = plan_reachability_vex(findings, summary)
    guard = {"$or": [
        {"vex_status": None},
        {"vex_updated_by": GOVULNCHECK_ACTOR},
        {"vex_updated_by": {"$regex": f"^{VEX_RULE_ACTOR_PREFIX}"}},
    ]}
    now = datetime.now(tz=UTC)
    applied = 0
    by_statement: dict[tuple[str, str], list[Any]] = {}
    for finding_id, justification, detail in to_set:
        by_statement.setdefault((justification, detail), []).append(finding_id)
    for (justification, detail), finding_ids in by_statement.items():
        result = await collection.update_many(
            {"_id": {"$in": finding_ids}, **guard},
            {"$set": {
                "vex_status": "not_affected",
                "vex_justification": justification,
                "vex_detail": detail,
                "vex_response": None,
                "vex_updated_at": now,
                "vex_updated_by": GOVULNCHECK_ACTOR,
            }},
        )
        applied += result.modified_count
    cleared = 0
    if to_clear:
        result = await collection.update_many(
            {"_id": {"$in": to_clear}, "vex_updated_by": GOVULNCHECK_ACTOR},
            {"$set": {
                "vex_status": None,
                "vex_justification": None,
                "vex_detail": None,
                "vex_response": None,
                "vex_updated_at": now,
                "vex_updated_by": None,
            }},
        )
        cleared = result.modified_count
    log.info(
        "reachability.govulncheck_vex_applied",
        scan_id=scan_id, applied=applied, cleared=cleared, complete=summary.complete,
    )
    return {"applied": applied, "cleared": cleared}
