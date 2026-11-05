#!/usr/bin/env python3
"""Build Hecate's VEX documents from collected evidence and hand-written assessments.

    python vex/tools/generate.py [backend frontend docs scanner source]

Reads vex/.work/<name>/ (written by collect.sh; `source` reads
vex/.work/source/ with trivy.json / grype.json of the repository) and
vex/assessments.toml, and writes per image:

    vex/hecate-<name>.openvex.json   OpenVEX 0.2.0, for `trivy --vex` / `grype --vex`
    vex/hecate-<name>.cdx.json       CycloneDX 1.6 VEX, for Hecate's VEX import
    vex/evidence/hecate-<name>.json  what the statements rest on
    vex/STATUS.md                    readable overview of all documents

A statement comes from, in this order: a matching [[statement]] in
assessments.toml; for OS packages the runtime evidence (not loaded or run by
the service -> not_affected, else under_investigation); for Go modules
govulncheck in binary mode (vulnerable function in the binary -> affected,
module present without it -> not_affected). Anything else stays
under_investigation: nothing is declared not_affected without a reason.
Stdlib only, Python 3.11+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import tomllib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

VEX_DIR = Path(__file__).resolve().parents[1]
WORK = VEX_DIR / ".work"
REPO_URL = "https://github.com/0x3e4/hecate"
DOC_BASE = f"{REPO_URL}/blob/main/vex"
NAMES = ("backend", "frontend", "docs", "scanner", "source")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"]
STATUS_ORDER = ["affected", "under_investigation", "not_affected", "fixed"]  # most conservative first
OS_TYPES = {"deb", "apk", "debian", "alpine"}

SERVICE = {
    "backend": "backend (uvicorn) process",
    "frontend": "nginx serving the SPA",
    "docs": "nginx serving the documentation site",
    "scanner": "scanner sidecar and the scanners it runs",
    "source": "repository",
}

CDX_STATE = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "under_investigation": "in_triage",
    "fixed": "resolved",
}
CDX_JUSTIFICATION = {
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_not_present": "code_not_present",
    "component_not_present": "code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


# ---------------------------------------------------------------- findings


@dataclass
class Finding:
    vuln_id: str
    pkg: str
    version: str
    pkg_type: str
    purl: str = ""
    source_pkg: str = ""
    location: str = ""
    aliases: set[str] = field(default_factory=set)
    severity: str = "unknown"
    fixed: set[str] = field(default_factory=set)
    vendor_status: set[str] = field(default_factory=set)
    title: str = ""
    scanners: set[str] = field(default_factory=set)

    @property
    def is_os(self) -> bool:
        return self.pkg_type in OS_TYPES

    def merge(self, other: Finding) -> None:
        self.aliases |= other.aliases
        self.fixed |= other.fixed
        self.vendor_status |= other.vendor_status
        self.scanners |= other.scanners
        self.severity = min(self.severity, other.severity, key=_sev_rank)
        self.purl = self.purl or other.purl
        self.source_pkg = self.source_pkg or other.source_pkg
        self.location = self.location or other.location
        self.title = self.title or other.title


def _sev_rank(value: str) -> int:
    value = (value or "unknown").lower()
    return SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _clean_purl(purl: str) -> str:
    """type/namespace/name@version without qualifiers, version unescaped."""
    if not purl:
        return ""
    base = purl.split("#", 1)[0].split("?", 1)[0]
    if "@" in base:
        head, version = base.rsplit("@", 1)
        return f"{head}@{unquote(version)}"
    return base


def _canonical(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-", "GO-"):
        hits = sorted(i for i in ids if i.upper().startswith(prefix))
        if hits:
            return hits[0]
    return sorted(ids)[0]


def load_trivy(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        rclass = result.get("Class", "")
        rtype = result.get("Type", "")
        for v in result.get("Vulnerabilities") or []:
            pkg_type = "deb" if rtype == "debian" else "apk" if rtype == "alpine" else rtype
            location = ""
            if rclass == "lang-pkgs":
                location = v.get("PkgPath") or ("" if target in ("Python", "Node.js") else target)
            vid = v["VulnerabilityID"]
            out.append(Finding(
                vuln_id=vid,
                pkg=v["PkgName"],
                version=v.get("InstalledVersion", ""),
                pkg_type=pkg_type,
                purl=_clean_purl((v.get("PkgIdentifier") or {}).get("PURL", "")),
                source_pkg=v.get("SrcName", "") or "",
                location="/" + location.lstrip("/") if location else "",
                aliases={vid},
                severity=(v.get("Severity") or "unknown").lower(),
                fixed={x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip()},
                vendor_status={v["Status"]} if v.get("Status") else set(),
                title=v.get("Title", "") or "",
                scanners={"trivy"},
            ))
    return out


def load_grype(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for m in data.get("matches") or []:
        v, a = m["vulnerability"], m["artifact"]
        ids = {v["id"]} | {r["id"] for r in m.get("relatedVulnerabilities") or [] if r.get("id")}
        locations = [loc.get("path", "") for loc in a.get("locations") or []]
        location = ""
        if a.get("type") not in ("deb", "apk"):
            location = next((p for p in locations if "/bin/" in p or p.endswith((".dll", ".json"))), "")
            location = location or (locations[0] if locations else "")
        upstreams = a.get("upstreams") or []
        fix = v.get("fix") or {}
        out.append(Finding(
            vuln_id=_canonical(ids),
            pkg=a["name"],
            version=a.get("version", ""),
            pkg_type=a.get("type", ""),
            purl=_clean_purl(a.get("purl", "")),
            source_pkg=upstreams[0]["name"] if upstreams else "",
            location=location,
            aliases=ids,
            severity=(v.get("severity") or "unknown").lower(),
            fixed=set(fix.get("versions") or []),
            vendor_status={fix["state"]} if fix.get("state") else set(),
            title=(v.get("description") or "")[:200],
            scanners={"grype"},
        ))
    return out


def merged_findings(name: str) -> list[Finding]:
    by_key: dict[tuple[str, str, str, str], Finding] = {}
    alias_to_id: dict[str, str] = {}
    raw = load_trivy(WORK / name / "trivy.json") + load_grype(WORK / name / "grype.json")
    # Grype names GHSA findings by their CVE; let Trivy's GHSA ids join them.
    for f in raw:
        canonical = _canonical(f.aliases | {f.vuln_id})
        for alias in f.aliases | {f.vuln_id}:
            alias_to_id.setdefault(alias, canonical)
    for f in raw:
        f.vuln_id = alias_to_id.get(f.vuln_id, f.vuln_id)
        # A Go module or Python package can sit in several binaries / venvs,
        # each with its own answer; OS packages exist once per image.
        key = (f.vuln_id, f.pkg, f.version, "" if f.is_os else f.location)
        if key in by_key:
            by_key[key].merge(f)
        else:
            by_key[key] = f
    return sorted(by_key.values(), key=lambda f: (f.pkg, f.vuln_id))


# ---------------------------------------------------------------- evidence


def load_loaded(name: str) -> set[str]:
    path = WORK / name / "loaded.txt"
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def load_sources(name: str) -> dict[str, str]:
    """binary package -> source package, as the distribution records it."""
    path = WORK / name / "sources.txt"
    result: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                result[parts[0].split(":")[0]] = parts[1]
    return result


@dataclass
class GoBinary:
    name: str
    readable: bool
    error: str = ""
    # GO id -> {"aliases": set, "level": "symbol" | "package" | "module", "functions": set}
    vulns: dict[str, dict] = field(default_factory=dict)
    known: dict[str, set[str]] = field(default_factory=dict)  # every OSV entry checked: GO id -> aliases


def _json_stream(text: str) -> list[dict]:
    decoder, idx, out = json.JSONDecoder(), 0, []
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, idx = decoder.raw_decode(text, idx)
        out.append(obj)
    return out


def load_govulncheck(name: str) -> dict[str, GoBinary]:
    folder = WORK / name / "govulncheck"
    result: dict[str, GoBinary] = {}
    if not folder.is_dir():
        return result
    for path in sorted(folder.glob("*.json")):
        err = (folder / f"{path.stem}.err").read_text(encoding="utf-8", errors="replace").strip() \
            if (folder / f"{path.stem}.err").exists() else ""
        objs = _json_stream(path.read_text(encoding="utf-8"))
        binary = GoBinary(path.stem, readable=bool(objs) and not err, error=err)
        for obj in objs:
            if "osv" in obj:
                osv = obj["osv"]
                binary.known[osv["id"]] = set(osv.get("aliases") or []) | {osv["id"]}
        for obj in objs:
            finding = obj.get("finding")
            if not finding:
                continue
            frame = (finding.get("trace") or [{}])[0]
            level = "symbol" if frame.get("function") else "package" if frame.get("package") else "module"
            entry = binary.vulns.setdefault(finding["osv"], {"level": "module", "functions": set(), "module": frame.get("module", "")})
            if ["module", "package", "symbol"].index(level) > ["module", "package", "symbol"].index(entry["level"]):
                entry["level"] = level
            if frame.get("function"):
                fn = frame["function"]
                entry["functions"].add(f"{frame.get('receiver', '') + '.' if frame.get('receiver') else ''}{fn}")
        result[binary.name] = binary
    return result


# ---------------------------------------------------------------- assessments


def load_assessments() -> list[dict]:
    path = VEX_DIR / "assessments.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return data.get("statement", [])


def _matches(rule: dict, name: str, f: Finding) -> bool:
    def hit(key: str, values: set[str]) -> bool:
        wanted = rule.get(key, ["*"])
        wanted = [wanted] if isinstance(wanted, str) else wanted
        return "*" in wanted or bool(values & set(wanted))

    return (
        hit("images", {name})
        and hit("packages", {f.pkg, f.source_pkg} - {""})
        and hit("vulnerabilities", f.aliases | {f.vuln_id})
        and (not rule.get("locations") or any(f.location.endswith(x) for x in rule["locations"]))
    )


# ---------------------------------------------------------------- classification


@dataclass
class Statement:
    status: str
    justification: str = ""
    impact: str = ""
    action: str = ""
    notes: str = ""
    basis: str = ""  # assessment | runtime-evidence | govulncheck | advisory | default
    users: tuple[str, ...] = ()  # runtime evidence: the loaded packages that put it in use
    vendor: str = ""  # what the distribution or upstream says about a fix


_VENDOR_STATES = {
    # Grype fix.state / Trivy Status -> what the distribution says
    "wont-fix": "the distribution will not fix it in this release (rated minor)",
    "will_not_fix": "the distribution will not fix it in this release (rated minor)",
    "fix_deferred": "the distribution has deferred the fix",
    "not-fixed": "no fixed package has been released yet",
    "affected": "no fixed package has been released yet",
    "end_of_life": "the package is end of life in this release",
}


def _vendor_phrases(f: Finding) -> list[str]:
    if f.fixed:
        return [f"fixed upstream in {', '.join(sorted(f.fixed))}"]
    return sorted({_VENDOR_STATES.get(s, s) for s in f.vendor_status - {"fixed", "unknown", ""}})


def _vendor_note(f: Finding) -> str:
    if f.fixed:
        return f"Fixed upstream in {', '.join(sorted(f.fixed))}."
    phrases = _vendor_phrases(f)
    if phrases:
        return f"No fix available: {'; '.join(phrases)}."
    return "No fixed version known."


def _numeric(version: str) -> tuple[int, ...] | None:
    """Plain dotted release (3.14.10, v1.2.3); None for anything else."""
    parts = version.lstrip("v").split(".")
    return tuple(int(p) for p in parts) if parts and all(p.isdigit() for p in parts) else None


def _fixed_on_release_line(f: Finding) -> str:
    """A fixed version on the installed release line that the installed one reaches.

    The advisory says e.g. "fixed in 3.13.16, 3.14.8": an installed 3.14.10 has
    the fix. Only for plain numeric versions of non-OS packages; distribution
    versions (2.41-12+deb13u4) have their own ordering and are left alone.
    """
    if f.is_os:
        return ""
    installed = _numeric(f.version)
    if installed is None or len(installed) < 2:
        return ""
    for candidate in sorted(f.fixed):
        fixed = _numeric(candidate)
        if fixed and len(fixed) >= 2 and fixed[:2] == installed[:2] and installed >= fixed:
            return candidate
    return ""


def classify(name: str, f: Finding, loaded: set[str], sources: dict[str, str],
             gobins: dict[str, GoBinary], rules: list[dict]) -> Statement:
    for rule in rules:
        if _matches(rule, name, f):
            return Statement(
                status=rule["status"],
                justification=rule.get("justification", ""),
                impact=rule.get("impact", "").strip(),
                action=rule.get("action", "").strip(),
                notes=rule.get("notes", "").strip(),
                basis="assessment",
            )

    fixed_by = _fixed_on_release_line(f)
    if fixed_by:
        return Statement(
            status="fixed",
            notes=(f"The advisory lists {fixed_by} as fixed, and the installed {f.pkg} {f.version} is on "
                   f"the same release line and not older; the scanner's version range is too broad."),
            basis="advisory",
        )

    if f.is_os:
        loaded_sources = {sources.get(p, p) for p in loaded}
        source = f.source_pkg or sources.get(f.pkg, f.pkg)
        if f.pkg in loaded or source in loaded_sources:
            users = sorted(p for p in loaded if sources.get(p, p) == source) or [f.pkg]
            return Statement(
                status="under_investigation",
                notes=(f"{source} is in use: the {SERVICE[name]} loads or runs {', '.join(users)} "
                       f"(runtime evidence). Not analysed per CVE yet. {_vendor_note(f)} The image "
                       f"takes distribution fixes at build time (apk/apt-get upgrade)."),
                basis="runtime-evidence",
                users=tuple(users),
                vendor="; ".join(_vendor_phrases(f)),
            )
        return Statement(
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            impact=(f"{f.pkg} is part of the base image, but the {SERVICE[name]} never loads or runs it: "
                    f"it is neither mapped by the service's process nor in the ldd closure of any program "
                    f"the service executes (see vex/evidence/hecate-{name}.json)."),
            basis="runtime-evidence",
        )

    binary = gobins.get(Path(f.location).name) if f.location else None
    if f.pkg_type in ("gobinary", "go-module") and binary is not None:
        if not binary.readable:
            return Statement(status="under_investigation",
                             notes=f"govulncheck cannot read {binary.name}: {binary.error[:120]}",
                             basis="govulncheck")
        ids = f.aliases | {f.vuln_id}
        go_ids = sorted(g for g, aliases in binary.known.items() if aliases & ids)
        symbol = [g for g in go_ids if binary.vulns.get(g, {}).get("level") == "symbol"]
        if symbol:
            fns = sorted({fn for g in symbol for fn in binary.vulns[g]["functions"]})
            return Statement(
                status="affected",
                action=(f"{f.pkg} {f.version} in {f.location}: govulncheck finds the vulnerable "
                        f"code of {', '.join(symbol)} in the binary ({', '.join(fns[:4])}"
                        f"{', …' if len(fns) > 4 else ''}). {_vendor_note(f)} Taken in once the "
                        f"binary is rebuilt with it."),
                basis="govulncheck",
            )
        reported = [g for g in go_ids if g in binary.vulns]
        if reported:
            return Statement(
                status="not_affected",
                justification="vulnerable_code_not_present",
                impact=(f"govulncheck -mode=binary: {f.location} contains {f.pkg} {f.version}, but none "
                        f"of the vulnerable functions of {', '.join(reported)}."),
                basis="govulncheck",
            )
        if go_ids:
            return Statement(
                status="under_investigation",
                notes=(f"The Go vulnerability database ({', '.join(go_ids)}) does not list {f.pkg} "
                       f"{f.version} as affected; the scanner match comes from a broader advisory range. "
                       f"{_vendor_note(f)}"),
                basis="govulncheck",
            )
        return Statement(status="under_investigation",
                         notes=f"Not in the Go vulnerability database; not analysed yet. {_vendor_note(f)}",
                         basis="default")

    return Statement(status="under_investigation",
                     notes=f"Not analysed yet. {_vendor_note(f)}", basis="default")


# ---------------------------------------------------------------- documents


def product_id(name: str) -> str:
    if name == "source":
        return "pkg:github/0x3e4/hecate"
    return f"pkg:oci/hecate-{name}?repository_url=ghcr.io/0x3e4/hecate-{name}"


def _sub_id(f: Finding) -> str:
    return f.purl or f"pkg:generic/{f.pkg}@{f.version}"


def _per_purl(rows: list[tuple[Finding, Statement]]) -> list[tuple[Finding, Statement]]:
    """One statement per (vulnerability, purl).

    Trivy and Grype match a statement by purl, not by the binary a module sits
    in, so x/crypto v0.58.0 in skopeo (not affected) and in grype (under
    investigation) must not become two statements for the same purl: the
    tools would apply either. The most conservative one wins and the text
    names the binaries with their own answer.
    """
    by_key: dict[tuple[str, str], list[tuple[Finding, Statement]]] = defaultdict(list)
    for f, st in rows:
        by_key[(f.vuln_id, _sub_id(f))].append((f, st))
    out = []
    for items in by_key.values():
        distinct = {(st.status, st.justification, st.impact, st.action, st.notes) for _, st in items}
        if len(distinct) == 1:
            out.append(items[0])
            continue
        f0, worst = min(items, key=lambda x: STATUS_ORDER.index(x[1].status))
        parts = [f"{f.location or f.pkg}: {st.status.replace('_', ' ')}. {st.impact or st.action or st.notes}"
                 for f, st in sorted(items, key=lambda x: x[0].location)]
        merged = Statement(status=worst.status, basis=worst.basis)
        text = " ".join(parts)
        if worst.status == "affected":
            merged.action = text
        elif worst.status == "not_affected":
            merged.justification, merged.impact = worst.justification, text
        else:
            merged.notes = text
        out.append((f0, merged))
    return out


def build_openvex(name: str, rows: list[tuple[Finding, Statement]], previous: dict | None) -> dict:
    grouped: dict[tuple, dict] = {}
    for f, st in _per_purl(rows):
        key = (f.vuln_id, st.status, st.justification, st.impact, st.action, st.notes)
        entry = grouped.setdefault(key, {"aliases": set(), "subs": set()})
        entry["aliases"] |= f.aliases - {f.vuln_id}
        entry["subs"].add(_sub_id(f))
    statements = []
    for (vid, status, just, impact, action, notes), entry in sorted(grouped.items()):
        st: dict = {
            "vulnerability": {"name": vid},
            "products": [{"@id": product_id(name),
                          "subcomponents": [{"@id": s} for s in sorted(entry["subs"])]}],
            "status": status,
        }
        if entry["aliases"]:
            st["vulnerability"]["aliases"] = sorted(entry["aliases"])
        if just:
            st["justification"] = just
        if impact:
            st["impact_statement"] = impact
        if action:
            st["action_statement"] = action
        elif status == "affected":
            st["action_statement"] = "No remediation available yet."
        if notes:
            st["status_notes"] = notes
        statements.append(st)

    version, timestamp = 1, _now()
    if previous:
        if previous.get("statements") == statements:
            version, timestamp = previous.get("version", 1), previous.get("timestamp", timestamp)
        else:
            version = int(previous.get("version", 0)) + 1
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{DOC_BASE}/hecate-{name}.openvex.json",
        "author": "Hecate maintainers",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": version,
        "tooling": "vex/tools/generate.py",
        "statements": statements,
    }


def build_cyclonedx(name: str, rows: list[tuple[Finding, Statement]], version: int, timestamp: str) -> dict:
    # Hecate's import applies one state per vulnerability id and target, so
    # each id gets one entry with the most conservative state of its packages.
    by_id: dict[str, list[tuple[Finding, Statement]]] = defaultdict(list)
    for f, st in rows:
        by_id[f.vuln_id].append((f, st))
    components: dict[str, dict] = {}
    vulns = []
    for vid in sorted(by_id):
        items = by_id[vid]
        worst = min(items, key=lambda x: STATUS_ORDER.index(x[1].status))
        state = worst[1].status
        texts = []
        for f, st in items:
            text = st.impact or st.action or st.notes
            if text and text not in texts:
                texts.append(text)
        analysis: dict = {"state": CDX_STATE[state]}
        just = {st.justification for _, st in items if st.status == state and st.justification}
        if state == "not_affected" and len(just) == 1:
            analysis["justification"] = CDX_JUSTIFICATION.get(just.pop(), "code_not_reachable")
        if state == "affected":
            analysis["response"] = ["update"] if any(f.fixed for f, _ in items) else ["can_not_fix"]
        if texts:
            analysis["detail"] = " ".join(texts)
        refs = []
        for f, _ in items:
            ref = _sub_id(f)
            refs.append({"ref": ref})
            components.setdefault(ref, {"type": "library", "bom-ref": ref, "name": f.pkg,
                                        "version": f.version, **({"purl": f.purl} if f.purl else {})})
        entry = {"id": vid, "analysis": analysis, "affects": sorted(refs, key=lambda r: r["ref"])}
        aliases = sorted({a for f, _ in items for a in f.aliases} - {vid})
        if aliases:
            entry["references"] = [{"id": a, "source": {"name": "alias"}} for a in aliases]
        vulns.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{DOC_BASE}/hecate-{name}.cdx.json#{version}')}",
        "version": version,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "vex/tools/generate.py",
                                      "externalReferences": [{"type": "vcs", "url": REPO_URL}]}]},
            "component": ({"type": "application", "bom-ref": product_id(name), "name": "hecate",
                           "purl": product_id(name)} if name == "source" else
                          {"type": "container", "bom-ref": product_id(name),
                           "name": f"ghcr.io/0x3e4/hecate-{name}"}),
        },
        "components": [components[k] for k in sorted(components)],
        "vulnerabilities": vulns,
    }


def _now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


# ---------------------------------------------------------------- status page


def status_section(name: str, rows: list[tuple[Finding, Statement]], digest: str) -> str:
    title = "Repository (source)" if name == "source" else f"hecate-{name}"
    lines = [f"## {title}", ""]
    if digest:
        lines += [f"Scanned: `{digest}`", ""]
    if not rows:
        return "\n".join(lines + ["No findings from Trivy or Grype.", ""])
    ids_by_status: dict[str, set[str]] = defaultdict(set)
    for f, st in rows:
        ids_by_status[st.status].add(f.vuln_id)
    lines += ["| Status | Vulnerabilities |", "| --- | --- |"]
    lines += [f"| `{s}` | {len(ids_by_status[s])} |" for s in STATUS_ORDER if ids_by_status.get(s)]
    lines.append("")

    headings = {"affected": "Affected", "under_investigation": "Under investigation",
                "not_affected": "Not affected", "fixed": "Fixed (scanner match too broad)"}
    for status in STATUS_ORDER:
        items = [(f, st) for f, st in rows if st.status == status]
        if not items:
            continue
        groups: dict[tuple[str, str], dict] = {}
        for f, st in items:
            group = (f.source_pkg if f.is_os and f.source_pkg else f.pkg)
            if f.location and not f.is_os:
                group = f"{group} ({Path(f.location).name})"
            if st.basis == "runtime-evidence" and status == "under_investigation":
                reason = f"In use: the service loads or runs {', '.join(st.users)}. Not analysed per CVE yet."
            elif st.basis == "runtime-evidence":
                reason = "Never loaded or run by the service (runtime evidence)."
            else:
                reason = st.action or st.impact or st.notes
            entry = groups.setdefault((group, reason), {"ids": set(), "pkgs": set(), "sev": "unknown", "vendor": set()})
            entry["ids"].add(f.vuln_id)
            entry["pkgs"].add(f.pkg)
            entry["sev"] = min(entry["sev"], f.severity, key=_sev_rank)
            if st.vendor:
                entry["vendor"].update(st.vendor.split("; "))
        lines += [f"### {headings[status]}", "",
                  "| Component | Worst | Vulnerabilities | Reason |", "| --- | --- | --- | --- |"]
        for (group, reason), entry in sorted(groups.items(), key=lambda x: (_sev_rank(x[1]["sev"]), x[0][0])):
            ids = sorted(entry["ids"])
            shown = ", ".join(ids[:8]) + (f" and {len(ids) - 8} more" if len(ids) > 8 else "")
            pkgs = sorted(entry["pkgs"] - {group})
            label = group + (f" ({', '.join(pkgs[:3])}{', …' if len(pkgs) > 3 else ''})" if pkgs and "(" not in group else "")
            vendor = (f" No fix available: {'; '.join(sorted(entry['vendor']))}.") if entry["vendor"] else ""
            lines.append(f"| {_md(label)} | {entry['sev']} | {len(ids)}: {shown} | {_md(reason + vendor)} |")
        lines.append("")
    return "\n".join(lines)


def _md(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


# ---------------------------------------------------------------- main


def run(name: str, rules: list[dict]) -> str:
    findings = merged_findings(name)
    loaded = load_loaded(name)
    sources = load_sources(name)
    for f in findings:  # Grype-only OS findings may lack the source package
        if f.is_os and not f.source_pkg:
            f.source_pkg = sources.get(f.pkg, "")
    gobins = load_govulncheck(name)
    rows = [(f, classify(name, f, loaded, sources, gobins, rules)) for f in findings]

    openvex_path = VEX_DIR / f"hecate-{name}.openvex.json"
    openvex = build_openvex(name, rows, _read_json(openvex_path))
    _write_json(openvex_path, openvex)
    _write_json(VEX_DIR / f"hecate-{name}.cdx.json",
                build_cyclonedx(name, rows, openvex["version"], openvex["timestamp"]))

    digest_file = WORK / name / "digest.txt"
    digest = digest_file.read_text(encoding="utf-8").strip() if digest_file.exists() else ""
    _write_json(VEX_DIR / "evidence" / f"hecate-{name}.json", {
        "image": digest,
        "collectedWith": "vex/tools/collect.sh",
        "loadedPackages": sorted(loaded),
        "govulncheck": {
            b.name: ({"error": b.error} if not b.readable else
                     {"vulnerableFunctionsPresent": sorted(g for g, v in b.vulns.items() if v["level"] == "symbol"),
                      "moduleOnly": sorted(g for g, v in b.vulns.items() if v["level"] != "symbol")})
            for b in gobins.values()
        },
        "statementBasis": {basis: sum(1 for _, st in rows if st.basis == basis)
                           for basis in sorted({st.basis for _, st in rows})},
    })
    print(f"{name}: {len(rows)} findings -> " + ", ".join(
        f"{s}={len({f.vuln_id for f, st in rows if st.status == s})}" for s in STATUS_ORDER
        if any(st.status == s for _, st in rows)))
    return status_section(name, rows, digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("names", nargs="*", default=list(NAMES))
    args = parser.parse_args()
    rules = load_assessments()
    sections = []
    for name in args.names:
        if name not in NAMES:
            print(f"unknown name: {name}", file=sys.stderr)
            return 2
        if not (WORK / name).is_dir():
            print(f"{name}: no evidence in {WORK / name}, run collect.sh first", file=sys.stderr)
            return 1
        sections.append(run(name, rules))
    header = [
        "# VEX status",
        "",
        "Generated by `vex/tools/generate.py`; do not edit by hand. Each section counts distinct",
        "vulnerability ids that Trivy or Grype report for the image, and says what the matching VEX",
        "statement rests on. Background and how to use the files: [README.md](README.md).",
        "",
        f"Last generated: {_now()[:10]}",
        "",
    ]
    if set(args.names) == set(NAMES):
        (VEX_DIR / "STATUS.md").write_text("\n".join(header + sections), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
