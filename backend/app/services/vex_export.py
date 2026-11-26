"""VEX export in OpenVEX 0.2.0 and CSAF 2.0 (profile "VEX"), next to CycloneDX.

CycloneDX VEX stays in ``VexService.export_cyclonedx_vex`` and keeps its shape:
only findings with a VEX status. OpenVEX and CSAF are built here from the same
findings, with two differences that the formats ask for:

- **Every vulnerability finding is a statement.** A finding nobody assessed yet
  is exported as ``under_investigation``: Hecate knows the package carries the
  advisory, nobody has said whether it matters. ``known_affected`` would be a
  claim nobody made, and leaving it out would read as "not mentioned".
- **The product is the scan target, the packages are its components.** OpenVEX
  names the target as product with the package purl as subcomponent (the shape
  Hecate's own ``vex/`` files use, which ``_parse_openvex`` reads back); CSAF
  lists both in ``product_tree`` and states the status of the relationship
  product "<package> as a component of <target>".

Findings without a vulnerability id (SAST, secrets, compliance checks, Hecate's
heuristic malware rules) are no VEX statements and are left out.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from app.core.config import settings

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VEX_FORMATS = ("cyclonedx", "openvex", "csaf")

# Finding types that carry no advisory id worth a VEX statement.
_NON_VEX_TYPES = frozenset({"sast-finding", "secret-finding", "compliance-check"})
# Findings read per export. A scan with more vulnerability findings than this is
# not realistic; the cap keeps a pathological one from exhausting memory.
MAX_EXPORT_FINDINGS = 20_000

# The five justifications OpenVEX and CSAF share (CSAF calls them flag labels).
VEX_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

# CycloneDX analysis.justification -> OpenVEX / CSAF, as in CISA's
# "Minimum Requirements for VEX" mapping table.
CYCLONEDX_TO_VEX_JUSTIFICATION = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "component_not_present",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
}

# Hecate VEX status -> CSAF product_status group.
CSAF_STATUS_GROUPS = {
    "not_affected": "known_not_affected",
    "affected": "known_affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
}

# CycloneDX analysis.response -> CSAF remediation category.
_RESPONSE_TO_REMEDIATION = {
    "will_not_fix": "no_fix_planned",
    "can_not_fix": "no_fix_planned",
    "workaround_available": "workaround",
    "update": "vendor_fix",
    "rollback": "vendor_fix",
}

_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_STATUSES = frozenset(CSAF_STATUS_GROUPS)


CYCLONEDX_JUSTIFICATIONS = frozenset(CYCLONEDX_TO_VEX_JUSTIFICATION)

# OpenVEX / CSAF label -> CycloneDX analysis.justification. The CISA table maps
# several CycloneDX values onto one label, so the way back picks the closest one.
VEX_TO_CYCLONEDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


def cyclonedx_justification(text: Any) -> str | None:
    """The CycloneDX ``analysis.justification`` enum value a stored justification stands for.

    Rules write CycloneDX labels, reachability analysis and OpenVEX imports write
    OpenVEX labels, people type free text. Only the first two have a CycloneDX
    value; free text gets ``None`` (the export carries it in ``detail`` instead,
    since an unknown enum value makes the document invalid).
    """
    if not isinstance(text, str):
        return None
    key = re.sub(r"[\s\-]+", "_", text.strip().lower())
    if key in CYCLONEDX_JUSTIFICATIONS:
        return key
    return VEX_TO_CYCLONEDX_JUSTIFICATION.get(key)


# Hecate VEX status -> CycloneDX analysis.state. CycloneDX has no "affected";
# its counterpart (as in CISA's OpenVEX mapping) is "exploitable", which the
# import maps back to "affected".
VEX_TO_CYCLONEDX_STATE = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved",
    "under_investigation": "in_triage",
}
# affects[].versions[].status has an enum of its own.
VEX_TO_CYCLONEDX_VERSION_STATUS = {
    "not_affected": "unaffected",
    "affected": "affected",
    "fixed": "unaffected",
    "under_investigation": "unknown",
}


def cyclonedx_analysis(finding: dict[str, Any]) -> dict[str, Any] | None:
    """The CycloneDX ``analysis`` block of a finding's VEX status, ``None`` without one.

    CycloneDX only accepts its own justification enum: labels are mapped, free
    text goes into ``detail`` rather than in as an invalid value.
    """
    status = finding.get("vex_status")
    if not isinstance(status, str) or not status:
        return None
    analysis: dict[str, Any] = {"state": VEX_TO_CYCLONEDX_STATE.get(status, status)}
    justification = finding.get("vex_justification")
    cdx_justification = cyclonedx_justification(justification)
    if cdx_justification:
        analysis["justification"] = cdx_justification
    detail = finding.get("vex_detail")
    if not cdx_justification and isinstance(justification, str) and justification.strip():
        detail = f"{justification.strip()}\n\n{detail}" if detail else justification.strip()
    if detail:
        analysis["detail"] = detail
    if finding.get("vex_response"):
        analysis["response"] = finding["vex_response"]
    updated_at = finding.get("vex_updated_at")
    if isinstance(updated_at, datetime):
        analysis["lastUpdated"] = updated_at.isoformat()
    return analysis


def vex_review_properties(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Review evidence as CycloneDX properties: who set the status, at which version, re-review date."""
    return [
        {"name": name, "value": str(finding[key])}
        for name, key in (
            ("hecate:vex:updated-by", "vex_updated_by"),
            ("hecate:vex:assessed-version", "vex_assessed_version"),
            ("hecate:vex:review-due", "vex_review_due"),
        )
        if finding.get(key)
    ]


def vex_justification_label(text: Any) -> str | None:
    """The OpenVEX / CSAF justification a free-text or CycloneDX value stands for.

    Hecate stores the justification as typed (the editor is a text field, VEX
    imports and rules write machine labels), so ``"Vulnerable code not
    present"``, ``code_not_present`` and ``vulnerable_code_not_present`` all
    land on the same label. Anything else has no label (``None``).
    """
    if not isinstance(text, str):
        return None
    key = re.sub(r"[\s\-]+", "_", text.strip().lower())
    if key in VEX_JUSTIFICATIONS:
        return key
    return CYCLONEDX_TO_VEX_JUSTIFICATION.get(key)


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        value = value if value.tzinfo else value.replace(tzinfo=UTC)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str) and value:
        return value
    return None


def _text(value: Any, limit: int = 2000) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:limit]
    return None


# ---------------------------------------------------------------- statements


def collect_statements(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record per (vulnerability, package, version), across scanners.

    Several scanners report the same package; a status set in the UI is written
    to all of them, so when they differ the most recently set status wins and a
    finding with a status beats one without.
    """
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    scanners: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for f in findings:
        vid = f.get("vulnerability_id")
        if not isinstance(vid, str) or not vid.strip():
            continue
        if f.get("package_type") in _NON_VEX_TYPES:
            continue
        key = (vid.strip(), str(f.get("package_name") or ""), str(f.get("package_version") or ""))
        if f.get("scanner"):
            scanners[key].add(str(f["scanner"]))
        current = best.get(key)
        if current is None or _rank(f) > _rank(current):
            best[key] = f
    out: list[dict[str, Any]] = []
    for key in sorted(best):
        f = best[key]
        status = f.get("vex_status") if f.get("vex_status") in _STATUSES else None
        out.append({
            "vulnerability_id": key[0],
            "package_name": key[1],
            "package_version": key[2],
            "status": status or "under_investigation",
            "assessed": status is not None,
            "justification": _text(f.get("vex_justification")),
            "detail": _text(f.get("vex_detail")),
            "response": [r for r in (f.get("vex_response") or []) if isinstance(r, str)],
            "updated_at": f.get("vex_updated_at"),
            "fix_version": _text(f.get("fix_version"), 200),
            "title": _text(f.get("title"), 500) or _text(f.get("description"), 500),
            "scanners": sorted(scanners[key]),
            # Review evidence (assessed version, re-review date); written by the
            # VEX review workflow when present, ignored otherwise.
            "assessed_version": _text(f.get("vex_assessed_version"), 200),
            "review_due": f.get("vex_review_due"),
        })
    return out


def _rank(f: dict[str, Any]) -> tuple[int, str]:
    has_status = 1 if f.get("vex_status") in _STATUSES else 0
    return has_status, _iso(f.get("vex_updated_at")) or ""


def review_note(st: dict[str, Any]) -> str | None:
    """"Assessed against 1.2.3; review due 2027-01-01", or None without evidence."""
    parts = []
    if st.get("assessed_version"):
        parts.append(f"Assessed against version {st['assessed_version']}")
    due = st.get("review_due")
    due_text = due.strftime("%Y-%m-%d") if isinstance(due, datetime) else _text(due, 40)
    if due_text:
        parts.append(f"review due {due_text}")
    return "; ".join(parts) if parts else None


# ---------------------------------------------------------------- identities


def component_purls(components: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    """(lower-cased name, version) -> purl from the scan's SBOM rows.

    A name-only entry (version ``""``) catches a finding whose version string
    differs from the SBOM's (epoch prefixes, ``v`` prefixes).
    """
    index: dict[tuple[str, str], str] = {}
    for comp in components:
        purl = comp.get("purl")
        name = comp.get("name")
        if not isinstance(purl, str) or not purl.startswith("pkg:") or not isinstance(name, str):
            continue
        version = str(comp.get("version") or "")
        index.setdefault((name.lower(), version), purl)
        index.setdefault((name.lower(), ""), purl)
    return index


def purl_for(st: dict[str, Any], purls: dict[tuple[str, str], str]) -> str | None:
    name = st["package_name"].lower()
    exact = purls.get((name, st["package_version"]))
    if exact:
        return exact
    loose = purls.get((name, ""))
    # A purl of another version would name the wrong release.
    if loose and st["package_version"] and st["package_version"] in loose:
        return loose
    return None


def generic_purl(name: str, version: str) -> str:
    base = f"pkg:generic/{quote(name or 'unknown', safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


def target_identity(scan: dict[str, Any], target: dict[str, Any] | None) -> dict[str, Any]:
    """Name, type and identifiers of the scanned product.

    ``purl`` is set for a container image (``pkg:oci``, digest as version when
    the scan recorded one); ``iri`` is what OpenVEX uses as product ``@id``.
    """
    target = target or {}
    target_id = str(scan.get("target_id") or target.get("target_id") or "")
    name = target.get("name") or scan.get("target_name") or target_id or "unknown"
    ttype = target.get("type") or ""
    purl: str | None = None
    if ttype == "container_image":
        ref = str(scan.get("image_ref") or target_id)
        repo, _, digest = ref.partition("@")
        last = repo.rsplit("/", 1)[-1]
        if ":" in last:  # strip a tag
            repo = repo[: len(repo) - len(last)] + last.split(":", 1)[0]
        short = repo.rsplit("/", 1)[-1].lower() or "image"
        purl = f"pkg:oci/{quote(short, safe='')}"
        if digest:
            purl += f"@{quote(digest, safe='')}"
        purl += f"?repository_url={quote(repo, safe='/.-_')}"
    if purl:
        iri = purl
    elif re.match(r"^https?://", target_id):
        iri = target_id
    else:
        iri = f"urn:hecate:target:{quote(target_id, safe='')}"
    return {
        "id": target_id,
        "name": str(name),
        "type": ttype,
        "purl": purl,
        "iri": iri,
        "commit_sha": scan.get("commit_sha"),
        "image_ref": scan.get("image_ref"),
    }


def _generator_version() -> str:
    try:
        from app.api.v1.version import CURRENT_VERSION

        return CURRENT_VERSION
    except Exception:  # pragma: no cover - defensive
        return "unknown"


# ---------------------------------------------------------------- OpenVEX


def build_openvex(
    scan: dict[str, Any],
    target: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    components: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """OpenVEX 0.2.0 document; ``{}`` when the scan has no vulnerability finding."""
    statements = collect_statements(findings)
    if not statements:
        return {}
    now = now or datetime.now(tz=UTC)
    ident = target_identity(scan, target)
    purls = component_purls(components)
    out: list[dict[str, Any]] = []
    for st in statements:
        sub_id = purl_for(st, purls) or generic_purl(st["package_name"], st["package_version"])
        entry: dict[str, Any] = {
            "vulnerability": {"name": st["vulnerability_id"]},
            "products": [{"@id": ident["iri"], "subcomponents": [{"@id": sub_id}]}],
            "status": st["status"],
        }
        if st["assessed"] and _iso(st["updated_at"]):
            entry["timestamp"] = _iso(st["updated_at"])
        label = vex_justification_label(st["justification"])
        free_text = st["detail"] or (st["justification"] if not label else None)
        if st["status"] == "not_affected":
            if label:
                entry["justification"] = label
            if free_text or not label:
                # Required without a justification.
                entry["impact_statement"] = free_text or "Assessed as not affected; no justification recorded."
        elif st["status"] == "affected":
            entry["action_statement"] = free_text or _action_text(st)
        elif free_text:
            entry["status_notes"] = free_text
        notes = review_note(st)
        if notes:
            entry["status_notes"] = f"{entry['status_notes']} ({notes})" if entry.get("status_notes") else notes
        if not st["assessed"]:
            entry.setdefault("status_notes", "Reported by a scan; not assessed yet.")
        out.append(entry)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid4()}",
        "author": settings.csaf_publisher_name,
        "role": "Document Creator",
        "timestamp": _iso(now),
        "version": 1,
        "tooling": f"Hecate {_generator_version()}",
        "statements": out,
    }


def _action_text(st: dict[str, Any]) -> str:
    if st["fix_version"]:
        return f"Update {st['package_name']} to {st['fix_version']} or later."
    return "No fixed version is known yet; follow the advisory."


# ---------------------------------------------------------------- CSAF 2.0


def csaf_tracking_id(scan_id: str, now: datetime) -> str:
    return f"HECATE-VEX-{scan_id}-{now.strftime('%Y%m%dT%H%M%SZ')}"


def csaf_filename(tracking_id: str) -> str:
    """The file name CSAF asks for: tracking id lower-cased, ``[^+\\-a-z0-9]`` -> ``_``."""
    return re.sub(r"[^+\-a-z0-9]+", "_", tracking_id.lower()) + ".json"


def _vuln_ids(vuln_id: str) -> dict[str, Any]:
    if _CVE_RE.match(vuln_id):
        return {"cve": vuln_id}
    system = vuln_id.split("-", 1)[0] if "-" in vuln_id else "Hecate"
    return {"ids": [{"system_name": system or "Hecate", "text": vuln_id}]}


def build_csaf_vex(
    scan: dict[str, Any],
    target: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    components: list[dict[str, Any]],
    *,
    release: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """CSAF 2.0 document of category ``csaf_vex``; ``{}`` without vulnerability findings.

    Each export is a snapshot: the tracking id carries the generation time, so a
    later export of the same scan is a new document, not an unversioned edit.
    """
    statements = collect_statements(findings)
    if not statements:
        return {}
    now = now or datetime.now(tz=UTC)
    stamp = _iso(now)
    scan_id = str(scan.get("_id") or scan.get("id") or "scan")
    ident = target_identity(scan, target)
    purls = component_purls(components)

    target_pid = "HECATE-TARGET"
    target_product: dict[str, Any] = {"name": ident["name"], "product_id": target_pid}
    if ident["purl"]:
        target_product["product_identification_helper"] = {"purl": ident["purl"]}

    # One product per distinct package, one relationship product per package
    # "as a component of" the target; statuses refer to the relationship.
    package_pids: dict[tuple[str, str], str] = {}
    full_products = [target_product]
    relationships: list[dict[str, Any]] = []
    for st in statements:
        key = (st["package_name"], st["package_version"])
        if key in package_pids:
            continue
        pid = f"HECATE-PKG-{len(package_pids) + 1:04d}"
        package_pids[key] = pid
        label = f"{key[0]} {key[1]}".strip() or "unknown package"
        product: dict[str, Any] = {"name": label, "product_id": pid}
        purl = purl_for(st, purls)
        if purl:
            product["product_identification_helper"] = {"purl": purl}
        full_products.append(product)
        relationships.append({
            "category": "default_component_of",
            "product_reference": pid,
            "relates_to_product_reference": target_pid,
            "full_product_name": {
                "name": f"{label} as a component of {ident['name']}",
                "product_id": f"{pid}:{target_pid}",
            },
        })

    by_vuln: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for st in statements:
        by_vuln[st["vulnerability_id"]].append(st)

    vulnerabilities: list[dict[str, Any]] = []
    for vuln_id in sorted(by_vuln):
        sts = by_vuln[vuln_id]
        product_status: dict[str, list[str]] = defaultdict(list)
        flags: dict[str, list[str]] = defaultdict(list)
        threats: list[dict[str, Any]] = []
        remediations: dict[tuple[str, str], list[str]] = defaultdict(list)
        review_lines: list[str] = []
        title = next((s["title"] for s in sts if s["title"]), None)
        for st in sts:
            rel_pid = f"{package_pids[(st['package_name'], st['package_version'])]}:{target_pid}"
            group = CSAF_STATUS_GROUPS[st["status"]]
            if rel_pid in product_status[group]:
                continue
            product_status[group].append(rel_pid)
            label = vex_justification_label(st["justification"])
            free_text = st["detail"] or (st["justification"] if not label else None)
            if st["status"] == "not_affected":
                # 6.1.27.9: every known_not_affected product needs a flag or an
                # impact threat; at most one justification flag per product.
                if label:
                    flags[label].append(rel_pid)
                if free_text or not label:
                    threats.append({
                        "category": "impact",
                        "details": free_text or "Assessed as not affected; no justification recorded.",
                        "product_ids": [rel_pid],
                    })
            elif st["status"] == "affected":
                # 6.1.27.10: every known_affected product needs a remediation.
                category, details = _csaf_remediation(st, free_text)
                remediations[(category, details)].append(rel_pid)
            note = review_note(st)
            if note:
                review_lines.append(f"{st['package_name']} {st['package_version']}".strip() + f": {note}")
        entry: dict[str, Any] = _vuln_ids(vuln_id)
        entry["notes"] = [{
            "category": "description",
            "title": "Finding",
            "text": title or f"{vuln_id} reported for {', '.join(sorted({s['package_name'] for s in sts}))}.",
        }]
        if review_lines:
            entry["notes"].append({
                "category": "details",
                "title": "Assessment evidence",
                "text": "\n".join(review_lines),
            })
        entry["product_status"] = {k: sorted(v) for k, v in product_status.items()}
        if flags:
            entry["flags"] = [{"label": k, "product_ids": sorted(v)} for k, v in sorted(flags.items())]
        if threats:
            entry["threats"] = threats
        if remediations:
            entry["remediations"] = [
                {"category": c, "details": d, "product_ids": sorted(p)}
                for (c, d), p in sorted(remediations.items())
            ]
        vulnerabilities.append(entry)

    tracking_id = csaf_tracking_id(scan_id, now)
    summary_lines = [
        f"VEX statements for {ident['name']} from Hecate scan {scan_id}.",
    ]
    if release and release.get("label"):
        summary_lines.append(f"Release: {release['label']}.")
    if ident["commit_sha"]:
        summary_lines.append(f"Commit: {ident['commit_sha']}.")
    if ident["image_ref"]:
        summary_lines.append(f"Image: {ident['image_ref']}.")
    summary_lines.append(
        "Findings that have not been assessed yet are listed as under investigation."
    )
    publisher: dict[str, Any] = {
        "category": publisher_category(),
        "name": settings.csaf_publisher_name,
        "namespace": settings.csaf_publisher_namespace,
    }
    if settings.csaf_publisher_contact:
        publisher["contact_details"] = settings.csaf_publisher_contact
    title_text = f"VEX for {ident['name']}"
    if release and release.get("label"):
        title_text += f" {release['label']}"
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "lang": "en",
            "title": title_text,
            "publisher": publisher,
            "notes": [{"category": "summary", "title": "Scope", "text": " ".join(summary_lines)}],
            "tracking": {
                "id": tracking_id,
                "status": "final",
                "version": "1",
                "initial_release_date": stamp,
                "current_release_date": stamp,
                "revision_history": [{
                    "date": stamp,
                    "number": "1",
                    "summary": f"Generated by Hecate from scan {scan_id}.",
                }],
                "generator": {
                    "date": stamp,
                    "engine": {"name": "Hecate", "version": _generator_version()},
                },
            },
        },
        "product_tree": {
            "full_product_names": full_products,
            "relationships": relationships,
        },
        "vulnerabilities": vulnerabilities,
    }


_PUBLISHER_CATEGORIES = frozenset({"coordinator", "discoverer", "other", "translator", "user", "vendor"})


def publisher_category() -> str:
    value = (settings.csaf_publisher_category or "").strip().lower()
    return value if value in _PUBLISHER_CATEGORIES else "other"


def _csaf_remediation(st: dict[str, Any], free_text: str | None) -> tuple[str, str]:
    for response in st["response"]:
        category = _RESPONSE_TO_REMEDIATION.get(response)
        if category:
            return category, free_text or _action_text(st)
    if st["fix_version"]:
        return "vendor_fix", free_text or _action_text(st)
    return "none_available", free_text or _action_text(st)


# ---------------------------------------------------------------- loading


async def load_vex_inputs(repos: Any, scan_id: str) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]] | None:
    """Scan, target, findings and SBOM rows for an export; ``None`` for an unknown scan.

    ``repos`` is anything with ``scan_repo`` / ``target_repo`` / ``finding_repo``
    / ``sbom_repo`` (a ``ScanService``).
    """
    scan = await repos.scan_repo.get(scan_id)
    if not scan:
        return None
    target = await repos.target_repo.get(scan.get("target_id", ""))
    _, findings = await repos.finding_repo.list_by_scan(
        scan_id, limit=MAX_EXPORT_FINDINGS, include_dismissed=True,
    )
    components = await repos.sbom_repo.list_all_by_scan(scan_id)
    return scan, target, findings, components


async def export_vex_document(repos: Any, scan_id: str, fmt: str) -> tuple[dict[str, Any], str] | None:
    """(document, filename) for one format; ``None`` for an unknown scan.

    The document is ``{}`` when there is nothing to state (CycloneDX: no finding
    with a VEX status; OpenVEX / CSAF: no vulnerability finding).
    """
    if fmt not in VEX_FORMATS:
        raise ValueError(f"Unknown VEX format: {fmt}")
    if fmt == "cyclonedx":
        from app.services.vex_service import VexService

        if not await repos.scan_repo.get(scan_id):
            return None
        doc = await VexService(repos.finding_repo, repos.scan_repo).export_cyclonedx_vex(scan_id)
        return doc, f"vex-{scan_id}.cdx.json"
    loaded = await load_vex_inputs(repos, scan_id)
    if loaded is None:
        return None
    scan, target, findings, components = loaded
    if fmt == "openvex":
        return build_openvex(scan, target, findings, components), f"vex-{scan_id}.openvex.json"
    now = datetime.now(tz=UTC)
    doc = build_csaf_vex(scan, target, findings, components, release=scan.get("release"), now=now)
    return doc, csaf_filename(csaf_tracking_id(scan_id, now))
