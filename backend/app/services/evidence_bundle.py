"""Evidence bundle: one ZIP with everything a release's vulnerability handling rests on.

Contents (all JSON unless noted):

- ``sbom/<name>.cdx.json`` and ``sbom/<name>.spdx.json``: the SBOM in
  CycloneDX 1.5 and SPDX 2.3 (``sbom_export``),
- ``vex/vex.cdx.json``, ``vex/vex.openvex.json``, ``vex/<csaf name>.json``:
  the VEX statements in the three formats (``vex_export``),
- ``findings-summary.json``: severity counts, VEX status counts and one row
  per vulnerability finding,
- ``manifest.json``: target, scan, commit / image digest, release label,
  generation time and the SHA-256 of every other file,
- ``SHA256SUMS``: the same hashes for ``sha256sum -c``.

A format with nothing to state (CycloneDX VEX without any assessed finding) is
listed under ``omitted`` in the manifest instead of being written empty.

The bundle is built in memory; ``MAX_UNCOMPRESSED_BYTES`` caps it.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.services.sbom_export import build_cyclonedx_json, build_spdx_json
from app.services.vex_export import (
    build_csaf_vex,
    build_openvex,
    collect_statements,
    csaf_filename,
    csaf_tracking_id,
    load_vex_inputs,
)

MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
BUNDLE_FORMAT = "hecate-evidence-bundle"
BUNDLE_VERSION = 1

_OTHER_TYPES = ("sast-finding", "secret-finding", "compliance-check", "malicious-indicator")


class BundleTooLarge(Exception):
    pass


def _safe(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._+-]+", "-", value).strip("-.")
    return cleaned[:80] or "scan"


def _json_bytes(doc: Any) -> bytes:
    return json.dumps(doc, indent=2, ensure_ascii=False, default=_default).encode("utf-8")


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        value = value if value.tzinfo else value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return str(value)


def findings_summary(scan: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    statements = collect_statements(findings)
    severities = _worst_severities(findings)
    other = Counter(f.get("package_type") for f in findings if f.get("package_type") in _OTHER_TYPES)
    return {
        "scanId": str(scan.get("_id") or ""),
        "severitySummary": scan.get("summary") or {},
        "vulnerabilityFindings": len(statements),
        "vexStatusCounts": dict(Counter(
            st["status"] if st["assessed"] else "unassessed" for st in statements
        )),
        "otherFindings": {k: other.get(k, 0) for k in _OTHER_TYPES},
        "findings": [
            {
                "vulnerabilityId": st["vulnerability_id"],
                "package": st["package_name"],
                "version": st["package_version"],
                "severity": severities.get(
                    (st["vulnerability_id"], st["package_name"], st["package_version"]), "unknown",
                ),
                "fixVersion": st["fix_version"],
                "vexStatus": st["status"] if st["assessed"] else None,
                "vexJustification": st["justification"],
                "assessedVersion": st["assessed_version"],
                "reviewDue": st["review_due"],
                "scanners": st["scanners"],
            }
            for st in statements
        ],
    }


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")


def _worst_severities(findings: list[dict[str, Any]]) -> dict[tuple[str, str, str], str]:
    """Worst severity any scanner gave per (vulnerability, package, version)."""
    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out: dict[tuple[str, str, str], str] = {}
    for f in findings:
        vid = f.get("vulnerability_id")
        if not isinstance(vid, str) or not vid.strip():
            continue
        key = (vid.strip(), str(f.get("package_name") or ""), str(f.get("package_version") or ""))
        sev = str(f.get("severity") or "unknown").lower()
        sev = sev if sev in rank else "unknown"
        if key not in out or rank[sev] < rank[out[key]]:
            out[key] = sev
    return out


def build_bundle_bytes(files: list[tuple[str, bytes]], manifest_base: dict[str, Any]) -> bytes:
    """Zip ``files`` plus ``manifest.json`` and ``SHA256SUMS``. Pure, for tests."""
    total = sum(len(data) for _, data in files)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise BundleTooLarge(f"The bundle would hold {total} bytes (limit {MAX_UNCOMPRESSED_BYTES}).")
    entries = [
        {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for path, data in files
    ]
    manifest = {**manifest_base, "files": entries}
    sums = "".join(f"{e['sha256']}  {e['path']}\n" for e in entries).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in files:
            zf.writestr(path, data)
        zf.writestr("manifest.json", _json_bytes(manifest))
        zf.writestr("SHA256SUMS", sums)
    return buffer.getvalue()


async def build_evidence_bundle(repos: Any, scan_id: str) -> tuple[bytes, str] | None:
    """(zip bytes, filename) for a scan; ``None`` when the scan does not exist."""
    from app.services.vex_service import VexService

    loaded = await load_vex_inputs(repos, scan_id)
    if loaded is None:
        return None
    scan, target, findings, components = loaded
    now = datetime.now(tz=UTC)
    release = scan.get("release") or None
    target_name = (target or {}).get("name") or scan.get("target_name") or scan.get("target_id") or "scan"
    base = _safe(str(target_name).rsplit("/", 1)[-1])
    label = _safe(release["label"]) if release and release.get("label") else scan_id

    files: list[tuple[str, bytes]] = [
        (f"sbom/{base}-{label}.cdx.json", _json_bytes(build_cyclonedx_json(scan, target, components))),
        (f"sbom/{base}-{label}.spdx.json", _json_bytes(build_spdx_json(scan, target, components))),
    ]
    omitted: list[dict[str, str]] = []
    cdx_vex = await VexService(repos.finding_repo, repos.scan_repo).export_cyclonedx_vex(scan_id)
    if cdx_vex:
        files.append(("vex/vex.cdx.json", _json_bytes(cdx_vex)))
    else:
        omitted.append({"path": "vex/vex.cdx.json", "reason": "No finding of this scan has a VEX status."})
    openvex = build_openvex(scan, target, findings, components, now=now)
    csaf = build_csaf_vex(scan, target, findings, components, release=release, now=now)
    if openvex:
        files.append(("vex/vex.openvex.json", _json_bytes(openvex)))
        files.append((f"vex/{csaf_filename(csaf_tracking_id(scan_id, now))}", _json_bytes(csaf)))
    else:
        omitted.append({"path": "vex/vex.openvex.json", "reason": "The scan has no vulnerability findings."})
        omitted.append({"path": "vex/csaf", "reason": "The scan has no vulnerability findings."})
    files.append(("findings-summary.json", _json_bytes(findings_summary(scan, findings))))

    from app.services.vex_export import _generator_version, target_identity

    ident = target_identity(scan, target)
    manifest_base = {
        "format": BUNDLE_FORMAT,
        "formatVersion": BUNDLE_VERSION,
        "generatedAt": _default(now),
        "generator": {"name": "Hecate", "version": _generator_version()},
        "target": {"id": ident["id"], "name": ident["name"], "type": ident["type"], "purl": ident["purl"]},
        "scan": {
            "id": scan_id,
            "status": scan.get("status"),
            "startedAt": scan.get("started_at"),
            "finishedAt": scan.get("finished_at"),
            "commitSha": scan.get("commit_sha"),
            "imageRef": scan.get("image_ref"),
            "branch": scan.get("branch"),
            "scanners": scan.get("scanners") or [],
        },
        "release": (
            {"label": release.get("label"), "note": release.get("note"), "markedAt": release.get("marked_at")}
            if release else None
        ),
        "omitted": omitted,
    }
    data = await asyncio.to_thread(build_bundle_bytes, files, manifest_base)
    return data, f"{base}-{label}-evidence.zip"
