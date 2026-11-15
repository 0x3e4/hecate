"""Who scored a vulnerability, and do they agree?

Hecate shows one CVSS score per vulnerability, but the stored ``cvss_metrics``
keep every score the sources sent: NVD's own, the CNA's (NVD lists it as
``Secondary``), the assigner score EUVD carries, GitHub's and OSV's. Since NIST
stopped enriching most CVEs, the CNA score is often the only one, and where
several exist they can be far apart. This module lays them side by side for
the detail page and flags a disagreement; it adds no ingestion and reads only
what the document already holds.

Which score is primary: ``cvss`` is written by the ``INGESTION_PRIORITY_VULN_DB``
source (NVD by default); the other database only fills an empty score. Within a
record the newest CVSS version wins, and among its entries the highest base
score (``apply_inferred_cvss``), so the shown score can be a CNA's.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from app.core.config import settings

# Base-score spread (same CVSS major version) from which sources "disagree".
DISAGREEMENT_SPREAD = 2.0

_KEY_VERSIONS = {"v40": "4.0", "v31": "3.1", "v30": "3.0", "v20": "2.0"}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SEVERITY_ALIASES = {"moderate": "medium", "important": "high", "none": "none"}
_BAND_ORDER = ("none", "low", "medium", "high", "critical")


def _score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _version(entry_data: Mapping[str, Any], key: str) -> str | None:
    raw = entry_data.get("version")
    if isinstance(raw, (int, float)):
        raw = str(raw)
    if isinstance(raw, str) and raw.strip():
        value = raw.replace("CVSS:", "").strip()
        return value if re.match(r"^\d(\.\d)?$", value) else _KEY_VERSIONS.get(key)
    vector = entry_data.get("vectorString")
    if isinstance(vector, str):
        match = re.match(r"^CVSS:(\d\.\d)/", vector)
        if match:
            return match.group(1)
    return _KEY_VERSIONS.get(key)


def _major(version: str | None) -> str | None:
    return version.split(".", 1)[0] if version else None


def severity_band(score: float | None, version: str | None) -> str | None:
    """Qualitative band of a base score (CVSS v2 has no "critical")."""
    if score is None:
        return None
    if _major(version) == "2":
        return "low" if score < 4.0 else "medium" if score < 7.0 else "high"
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _normalize_severity(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    lowered = value.strip().lower()
    lowered = _SEVERITY_ALIASES.get(lowered, lowered)
    return lowered if lowered in _BAND_ORDER else None


def classify_source(source: Any, metric_type: Any) -> tuple[str, str]:
    """(kind, label) of one ``cvss_metrics`` entry.

    NVD API entries carry ``type`` Primary (NVD itself) or Secondary (the CNA);
    the GHSA and OSV pipelines write ``source`` GHSA / OSV; EUVD entries carry
    the assigner as source and no type.
    """
    src = source.strip() if isinstance(source, str) else ""
    upper = src.upper()
    if upper == "GHSA":
        return "ghsa", "GitHub Advisory"
    if upper == "OSV":
        return "osv", "OSV"
    if src.lower() == "nvd@nist.gov" or upper == "NVD":
        return "nvd", "NVD"
    label = "CNA" if not src or _UUID_RE.match(src) else src
    if isinstance(metric_type, str) and metric_type.strip().lower() in ("primary", "secondary"):
        return "cna", label
    return "euvd", label if src else "EUVD"


def extract_severity_sources(cvss_metrics: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """One row per distinct (source, version, score, vector), newest version first."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    if not isinstance(cvss_metrics, Mapping):
        return rows
    for key, entries in cvss_metrics.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            data = entry.get("data") if isinstance(entry.get("data"), Mapping) else entry
            version = _version(data, str(key))
            score = _score(data.get("baseScore", entry.get("baseScore")))
            vector = data.get("vectorString") or entry.get("vectorString")
            vector = vector if isinstance(vector, str) and vector.strip() else None
            reported = _normalize_severity(data.get("baseSeverity") or entry.get("baseSeverity"))
            if score is None and reported is None:
                continue  # a bare vector (OSV v4) says nothing comparable
            kind, label = classify_source(entry.get("source"), entry.get("type"))
            dedup = (kind, label.lower(), version, score, vector)
            if dedup in seen:
                continue
            seen.add(dedup)
            rows.append({
                "source": label,
                "kind": kind,
                "type": entry.get("type") if isinstance(entry.get("type"), str) else None,
                "version": version,
                "baseScore": score,
                "severity": severity_band(score, version) or reported,
                "vector": vector,
                "isPrimary": False,
            })
    rows.sort(key=lambda r: (-(float(r["version"]) if r["version"] else 0.0), -(r["baseScore"] or 0.0)))
    return rows


def find_disagreement(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The widest disagreement between two sources on the same CVSS major version.

    Sources disagree when their base scores are ``DISAGREEMENT_SPREAD`` or more
    apart or land in different severity bands. Scores of different CVSS
    versions are not compared: v2 and v4 score the same flaw differently by design.
    """
    worst: dict[str, Any] | None = None
    by_major: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        major = _major(row["version"])
        if major:
            by_major.setdefault(major, []).append(row)
    for major, group in by_major.items():
        sources = {r["source"].lower() for r in group}
        if len(sources) < 2:
            continue
        scored = [r for r in group if r["baseScore"] is not None]
        spread = (
            max(r["baseScore"] for r in scored) - min(r["baseScore"] for r in scored)
            if len(scored) >= 2 else 0.0
        )
        bands = sorted({r["severity"] for r in group if r["severity"]}, key=_BAND_ORDER.index)
        if spread >= DISAGREEMENT_SPREAD - 1e-9 or len(bands) > 1:
            candidate = {
                "cvssMajor": major,
                "spread": round(spread, 1),
                "bands": bands,
                "sources": sorted({r["source"] for r in group}),
            }
            if worst is None or candidate["spread"] > worst["spread"]:
                worst = candidate
    return worst


def build_severity_provenance(
    cvss: Mapping[str, Any] | None,
    cvss_metrics: Mapping[str, Any] | None,
    *,
    priority_db: str | None = None,
) -> dict[str, Any]:
    rows = extract_severity_sources(cvss_metrics)
    cvss = cvss if isinstance(cvss, Mapping) else {}
    primary_score = _score(cvss.get("base_score", cvss.get("baseScore")))
    primary_vector = cvss.get("vector") if isinstance(cvss.get("vector"), str) else None
    primary_version = cvss.get("version") if isinstance(cvss.get("version"), str) else None
    priority = (priority_db or settings.ingestion_priority_vuln_db or "NVD").strip().upper()

    match: dict[str, Any] | None = None
    if primary_score is not None or primary_vector:
        candidates = [
            r for r in rows
            if (primary_vector and r["vector"] == primary_vector)
            or (
                not primary_vector
                and r["baseScore"] == primary_score
                and _major(r["version"]) == _major(primary_version)
            )
        ]
        # Several sources can send the same vector; name the priority one.
        candidates.sort(key=lambda r: 0 if r["kind"] == priority.lower() else 1)
        match = candidates[0] if candidates else None
    if match is not None:
        match["isPrimary"] = True

    disagreement = find_disagreement(rows)
    return {
        "sources": rows,
        "primary": {
            "version": primary_version,
            "baseScore": primary_score,
            "severity": _normalize_severity(cvss.get("severity")),
            "vector": primary_vector,
            "source": match["source"] if match else None,
            "kind": match["kind"] if match else None,
        },
        "priorityDb": priority,
        "disagreement": disagreement is not None,
        "disagreementDetail": disagreement,
    }
