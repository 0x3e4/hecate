"""Severity by source on the vulnerability detail page."""
from __future__ import annotations

from typing import Any

import pytest

from app.services.severity_provenance import (
    build_severity_provenance,
    classify_source,
    extract_severity_sources,
    find_disagreement,
    severity_band,
)

V31_NVD = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_CNA = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"


def _nvd_entry(source: str, mtype: str, score: float, vector: str, version: str = "3.1") -> dict[str, Any]:
    return {"source": source, "type": mtype,
            "data": {"version": version, "baseScore": score, "vectorString": vector}}


METRICS = {
    "v31": [
        _nvd_entry("nvd@nist.gov", "Primary", 9.8, V31_NVD),
        _nvd_entry("security@apache.org", "Secondary", 4.2, V31_CNA),
        {"source": "GHSA", "type": "Primary",
         "data": {"version": "3.1", "baseScore": 9.8, "vectorString": V31_NVD, "baseSeverity": "critical"}},
    ],
    "v20": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
             "data": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}],
    "v40": [{"source": "OSV", "type": "Primary", "data": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N"}}],
}


@pytest.mark.parametrize(
    ("source", "mtype", "kind"),
    [
        ("nvd@nist.gov", "Primary", "nvd"),
        ("security@apache.org", "Secondary", "cna"),
        ("134c704f-9b21-4f2e-91b3-4a467353bcc0", "Secondary", "cna"),
        ("GHSA", "Primary", "ghsa"),
        ("OSV", "Primary", "osv"),
        ("GitHub_M", None, "euvd"),
    ],
)
def test_sources_are_classified(source: str, mtype: str | None, kind: str) -> None:
    assert classify_source(source, mtype)[0] == kind


def test_uuid_cna_sources_get_a_readable_label() -> None:
    assert classify_source("134c704f-9b21-4f2e-91b3-4a467353bcc0", "Secondary") == ("cna", "CNA")


def test_rows_skip_bare_vectors_and_sort_newest_version_first() -> None:
    rows = extract_severity_sources(METRICS)
    assert [r["version"] for r in rows] == ["3.1", "3.1", "3.1", "2.0"]
    assert all(r["kind"] != "osv" for r in rows)  # a bare v4 vector has no score
    v2 = rows[-1]
    assert v2["severity"] == "high"  # v2 band, no "critical" in v2


def test_bands() -> None:
    assert severity_band(9.0, "3.1") == "critical"
    assert severity_band(9.5, "2.0") == "high"
    assert severity_band(0.0, "3.1") == "none"
    assert severity_band(None, "3.1") is None


def test_primary_is_matched_and_disagreement_flagged() -> None:
    prov = build_severity_provenance(
        {"version": "3.1", "base_score": 9.8, "severity": "critical", "vector": V31_NVD},
        METRICS,
        priority_db="NVD",
    )
    primary = [r for r in prov["sources"] if r["isPrimary"]]
    # NVD and GHSA send the same vector; the priority database is named.
    assert len(primary) == 1 and primary[0]["kind"] == "nvd"
    assert prov["primary"]["source"] == "NVD" and prov["priorityDb"] == "NVD"
    assert prov["disagreement"] is True
    detail = prov["disagreementDetail"]
    assert detail["cvssMajor"] == "3" and detail["spread"] == 5.6
    assert detail["bands"] == ["medium", "critical"]


def _rows(*pairs: tuple[str, float]) -> list[dict[str, Any]]:
    return [
        {"source": s, "kind": "cna", "version": "3.1", "baseScore": score,
         "severity": severity_band(score, "3.1"), "vector": None}
        for s, score in pairs
    ]


def test_disagreement_thresholds() -> None:
    # 1.9 apart, same band: agree.
    assert find_disagreement(_rows(("A", 7.0), ("B", 8.9))) is None
    # 2.0 apart: disagree, even in one band.
    assert find_disagreement(_rows(("A", 4.0), ("B", 6.0)))["spread"] == 2.0
    # 0.2 apart across a band edge: disagree.
    assert find_disagreement(_rows(("A", 8.9), ("B", 9.1)))["bands"] == ["high", "critical"]
    # One source alone never disagrees with itself.
    assert find_disagreement(_rows(("A", 2.0), ("A", 9.0))) is None
    # Different CVSS versions are not compared.
    rows = _rows(("A", 9.8)) + [
        {"source": "B", "kind": "nvd", "version": "2.0", "baseScore": 5.0, "severity": "medium", "vector": None}
    ]
    assert find_disagreement(rows) is None


def test_no_metrics() -> None:
    prov = build_severity_provenance({}, {})
    assert prov["sources"] == [] and prov["disagreement"] is False and prov["primary"]["source"] is None
