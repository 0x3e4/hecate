"""Regression tests pinning documented data-correctness hotspots.

These are the pure/deterministic functions whose invariants are recorded in
CLAUDE.md and whose past regressions motivated fixes. Each has real correctness
risk and no prior test — a silent change here corrupts stored data.
"""
from __future__ import annotations

import pytest

from app.repositories.vulnerability_repository import (
    _allow_overwrite,
    _is_empty,
    _is_priority_source,
)
from app.services.attack_chain_stages import categorize_cve
from app.services.ingestion.normalizer import _parse_epss


# --------------------------------------------------------------------------
# EPSS scale invariant (canonical storage is a 0..1 probability).
# The '0.38 stored as 38%' regression: EUVD ships percentages for ALL
# magnitudes, so the value must ALWAYS be divided by 100 (no `if raw > 1`).
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (88.66, 0.8866),     # large percentage
        (0.38, 0.0038),      # small percentage — the motivating regression
        (0, 0.0),
        (100, 1.0),
        (150, 1.0),          # clamp high
        (-5, 0.0),           # clamp low
        ("88,66", 0.8866),   # comma decimal
        ("0.38", 0.0038),
        ({"score": 88.66}, 0.8866),
        ({"epssScore": "0.38"}, 0.0038),
    ],
)
def test_parse_epss_scales_and_clamps(value, expected):
    assert _parse_epss(value) == expected


@pytest.mark.parametrize("value", [None, "n/a", "", {}])
def test_parse_epss_returns_none_for_unparseable(value):
    assert _parse_epss(value) is None


# --------------------------------------------------------------------------
# NVD↔EUVD priority-gate helpers (enrich-vs-overwrite decision).
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", [], {}, (), set()])
def test_is_empty_true(value):
    assert _is_empty(value) is True


@pytest.mark.parametrize("value", [0, 0.0, False, "x", [1], {"a": 1}])
def test_is_empty_false_including_zero(value):
    # A legitimate base_score=0.0 must NOT be treated as missing data.
    assert _is_empty(value) is False


def test_allow_overwrite_priority_always_wins():
    assert _allow_overwrite(True, "existing", ["value"]) is True


def test_allow_overwrite_non_priority_only_fills_when_all_empty():
    assert _allow_overwrite(False, "", [], None) is True        # all empty -> fill
    assert _allow_overwrite(False, "", "x") is False            # one present -> keep
    assert _allow_overwrite(False, 0.0) is False                # 0.0 is present, not empty


def test_is_priority_source_matches_configured_default():
    # Default INGESTION_PRIORITY_VULN_DB is NVD.
    assert _is_priority_source("nvd") is True
    assert _is_priority_source("NVD") is True
    assert _is_priority_source("euvd") is False


# --------------------------------------------------------------------------
# categorize_cve — deterministic CWE→stage bucketing with severity fallback.
# Never silently drops a finding (unknown CWE -> severity -> default).
# --------------------------------------------------------------------------

def test_categorize_prefers_first_matching_cwe():
    assert categorize_cve(["CWE-89"], "high") == "foothold"          # SQLi
    assert categorize_cve(["CWE-798"], "low") == "credential_access"  # hardcoded creds
    assert categorize_cve(["CWE-269"], "low") == "priv_escalation"
    assert categorize_cve(["CWE-787"], "low") == "impact"


def test_categorize_walks_cwes_in_order():
    # First recognised CWE wins; an unknown leading CWE is skipped.
    assert categorize_cve(["CWE-99999", "CWE-89"], "low") == "foothold"


def test_categorize_falls_back_to_severity_then_default():
    assert categorize_cve([], "critical") == "impact"
    assert categorize_cve(None, "medium") == "priv_escalation"
    assert categorize_cve(["CWE-99999"], "low") == "credential_access"
    # Unknown severity and no CWE -> documented default, never dropped.
    assert categorize_cve(None, None) == "credential_access"


def test_categorize_is_deterministic():
    args = (["CWE-89", "CWE-787"], "high")
    assert categorize_cve(*args) == categorize_cve(*args)
