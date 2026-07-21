"""Tests for CVSS vector-string parsing.

Guards the fix for the duplicate-key ``value_mapping`` bug: single-letter metric
values are context-dependent, so a flat fallback dict mis-expanded every metric
that lacked an explicit branch (modified-environmental + CVSS v4 metrics). Each
metric now dispatches to its own map.
"""
from __future__ import annotations

import pytest

from app.services.ingestion.normalizer import _parse_cvss_vector_string as parse


def test_v31_base_vector_expands_correctly():
    m = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H")
    assert m["version"] == "3.1"
    assert m["attackVector"] == "NETWORK"
    assert m["attackComplexity"] == "LOW"
    assert m["privilegesRequired"] == "LOW"
    assert m["userInteraction"] == "NONE"
    assert m["scope"] == "UNCHANGED"
    assert m["confidentialityImpact"] == "LOW"
    assert m["integrityImpact"] == "NONE"
    assert m["availabilityImpact"] == "HIGH"


def test_v2_authentication_uses_pr_style_map():
    m = parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
    assert m["authentication"] == "NONE"
    # v2 impact uses PARTIAL/COMPLETE
    assert m["confidentialityImpact"] == "PARTIAL"


def test_v4_base_vector():
    m = parse("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:L/SA:N")
    assert m["attackRequirements"] == "PRESENT"
    assert m["vulnConfidentialityImpact"] == "HIGH"
    assert m["subIntegrityImpact"] == "LOW"


@pytest.mark.parametrize(
    "vector,key,expected",
    [
        # Previously mis-expanded by the collapsed flat dict:
        ("CVSS:3.1/MS:U", "modifiedScope", "UNCHANGED"),            # was "UNKNOWN"
        ("CVSS:3.1/MAV:N", "modifiedAttackVector", "NETWORK"),      # was "NONE"
        ("CVSS:3.1/MAC:H", "modifiedAttackComplexity", "HIGH"),
        ("CVSS:3.1/MPR:L", "modifiedPrivilegesRequired", "LOW"),
        ("CVSS:4.0/R:A", "recovery", "AUTOMATIC"),                  # was "ACTIVE"
        ("CVSS:4.0/R:U", "recovery", "USER"),                      # was "UNKNOWN"
        ("CVSS:4.0/V:C", "valueDensity", "CONCENTRATED"),          # was "CONFIRMED"
        ("CVSS:4.0/V:D", "valueDensity", "DIFFUSE"),
        ("CVSS:4.0/AU:Y", "automatable", "YES"),
        ("CVSS:4.0/AU:N", "automatable", "NO"),
        ("CVSS:4.0/RE:M", "vulnerabilityResponseEffort", "MODERATE"),
    ],
)
def test_previously_broken_metrics_now_correct(vector, key, expected):
    assert parse(vector)[key] == expected


def test_modified_metrics_accept_not_defined():
    assert parse("CVSS:3.1/MS:X")["modifiedScope"] == "NOT_DEFINED"
    assert parse("CVSS:4.0/R:X")["recovery"] == "NOT_DEFINED"


def test_provider_urgency_values_are_kept_raw():
    # v4 providerUrgency values are already words, not single letters.
    assert parse("CVSS:4.0/U:Amber")["providerUrgency"] == "Amber"


def test_unknown_metric_value_is_kept_as_is():
    # An unrecognised value must not be silently mangled.
    assert parse("CVSS:3.1/AV:Z")["attackVector"] == "Z"
