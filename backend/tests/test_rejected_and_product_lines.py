"""Three false inventory matches and their causes.

1. CVE-2026-56401 (Wazuh) was rejected; the EUVD upsert kept clearing the
   NVD's rejected flag, because EUVD only carries the CVE program's text.
2. The same CVE's CPE pins ``wazuh:5.0.0:alpha0/beta1/beta2`` were read as the
   final 5.0.0: CPE keeps a pre-release in the *update* field.
3. CVE-2023-24896 / CVE-2023-36800 are Dynamics 365 *Finance and
   Operations* (10.0.x) advisories; NVD names the line only in target_sw of a
   ``microsoft:dynamics_365`` CPE, and Dynamics 365 9.1 on-premises matched.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.models.vulnerability import CpeMatch, VulnerabilityDocument
from app.repositories import vulnerability_repository as repo_module
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.cpe_version import cpe_version, version_with_update
from app.services.ingestion.normalizer import _determine_rejected, _parse_cpe_uri_details
from app.services.inventory_matcher import (
    collect_product_evidence,
    cpe_match_span,
    edition_base_products,
    edition_pairs,
    evidence_matches,
    items_for_vuln,
)
from app.services.version_ranges import build_version_ranges

from tests.fake_mongo import FakeCollection

REJECTED_TEXT = "This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."


# --------------------------------------------------------------------------
# 1. Rejection
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"description": REJECTED_TEXT}, True),
        ({"description": "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."}, True),
        ({"cve": {"vulnStatus": "Rejected"}}, True),
        ({"description": "Wazuh wazuh-modulesd before 5.0.0-beta3 contains a null pointer dereference."}, False),
        ({"description": "A flaw in the rejection handler of the login form."}, False),
    ],
)
def test_rejection_is_recognised(record: dict[str, Any], expected: bool) -> None:
    assert _determine_rejected(record) is expected


def _euvd_document(rejected: bool) -> VulnerabilityDocument:
    return VulnerabilityDocument(
        vuln_id="CVE-2026-56401",
        source_id="EUVD-2026-42261",
        source="EUVD",
        title="CVE-2026-56401",
        summary="Wazuh wazuh-modulesd null pointer dereference",
        rejected=rejected,
        ingested_at=datetime.now(tz=UTC),
    )


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> VulnerabilityRepository:
    async def keep(payload: dict[str, Any], *_args: Any) -> dict[str, Any]:
        return payload

    async def no_index(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(repo_module, "_check_and_offload_oversized_raw_data", keep)
    monkeypatch.setattr(repo_module, "async_index_document", no_index)
    # The constructor would create the OpenSearch index.
    monkeypatch.setattr(repo_module, "ensure_vulnerability_index", lambda _name: None)
    return VulnerabilityRepository(FakeCollection(), FakeCollection(), index_name="test")


async def test_euvd_does_not_clear_a_rejection(repo: VulnerabilityRepository) -> None:
    await repo.collection.replace_one(
        {"_id": "CVE-2026-56401"},
        {"_id": "CVE-2026-56401", "vuln_id": "CVE-2026-56401", "title": "x", "summary": REJECTED_TEXT,
         "rejected": True, "sources": [{"source": "NVD"}]},
        upsert=True,
    )
    await repo.upsert_from_euvd(_euvd_document(rejected=False), euvd_raw={"id": "EUVD-2026-42261"})
    assert repo.collection.by_id("CVE-2026-56401")["rejected"] is True


async def test_euvd_can_still_mark_a_record_rejected(repo: VulnerabilityRepository) -> None:
    await repo.collection.replace_one(
        {"_id": "CVE-2026-56401"},
        {"_id": "CVE-2026-56401", "vuln_id": "CVE-2026-56401", "title": "x", "summary": "y",
         "rejected": False, "sources": [{"source": "NVD"}]},
        upsert=True,
    )
    await repo.upsert_from_euvd(_euvd_document(rejected=True), euvd_raw={"id": "EUVD-2026-42261"})
    assert repo.collection.by_id("CVE-2026-56401")["rejected"] is True


# --------------------------------------------------------------------------
# 2. Pre-release in the CPE update field
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("version", "update", "expected"),
    [
        ("5.0.0", "beta1", "5.0.0-beta1"),
        ("5.0.0", "alpha0", "5.0.0-alpha0"),
        ("2.1", "RC2", "2.1-rc2"),
        ("1.0", "preview.3", "1.0-preview.3"),
        ("2008", "sp2", "2008"),        # a service pack comes after, not before
        ("7.0", "update_45", "7.0"),
        ("5.0.0", "*", "5.0.0"),
        ("5.0.0", "-", "5.0.0"),
        ("*", "beta1", None),
        (None, "beta1", None),
    ],
)
def test_version_with_update(version: str | None, update: str, expected: str | None) -> None:
    assert version_with_update(version, update) == expected


def test_normalizer_and_matcher_read_the_same_version() -> None:
    criteria = "cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"
    assert cpe_version(criteria) == "5.0.0-beta1"
    assert _parse_cpe_uri_details(criteria)["version"] == "5.0.0-beta1"
    assert _parse_cpe_uri_details("cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*")["version"] is None


def test_beta_pins_no_longer_cover_the_final_release() -> None:
    pins = [
        cpe_match_span(CpeMatch(criteria=f"cpe:2.3:a:wazuh:wazuh:5.0.0:{tag}:*:*:*:*:*:*", vulnerable=True))[0][0]
        for tag in ("alpha0", "beta1", "beta2")
    ]
    assert pins == ["5.0.0-alpha0", "5.0.0-beta1", "5.0.0-beta2"]
    evidence = collect_product_evidence(
        [],
        [{"nodes": [{"operator": "OR", "matches": [
            {"vulnerable": True, "criteria": f"cpe:2.3:a:wazuh:wazuh:5.0.0:{tag}:*:*:*:*:*:*"}
            for tag in ("alpha0", "beta1", "beta2")
        ]}]}],
        [],
    )[("wazuh", "wazuh")]
    assert evidence_matches("5.0.0-beta1", evidence)
    assert not evidence_matches("5.0.0", evidence)


def test_a_rejected_record_affects_nothing() -> None:
    vuln = {
        "rejected": True,
        "vendor_slugs": ["wazuh"],
        "product_slugs": ["wazuh"],
        "impactedProducts": [{"vendor": {"slug": "wazuh"}, "product": {"slug": "wazuh"}, "versions": ["< 5.0.0"]}],
    }
    item = {"vendor_slug": "wazuh", "product_slug": "wazuh", "version": "4.14.10"}
    assert items_for_vuln(vuln, [item]) == []
    assert items_for_vuln({**vuln, "rejected": False}, [item]) == [item]


# --------------------------------------------------------------------------
# 3. Product lines in target_sw (Dynamics 365)
# --------------------------------------------------------------------------

# CVE-2023-24896 as stored after the NVD sync.
FINANCE_CVE = {
    "vuln_id": "CVE-2023-24896",
    "vendors": ["microsoft"],
    "products": ["dynamics 365"],
    "vendor_slugs": ["microsoft"],
    "product_slugs": ["dynamics-365"],
    "impactedProducts": [{
        "vendor": {"name": "microsoft", "slug": "microsoft"},
        "product": {"name": "dynamics 365", "slug": "dynamics-365"},
        "versions": ["< 10.0.32"],
        "vulnerable": True,
        "environments": ["finance and operations"],
    }],
    "cpe_configurations": [{"nodes": [{"operator": "OR", "matches": [{
        "vulnerable": True,
        "criteria": "cpe:2.3:a:microsoft:dynamics_365:*:*:*:*:*:finance_and_operations:*:*",
        "versionEndExcluding": "10.0.32",
        "vendor": "microsoft",
        "product": "dynamics 365",
        "targetSw": "finance_and_operations",
    }]}]}],
    "cpes": ["cpe:2.3:a:microsoft:dynamics_365:*:*:*:*:*:finance_and_operations:*:*"],
}

# An on-premises Dynamics 365 (Customer Engagement) advisory: no target_sw.
ON_PREM_CVE = {
    "vuln_id": "CVE-2099-0001",
    "vendor_slugs": ["microsoft"],
    "product_slugs": ["dynamics-365"],
    "impactedProducts": [{
        "vendor": {"name": "microsoft", "slug": "microsoft"},
        "product": {"name": "dynamics 365", "slug": "dynamics-365"},
        "versions": [">= 9.1, < 9.1.49"],
        "vulnerable": True,
        "environments": [],
    }],
    "cpes": ["cpe:2.3:a:microsoft:dynamics_365:*:*:*:*:on-premises:*:*:*"],
}

ON_PREM = {"vendor_slug": "microsoft", "product_slug": "dynamics-365", "version": "9.1.48.04"}
FINANCE_OLD = {"vendor_slug": "microsoft", "product_slug": "dynamics-365-for-finance-and-operations", "version": "10.0.30"}
FINANCE_NEW = {"vendor_slug": "microsoft", "product_slug": "dynamics-365-for-finance-and-operations", "version": "10.0.40"}
FINANCE_SHORT = {"vendor_slug": "microsoft", "product_slug": "dynamics-365-finance", "version": "10.0.30"}


def test_a_finance_and_operations_advisory_skips_the_on_premises_server() -> None:
    assert items_for_vuln(FINANCE_CVE, [ON_PREM]) == []


def test_it_still_reaches_finance_and_operations_items() -> None:
    assert items_for_vuln(FINANCE_CVE, [FINANCE_OLD, FINANCE_NEW, FINANCE_SHORT]) == [FINANCE_OLD, FINANCE_SHORT]


def test_an_advisory_without_a_line_still_reaches_the_on_premises_server() -> None:
    assert items_for_vuln(ON_PREM_CVE, [ON_PREM]) == [ON_PREM]
    assert items_for_vuln(ON_PREM_CVE, [FINANCE_OLD]) == []


def test_the_range_index_splits_the_same_way() -> None:
    ranges = build_version_ranges(
        impacted_products=FINANCE_CVE["impactedProducts"],
        cpe_configurations=FINANCE_CVE["cpe_configurations"],
        cpes=FINANCE_CVE["cpes"],
    )
    products = {r["productSlug"] for r in ranges}
    assert "dynamics-365" not in products
    assert {"dynamics-365-for-finance-and-operations", "dynamics-365-finance-and-operations"} <= products


def test_a_platform_target_sw_splits_nothing() -> None:
    assert edition_pairs(("expressjs", "express"), "node.js") == [("expressjs", "express")]
    evidence = collect_product_evidence(
        [],
        [{"nodes": [{"operator": "OR", "matches": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:expressjs:express:*:*:*:*:*:node.js:*:*",
            "versionEndExcluding": "4.19.2",
        }]}]}],
        [],
    )
    assert set(evidence) == {("expressjs", "express")}


def test_edition_base_products() -> None:
    assert edition_base_products("microsoft", "dynamics-365-for-finance-and-operations") == {"dynamics-365"}
    assert edition_base_products("microsoft", "dynamics-365") == set()
    assert edition_base_products("microsoft", "dynamics-crm") == set()
    assert edition_base_products("other", "dynamics-365-finance") == set()
    assert edition_pairs(("microsoft", "dynamics-365"), "on-premises") == [("microsoft", "dynamics-365")]
