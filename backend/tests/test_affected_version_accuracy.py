"""False hits of ``affectedVersion:`` and the inventory matcher.

Two independent causes, both reported against the demo instance:

1. **Platform entries.** NVD lists the software a vulnerable product runs on
   as a ``vulnerable: false`` CPE match ("Next.js < 12.0.5 running on Node.js
   > 15.0.0"). Those ranges were indexed as affected, so
   ``vendorSlugs=nodejs&productSlugs=node-js&dqlQuery=affectedVersion:24.22.1``
   returned the Next.js CVEs CVE-2021-43803 and CVE-2022-36046, and Python
   3.14.10 returned the Odoo CVE-2020-29396.
2. **Release branches.** All ranges sat on one axis, so a version fixed on its
   own release line still fell into a range of another line: nginx 1.30.6 for
   CVE-2026-90439 (stable 1.30.x fixed in 1.30.5), Redis 7.4.12 for
   CVE-2026-81934 (fixed in 7.4.11, matched "< 8.10.1").

Found while checking .NET data: OSV writes ">=12.0.0 <12.0.5" with a space,
which lost its upper bound; NuGet runtime advisories list hundreds of pins and
overflowed the per-document range cap; pre-release bounds were not indexed and
pre-release pins marked the final release.

Every case runs through both the OpenSearch range index
(``build_version_ranges``) and the inventory matcher and asserts they agree,
because the vulnerability list and the inventory pages must not contradict
each other. Fixtures are the real documents from hecate.pw, trimmed.
"""
from __future__ import annotations

import pytest

from app.services.ingestion.circl_pipeline import _build_impacted_products_from_affected
from app.services.ingestion.normalizer import _build_impacted_products_payload
from app.services.inventory_matcher import (
    InventoryKey,
    _coerce_cpe_configurations,
    _coerce_impacted_products,
    coalesce_pins,
    match_in_configuration,
    version_in_ranges,
    version_sort_key,
)
from app.services.version_ranges import (
    MAX_VERSION_RANGES,
    build_version_ranges,
)


def _entry(vendor: str, product: str, versions: list[str], vulnerable: bool | None = True, name=None):
    return {
        "vendor": {"name": vendor, "slug": vendor},
        "product": {"name": name or product, "slug": product},
        "versions": versions,
        "vulnerable": vulnerable,
    }


def _match(criteria: str, vulnerable: bool | None = True, **bounds) -> dict:
    parts = criteria.split(":")
    match = {"criteria": criteria, "vendor": parts[3], "product": parts[4], **bounds}
    if vulnerable is not None:
        match["vulnerable"] = vulnerable
    return match


def _configs(*matches: dict) -> list[dict]:
    return [{"nodes": [{"operator": "OR", "matches": list(matches)}]}]


def affected(
    vendor: str,
    product: str,
    version: str,
    *,
    impacted: list | None = None,
    configs: list | None = None,
    cpes: list | None = None,
) -> bool:
    """Index and matcher decision for one version; fails if they differ."""
    ranges = build_version_ranges(impacted_products=impacted, cpe_configurations=configs, cpes=cpes)
    key = version_sort_key(version)
    assert key is not None, version
    in_index = any(
        r["vendorSlug"] == vendor
        and r["productSlug"] == product
        and r["startKey"] <= key < r["endKey"]
        for r in ranges
    )
    in_matcher = match_in_configuration(
        InventoryKey(vendor_slug=vendor, product_slug=product, version=version),
        _coerce_cpe_configurations(configs or []),
        cpes or [],
        impacted_products=_coerce_impacted_products(impacted or []),
    )
    assert in_index == in_matcher, f"index={in_index} matcher={in_matcher} for {product} {version}"
    return in_index


# --- 1. Platform entries (vulnerable: false) --------------------------------

# CVE-2021-43803 (Next.js): node.js only as the platform.
NEXTJS_IMPACTED = [
    _entry("nodejs", "node-js", ["> 15.0.0"], vulnerable=False, name="node.js"),
    _entry("vercel", "next-js", [">= 11.1.0, < 11.1.3", ">= 12.0.0, < 12.0.5"], name="next.js"),
]
NEXTJS_CPES = [
    "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
]


def test_impacted_products_platform_entry_is_not_affected():
    assert not affected("nodejs", "node-js", "24.22.1", impacted=NEXTJS_IMPACTED, cpes=NEXTJS_CPES)
    assert affected("vercel", "next-js", "11.1.2", impacted=NEXTJS_IMPACTED, cpes=NEXTJS_CPES)


def test_cpe_match_platform_entry_is_not_affected():
    """CVE-2022-36046: the node.js CPE match has ``vulnerable: false``."""
    configs = _configs(
        _match("cpe:2.3:a:vercel:next.js:12.2.3:*:*:*:*:node.js:*:*"),
        _match("cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*", vulnerable=False, versionStartIncluding="15.0.0"),
    )
    assert not affected("nodejs", "node-js", "24.22.1", configs=configs)
    assert affected("vercel", "next-js", "12.2.3", configs=configs)


def test_python_platform_in_both_tiers():
    """CVE-2020-29396 (Odoo), python listed in impactedProducts and as a CPE match."""
    impacted = [
        _entry("odoo", "odoo", [">= 11.0, <= 13.0"]),
        _entry("python", "python", ["3.6.0"], vulnerable=False),
    ]
    configs = _configs(
        _match("cpe:2.3:a:odoo:odoo:*:*:*:*:community:*:*:*", versionStartIncluding="11.0", versionEndIncluding="13.0"),
        _match("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", vulnerable=False, versionStartIncluding="3.6.0"),
    )
    assert not affected("python", "python", "3.14.10", impacted=impacted, configs=configs)
    assert not affected("python", "python", "3.6.0", impacted=impacted, configs=configs)
    assert affected("odoo", "odoo", "12.0", impacted=impacted, configs=configs)


def test_missing_flag_still_counts_as_affected():
    """``CpeMatch.vulnerable`` defaults to False; only an explicit False is a platform."""
    configs = _configs(_match("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", vulnerable=None, versionEndExcluding="2.0"))
    impacted = [_entry("acme", "gadget", ["< 3.0"], vulnerable=None)]
    assert affected("acme", "widget", "1.5", configs=configs)
    assert affected("acme", "gadget", "2.5", impacted=impacted)


def test_flat_platform_cpe_is_skipped():
    """The flat ``cpes`` list holds platform CPEs too, without a flag."""
    platform = "cpe:2.3:a:python:python:3.6.0:*:*:*:*:*:*:*"
    configs = _configs(
        _match("cpe:2.3:a:odoo:odoo:12.0:*:*:*:*:*:*:*"),
        _match(platform, vulnerable=False),
    )
    assert not affected("python", "python", "3.6.0", configs=configs, cpes=[platform])
    # Same pair seen only as a platform in impactedProducts.
    impacted = [_entry("python", "python", [], vulnerable=False)]
    assert not affected("python", "python", "3.6.0", impacted=impacted, cpes=[platform])


def test_product_that_is_platform_and_vulnerable_keeps_its_ranges():
    """A stale impactedProducts entry (old "False wins" aggregation) must not
    hide the vulnerable CPE match of the same product."""
    impacted = [_entry("acme", "server", ["> 1.0"], vulnerable=False)]
    configs = _configs(
        _match("cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", versionEndExcluding="3.4.2"),
        _match("cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", vulnerable=False, versionStartExcluding="1.0"),
    )
    assert affected("acme", "server", "3.4.1", impacted=impacted, configs=configs)
    assert not affected("acme", "server", "5.0", impacted=impacted, configs=configs)


def test_nvd_aggregation_lets_the_vulnerable_match_win():
    configs = [
        {"nodes": [{"operator": "OR", "matches": [
            {"criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", "part": "a", "vendor": "acme",
             "product": "server", "vulnerable": True, "versionEndExcluding": "3.4.2"},
        ]}]},
        {"nodes": [{"operator": "OR", "matches": [
            {"criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", "part": "a", "vendor": "acme",
             "product": "server", "vulnerable": False, "versionStartIncluding": "9.0"},
            {"criteria": "cpe:2.3:a:acme:host:*:*:*:*:*:*:*:*", "part": "a", "vendor": "acme",
             "product": "host", "vulnerable": False, "versionStartIncluding": "2.0"},
        ]}]},
    ]
    entries = {e["product"]["slug"]: e for e in _build_impacted_products_payload(
        cpe_configurations=configs, cpematch_entries=None, cpes=[]
    )}
    assert entries["server"]["vulnerable"] is True
    assert entries["server"]["versions"] == ["< 3.4.2"]  # no platform range mixed in
    assert entries["host"]["vulnerable"] is False
    assert entries["host"]["versions"]  # a pure platform keeps its versions for display


# --- 2. Release branches ------------------------------------------------------

NGINX = [_entry("f5", "nginx-open-source", [">= 1.29.2, < 1.31.6", ">= 1.30.4, < 1.30.5"], name="NGINX Open Source")]


@pytest.mark.parametrize(
    "version, expected",
    [("1.30.6", False), ("1.30.5", False), ("1.30.4", True), ("1.31.2", True),
     ("1.29.2", True), ("1.31.6", False), ("1.29.1", False)],
)
def test_nginx_stable_branch_is_decided_by_its_own_range(version, expected):
    """CVE-2026-90439: stable 1.30.x is fixed in 1.30.5."""
    assert affected("f5", "nginx-open-source", version, impacted=NGINX) is expected


REDIS = [_entry("redis", "redis", [
    "< 6.2.24", "< 7.2.16", "< 7.4.11", "< 8.10.1", "< 8.2.9", "< 8.4.6", "< 8.6.6", "< 8.8.2",
])]


@pytest.mark.parametrize(
    "version, expected",
    [("7.4.12", False), ("7.4.3", True), ("7.4.11", False), ("8.8.1", True), ("8.8.2", False),
     ("6.2.23", True), ("7.3.5", True), ("9.0.0", False)],
)
def test_redis_upper_bound_per_branch(version, expected):
    """CVE-2026-81934. 7.3.x has no fix of its own and stays affected."""
    assert affected("redis", "redis", version, impacted=REDIS) is expected


def test_redis_list_comes_from_the_cve_record_itself():
    """The CNA wrote ``{"version": "0", "lessThan": X}`` per branch; the CIRCL
    builder keeps it faithfully. The fix belongs to the range evaluation."""
    record = {"containers": {"cna": {"affected": [{
        "vendor": "Redis", "product": "Redis", "defaultStatus": "unknown",
        "versions": [
            {"version": "7.4.11", "status": "unaffected"},
            {"version": "0", "status": "affected", "lessThan": "7.4.11", "versionType": "custom"},
            {"version": "0", "status": "affected", "lessThan": "8.10.1", "versionType": "custom"},
        ],
    }]}}}
    (entry,) = _build_impacted_products_from_affected(record)
    assert entry["versions"] == ["< 7.4.11", "< 8.10.1"]
    assert not affected("redis", "redis", "7.4.12", impacted=[entry])


def test_real_hits_survive():
    # CVE-2021-23017: one range, no branches.
    nginx = [_entry("f5", "nginx", [">= 0.6.18, < 1.20.1"])]
    assert affected("f5", "nginx", "1.20.0", impacted=nginx)
    assert not affected("f5", "nginx", "1.20.1", impacted=nginx)
    # CVE-2026-111497: Node's branch is the major; 24.10.0 sits in a range
    # that spans two "branches" and is therefore never clipped.
    node = [_entry("nodejs", "node-js", ["< 22.23.4", ">= 23.0.0, < 24.22.1", ">= 25.0.0, < 26.12.1"], name="node.js")]
    assert affected("nodejs", "node-js", "24.10.0", impacted=node)
    assert affected("nodejs", "node-js", "22.22.0", impacted=node)
    assert not affected("nodejs", "node-js", "22.23.4", impacted=node)
    assert not affected("nodejs", "node-js", "26.12.1", impacted=node)
    # CVE-2026-63030: two branch ranges, nothing to carve.
    wordpress = [_entry("wordpress", "wordpress", [">= 6.9, < 6.9.5", ">= 7.0, < 7.0.2"])]
    assert affected("wordpress", "wordpress", "7.0.1", impacted=wordpress)
    assert not affected("wordpress", "wordpress", "7.1", impacted=wordpress)


def test_lone_upper_bound_keeps_meaning_everything_older():
    assert affected("acme", "lib", "2.5", impacted=[_entry("acme", "lib", ["< 3.0"])])
    assert affected("acme", "lib", "2.9.9", impacted=[_entry("acme", "lib", ["< 3.0.4"])])


def test_upper_bound_at_a_branch_start_is_not_a_branch_range():
    """"< 7.4" ends where 7.4 starts: everything before 7.4, not a fix on 7.4."""
    impacted = [_entry("acme", "lib", ["< 7.4", ">= 7.4.0, < 7.4.3"])]
    assert affected("acme", "lib", "7.3.9", impacted=impacted)
    assert affected("acme", "lib", "7.4.2", impacted=impacted)
    assert not affected("acme", "lib", "7.4.3", impacted=impacted)


def test_calendar_versions():
    lone = [_entry("acme", "cal", ["< 2026.10.18"])]
    assert affected("acme", "cal", "2025.1.1", impacted=lone)
    assert affected("acme", "cal", "2026.10.17", impacted=lone)
    spanning = [_entry("acme", "cal", [">= 2025.1.0, < 2026.10.18"])]
    assert affected("acme", "cal", "2026.3.1", impacted=spanning)
    assert not affected("acme", "cal", "2026.10.18", impacted=spanning)


def test_exact_pins_always_count():
    impacted = [_entry("acme", "lib", ["1.30.7", ">= 1.29.0, < 1.31.0", ">= 1.30.4, < 1.30.5"])]
    assert affected("acme", "lib", "1.30.7", impacted=impacted)
    assert not affected("acme", "lib", "1.30.6", impacted=impacted)


def test_one_product_name_for_several_packages_keeps_the_plain_rule():
    """NVD files every Azure Identity SDK language under one product and
    separates them by target_sw (CVE-2023-36415). Read as branches, Python
    1.10.3 (fixed in 1.14.1) would drop out."""
    impacted = [_entry("microsoft", "azure-identity-sdk", ["< 1.10.2", "< 1.14.1", "< 3.3.1"])]
    configs = _configs(
        _match("cpe:2.3:a:microsoft:azure_identity_sdk:*:*:*:*:*:java:*:*", versionEndExcluding="1.10.2"),
        _match("cpe:2.3:a:microsoft:azure_identity_sdk:*:*:*:*:*:python:*:*", versionEndExcluding="1.14.1"),
        _match("cpe:2.3:a:microsoft:azure_identity_sdk:*:*:*:*:*:javascript:*:*", versionEndExcluding="3.3.1"),
    )
    assert affected("microsoft", "azure-identity-sdk", "1.10.3", impacted=impacted, configs=configs)
    assert affected("microsoft", "azure-identity-sdk", "1.10.3", configs=configs)
    assert not affected("microsoft", "azure-identity-sdk", "3.3.1", impacted=impacted, configs=configs)


def test_na_target_counts_as_its_own_target():
    """CVE-2023-44487: grpc-go (target "go") and the C core (target "-")."""
    configs = _configs(
        _match("cpe:2.3:a:grpc:grpc:*:*:*:*:*:go:*:*", versionEndExcluding="1.56.3"),
        _match("cpe:2.3:a:grpc:grpc:*:*:*:*:*:-:*:*", versionEndIncluding="1.59.2"),
    )
    assert affected("grpc", "grpc", "1.58.3", configs=configs)
    assert not affected("grpc", "grpc", "1.59.3", configs=configs)


@pytest.mark.parametrize(
    "version, expected",
    [("14.1.56.72", True), ("14.1.56.73", False), ("14.1.4.42", True), ("13.1.60.1", False)],
)
def test_netscaler_branch_builds_agree(version, expected):
    impacted = [_entry("netscaler", "adc", [">= 14.1, < 56.73", ">= 13.1, < 59.22"])]
    assert affected("netscaler", "adc", version, impacted=impacted) is expected


# --- 3. .NET ------------------------------------------------------------------


@pytest.mark.parametrize(
    "version, expected",
    [("8.0.25", True), ("8.0.32", True), ("8.0.33", False), ("8.0.40", False),
     ("9.0.21", True), ("9.0.22", False), ("10.0.13", True), ("10.0.14", False),
     ("11.0.0", True), ("11.0.1", False), ("7.0.20", False), ("6.0.36", False)],
)
def test_dotnet_runtime_lines(version, expected):
    """CVE-2026-111497, microsoft/net: one fix per supported line."""
    impacted = [_entry("microsoft", "net", ["11.0.0", ">= 10.0.0, < 10.0.14", ">= 8.0.0, < 8.0.33", ">= 9.0.0, < 9.0.22"], name=".NET")]
    assert affected("microsoft", "net", version, impacted=impacted) is expected


def test_dotnet_listed_only_as_platform():
    """CVE-2023-36038 / CVE-2026-85790 list .NET 8.0.0 only as the platform."""
    impacted = [_entry("microsoft", "net", ["10.0.0", "11.0.0", "8.0.0", "9.0.0"], vulnerable=False)]
    assert not affected("microsoft", "net", "8.0.0", impacted=impacted)


def test_osv_space_separated_range_keeps_its_upper_bound():
    """">=12.0.0 <12.0.5" read as ">= 12.0.0" and matched every later release."""
    impacted = [_entry("npm", "next", [">=12.0.0 <12.0.5", ">=0.9.9 <11.1.3"])]
    assert affected("npm", "next", "12.0.4", impacted=impacted)
    assert not affected("npm", "next", "15.0.0", impacted=impacted)
    assert not affected("npm", "next", "11.1.3", impacted=impacted)


def _nuget_pins(line: str, last: int, skip: tuple[int, ...] = ()) -> list[str]:
    return [f"{line}.{patch}" for patch in range(last + 1) if patch not in skip]


def test_nuget_pin_lists_fit_and_keep_their_gaps():
    """CVE-2026-88092 lists ~90 pins for each of 14 runtime packages; the last
    packages used to fall off the 512-range cap."""
    pins = _nuget_pins("8.0", 31, skip=(9,)) + _nuget_pins("9.0", 20) + _nuget_pins("10.0", 12)
    impacted = [
        _entry("nuget", f"microsoft-aspnetcore-app-runtime-{rid}", pins + [">=11.0.0-preview.1 <11.0.0-rc.2"])
        for rid in ("linux-arm", "linux-arm64", "linux-musl-arm", "linux-musl-arm64", "linux-musl-x64",
                    "linux-x64", "osx-arm64", "osx-x64", "win-arm", "win-arm64", "win-x64", "win-x86",
                    "linux-bionic-arm64", "linux-bionic-x64")
    ]
    assert len(build_version_ranges(impacted_products=impacted)) < MAX_VERSION_RANGES
    last = "microsoft-aspnetcore-app-runtime-linux-bionic-x64"
    assert affected("nuget", last, "8.0.31", impacted=impacted)
    assert affected("nuget", last, "10.0.12", impacted=impacted)
    assert not affected("nuget", last, "8.0.9", impacted=impacted)  # gap in the list
    assert not affected("nuget", last, "8.0.32", impacted=impacted)
    assert not affected("nuget", last, "11.0.0", impacted=impacted)


def test_pre_release_bounds_are_indexed_for_final_versions():
    impacted = [_entry("microsoft", "net-source-build", [">= 8.0.100, < 10.0.403-servicing.26523.112"])]
    assert affected("microsoft", "net-source-build", "9.0.0", impacted=impacted)
    assert affected("microsoft", "net-source-build", "10.0.402", impacted=impacted)
    assert not affected("microsoft", "net-source-build", "10.0.403", impacted=impacted)
    preview = [_entry("microsoft", "net", [">= 11.0.0-preview.1, <= 11.0.0-rc.1"])]
    assert not affected("microsoft", "net", "11.0.0", impacted=preview)
    assert not affected("microsoft", "net", "10.0.9", impacted=preview)


def test_pre_release_pin_does_not_mark_the_final_release():
    """CVE-2022-30187 (azure-storage-blob): "12.4.0b1" used to encode as 12.4.0."""
    impacted = [_entry("pip", "azure-storage-blob", ["12.3.0", "12.4.0b1", "1.2.0rc1"])]
    assert not affected("pip", "azure-storage-blob", "12.4.0", impacted=impacted)
    assert not affected("pip", "azure-storage-blob", "1.2.0", impacted=impacted)
    assert affected("pip", "azure-storage-blob", "12.3.0", impacted=impacted)


def test_pin_runs_only_fold_where_no_deeper_version_exists():
    assert coalesce_pins(["17.0", "17.1"]) == (["17.0", "17.1"], [])
    singles, spans = coalesce_pins(["2.4.10", "2.4.11", "2.4.11.1"])
    assert spans == [] and sorted(singles) == ["2.4.10", "2.4.11", "2.4.11.1"]
    assert not version_in_ranges("17.0.1", ["17.0", "17.1"])
    singles, spans = coalesce_pins(["8.0.0", "8.0.1", "8.0.2", "8.0.4"])
    assert singles == ["8.0.4"] and len(spans) == 1


# --- 4. Formerly known limits -----------------------------------------------


_ORDERED = [
    "0", "0.0.1", "1.0.1", "1.0.1a", "1.0.1m", "1.0.2-beta1", "1.0.2", "1.0.2k", "1.0.2z", "1.0.2za",
    "4.26.9", "4.26.9m", "7.4", "7.4.0.1", "8", "8.0.1", "9", "10", "10.0.19044.0", "10.0.19045",
    "10.0.19045.7807", "11.0.0-preview.1", "11.0.0-rc.2", "11.0.0", "12.4.0b1", "12.4.0rc1", "12.4.0",
    "100", "2026.10.18",
]


def test_sort_keys_order_like_the_matcher():
    """The index compares keyword keys; their byte order must be the matcher's
    order, including segments above 9999 and pre/post-release suffixes."""
    keys = [version_sort_key(v) for v in _ORDERED]
    assert all(keys), dict(zip(_ORDERED, keys))
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)
    assert version_sort_key("8.0") == version_sort_key("8.0.0") == version_sort_key("v8")
    assert version_sort_key("1.2.3+build") is None  # compared by string only


def test_windows_builds_above_9999_are_told_apart():
    """CVE-2026-97788: the old encoder capped 19044 and 19045 at 9999."""
    impacted = [_entry("microsoft", "windows-10-version-22h2", [">= 10.0.19045.0, < 10.0.19045.7807"])]
    assert affected("microsoft", "windows-10-version-22h2", "10.0.19045.7806", impacted=impacted)
    assert not affected("microsoft", "windows-10-version-22h2", "10.0.19045.7807", impacted=impacted)
    assert not affected("microsoft", "windows-10-version-22h2", "10.0.19044.5000", impacted=impacted)


def test_openssl_letter_releases():
    """CVE-2015-4000: 1.0.1m and 1.0.2a are releases after 1.0.1 / 1.0.2."""
    impacted = [_entry("openssl", "openssl", [">= 1.0.1, <= 1.0.1m", ">= 1.0.2, <= 1.0.2a"])]
    for version, expected in [("1.0.1", True), ("1.0.1l", True), ("1.0.1m", True), ("1.0.1n", False),
                              ("1.0.2", True), ("1.0.2a", True), ("1.0.2b", False)]:
        assert affected("openssl", "openssl", version, impacted=impacted) is expected, version


def test_arista_train_suffix():
    impacted = [_entry("arista", "eos", [">= 4.26.0, < 4.26.9m", ">= 4.27.0, < 4.27.8m"])]
    assert affected("arista", "eos", "4.26.8m", impacted=impacted)
    assert not affected("arista", "eos", "4.26.9m", impacted=impacted)
    assert affected("arista", "eos", "4.27.1", impacted=impacted)


def test_pre_release_versions_are_searchable():
    impacted = [_entry("microsoft", "net", [">=11.0.0-preview.1 <11.0.0-rc.2"])]
    assert affected("microsoft", "net", "11.0.0-rc.1", impacted=impacted)
    assert not affected("microsoft", "net", "11.0.0-rc.2", impacted=impacted)
    assert not affected("microsoft", "net", "11.0.0", impacted=impacted)


@pytest.mark.parametrize(
    "version, expected",
    [("20.19.0", False), ("20.18.1", True), ("20.10.0", True), ("21.5.0", True),
     ("22.12.1", False), ("22.13.0", False), ("22.11.0", True)],
)
def test_one_line_per_major(version, expected):
    """Node-style: every upper bound on a different major, so the branch is the
    major. With two segments, 20.19.0 (above the 20.x fix) fell into "< 22.12.1"."""
    impacted = [_entry("nodejs", "node-js", ["< 20.18.2", "< 22.12.1"])]
    assert affected("nodejs", "node-js", version, impacted=impacted) is expected


def test_branch_start_bounds_do_not_switch_to_majors():
    """"< 3.0" ends at a branch start and does not count towards the decision."""
    impacted = [_entry("acme", "lib", ["< 3.0", ">= 2.7.0, < 2.7.5"])]
    assert affected("acme", "lib", "2.6.0", impacted=impacted)
    assert affected("acme", "lib", "2.7.4", impacted=impacted)


def test_curated_tier_wins_over_a_cpe_pin_of_the_fixed_build():
    """CVE-2026-50355: the CPE data names the fixed build 10.0.17763.9020 as a
    concrete version. The index used to union all tiers and flagged it."""
    impacted = [_entry("microsoft", "windows-server-2019", [">= 10.0.17763.0, < 10.0.17763.9020"])]
    configs = _configs(_match("cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.9020:*:*:*:*:*:*:*"))
    assert not affected("microsoft", "windows-server-2019", "10.0.17763.9020", impacted=impacted, configs=configs)
    assert affected("microsoft", "windows-server-2019", "10.0.17763.9019", impacted=impacted, configs=configs)


def test_tier_without_version_evidence_hands_over():
    """An impactedProducts entry with ``[]`` or only "*" says nothing about
    versions; the CPE ranges decide instead of an automatic "no"."""
    configs = _configs(_match("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", versionEndExcluding="2.0"))
    for versions in ([], ["*"], ["n/a"]):
        impacted = [_entry("acme", "widget", versions)]
        assert affected("acme", "widget", "1.5", impacted=impacted, configs=configs), versions
        assert not affected("acme", "widget", "2.0", impacted=impacted, configs=configs), versions


def test_bare_open_start_written_by_the_old_aggregation_is_an_open_range():
    """NVD "from 5.1 upwards" used to be stored in impactedProducts as "5.1"."""
    impacted = [_entry("acme", "server", ["5.1"])]
    configs = _configs(_match("cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", versionStartIncluding="5.1"))
    assert affected("acme", "server", "7.0", impacted=impacted, configs=configs)
    assert not affected("acme", "server", "5.0", impacted=impacted, configs=configs)
    # Without that CPE match a bare "5.1" stays the exact version.
    assert not affected("acme", "server", "7.0", impacted=impacted)


def test_nvd_aggregation_keeps_the_operator_of_an_open_start():
    configs = [{"nodes": [{"operator": "OR", "matches": [
        {"criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", "part": "a", "vendor": "acme",
         "product": "server", "vulnerable": True, "versionStartIncluding": "5.1"},
    ]}]}]
    (entry,) = _build_impacted_products_payload(cpe_configurations=configs, cpematch_entries=None, cpes=[])
    assert entry["versions"] == [">= 5.1"]
