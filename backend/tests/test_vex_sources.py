"""VEX sources on a scan target: URL rules, parsing, applying, and the fetch guard."""
from __future__ import annotations

import json
from functools import partial
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.services import vex_source_service as vs
from app.services.vex_source_service import (
    VexSourceError,
    VexSourceService,
    VexStatement,
    normalize_vex_source_urls,
    package_names_from_purl,
    parse_vex_document,
)

VEX_DIR = Path(__file__).resolve().parents[2] / "vex"


# ---------------------------------------------------------------- URLs


def test_urls_are_trimmed_deduplicated_and_github_blobs_become_raw() -> None:
    urls = normalize_vex_source_urls([
        " https://github.com/0x3e4/hecate/blob/main/vex/hecate-backend.openvex.json ",
        "https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-backend.openvex.json",
        "",
    ])
    assert urls == ["https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-backend.openvex.json"]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/vex.json",
        "file:///etc/passwd",
        "https://user:token@example.com/vex.json",
        "https:///vex.json",
        "https://example.com/" + "a" * 3000,
    ],
)
def test_unusable_urls_are_refused(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_vex_source_urls([url])


def test_at_most_five_sources() -> None:
    with pytest.raises(ValueError):
        normalize_vex_source_urls([f"https://example.com/{i}.json" for i in range(6)])


@pytest.mark.parametrize("value", ["https://example.com/a.json", [1], None])
def test_sources_must_be_a_list_of_strings(value: Any) -> None:
    with pytest.raises(ValueError):
        normalize_vex_source_urls(value)


# ---------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("purl", "names"),
    [
        ("pkg:deb/debian/libc6@2.41-12+deb13u4?arch=amd64", ["libc6", "debian/libc6", "debian:libc6"]),
        ("pkg:golang/golang.org/x/net@v0.60.0", ["net", "golang.org/x/net", "golang.org/x:net"]),
        ("pkg:npm/%40scope/pkg@1.0.0", ["pkg", "@scope/pkg", "@scope:pkg"]),
        ("pkg:generic/python@3.14.10", ["python"]),
        ("not-a-purl", []),
    ],
)
def test_package_names_from_purl(purl: str, names: list[str]) -> None:
    assert package_names_from_purl(purl) == names


def test_reads_hecates_own_openvex() -> None:
    document = json.loads((VEX_DIR / "hecate-scanner.openvex.json").read_text(encoding="utf-8"))
    fmt, statements = parse_vex_document(document)
    assert fmt == "openvex"
    assert len(statements) == len(document["statements"])
    curl = [s for s in statements if "CVE-2026-92388" in s.ids]
    assert curl and curl[0].status == "not_affected"
    assert "libcurl3t64-gnutls" in curl[0].packages
    assert curl[0].justification == "vulnerable_code_not_in_execute_path"
    assert "GIT_ALLOW_PROTOCOL" in (curl[0].detail or "")


def test_reads_hecates_own_cyclonedx() -> None:
    document = json.loads((VEX_DIR / "hecate-source.cdx.json").read_text(encoding="utf-8"))
    fmt, statements = parse_vex_document(document)
    assert fmt == "cyclonedx"
    katex = next(s for s in statements if "GHSA-238P-PMPM-9MQ7" in s.ids)
    assert katex.status == "not_affected"
    assert "katex" in katex.packages


def test_cyclonedx_exploitable_is_affected_and_references_are_aliases() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{
            "id": "CVE-2026-1",
            "references": [{"id": "GHSA-aaaa-bbbb-cccc"}],
            "analysis": {"state": "exploitable", "detail": "reachable"},
            "affects": [{"ref": "comp-1"}],
        }],
        "components": [{"bom-ref": "comp-1", "name": "lodash", "purl": "pkg:npm/lodash@4.17.20"}],
    }
    _, (statement,) = parse_vex_document(document)
    assert statement.status == "affected"
    assert "GHSA-AAAA-BBBB-CCCC" in statement.ids
    assert "lodash" in statement.packages


def test_statements_with_unknown_states_are_left_out() -> None:
    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [
            {"vulnerability": {"name": "CVE-2026-1"}, "status": "maybe"},
            {"vulnerability": {"name": {"$ne": 1}}, "status": "not_affected"},
            {"vulnerability": "CVE-2026-2", "status": "fixed"},
        ],
    }
    _, statements = parse_vex_document(document)
    assert [s.ids[0] for s in statements] == ["CVE-2026-2"]


@pytest.mark.parametrize("document", [{}, {"bomFormat": "SPDX"}, {"statements": []}])
def test_other_documents_are_refused(document: dict[str, Any]) -> None:
    with pytest.raises(VexSourceError) as exc:
        parse_vex_document(document)
    assert exc.value.kind == "unknown_format"


# ---------------------------------------------------------------- applying


class FakeFindings:
    def __init__(self) -> None:
        self.applied: list[dict[str, Any]] = []
        self.cleared: list[list[str]] = []

    async def apply_vex_from_source(self, target_id: str, ids: list[str], status: str, **kwargs: Any) -> int:
        self.applied.append({"ids": ids, "status": status, **kwargs})
        return 1

    async def clear_vex_source_statuses(self, target_id: str, keep_ids: list[str]) -> int:
        self.cleared.append(keep_ids)
        return 0


class FakeTargets:
    def __init__(self, urls: list[str]) -> None:
        self.urls = urls
        self.status: dict[str, Any] | None = None

    async def get(self, target_id: str) -> dict[str, Any]:
        return {"_id": target_id, "vex_sources": self.urls}

    async def set_vex_source_status(self, target_id: str, status: dict[str, Any]) -> None:
        self.status = status


async def test_one_status_per_vulnerability_covers_every_package() -> None:
    findings = FakeFindings()
    service = VexSourceService(FakeTargets([]), findings)  # type: ignore[arg-type]
    statements = [VexStatement(ids=["CVE-1"], status="not_affected", packages=["libc6"])]

    applied, skipped = await service.apply_statements("t", statements)

    assert (applied, skipped) == (1, 0)
    assert findings.applied[0]["package_names"] is None


async def test_conflicting_statuses_are_applied_per_package() -> None:
    findings = FakeFindings()
    service = VexSourceService(FakeTargets([]), findings)  # type: ignore[arg-type]
    statements = [
        VexStatement(ids=["CVE-1"], status="not_affected", packages=["skopeo"]),
        VexStatement(ids=["CVE-1"], status="affected", packages=["grype"]),
        VexStatement(ids=["CVE-1"], status="under_investigation"),  # names no package
    ]

    applied, skipped = await service.apply_statements("t", statements)

    assert (applied, skipped) == (2, 1)
    assert [a["package_names"] for a in findings.applied] == [["skopeo"], ["grype"]]


async def test_a_failed_source_keeps_existing_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fetch(url: str) -> dict[str, Any]:
        if "broken" in url:
            raise VexSourceError("http_status", "The server answered HTTP 404.")
        return {"@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed"}]}

    monkeypatch.setattr(vs, "fetch_vex_document", fetch)
    findings = FakeFindings()
    targets = FakeTargets(["https://a.example/ok.json", "https://a.example/broken.json"])
    status = await VexSourceService(targets, findings).apply_target_sources("t")  # type: ignore[arg-type]

    assert findings.cleared == []
    assert status is not None and status["applied"] == 1
    assert [s["ok"] for s in status["sources"]] == [True, False]
    assert status["sources"][1]["error_kind"] == "http_status"
    assert targets.status == status


async def test_statuses_no_source_mentions_are_cleared(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fetch(url: str) -> dict[str, Any]:
        return {"@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed"}]}

    monkeypatch.setattr(vs, "fetch_vex_document", fetch)
    findings = FakeFindings()
    await VexSourceService(FakeTargets(["https://a.example/ok.json"]), findings).apply_target_sources("t")  # type: ignore[arg-type]

    assert findings.cleared == [["CVE-1"]]


async def test_a_target_without_sources_does_nothing() -> None:
    findings = FakeFindings()
    assert await VexSourceService(FakeTargets([]), findings).apply_target_sources("t") is None  # type: ignore[arg-type]
    assert findings.applied == [] and findings.cleared == []


# ---------------------------------------------------------------- fetching


def _client_with(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    async def public(url: str) -> bool:
        return True

    monkeypatch.setattr(vs, "is_public_url", public)
    monkeypatch.setattr(vs.httpx, "AsyncClient", partial(httpx.AsyncClient, transport=httpx.MockTransport(handler)))


async def test_private_hosts_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    async def private(url: str) -> bool:
        return False

    monkeypatch.setattr(vs, "is_public_url", private)
    with pytest.raises(VexSourceError) as exc:
        await vs.fetch_vex_document("https://intranet.example/vex.json")
    assert exc.value.kind == "not_public"


async def test_a_document_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _client_with(monkeypatch, lambda request: httpx.Response(200, json={"bomFormat": "CycloneDX"}))
    assert await vs.fetch_vex_document("https://example.com/vex.json") == {"bomFormat": "CycloneDX"}


async def test_redirects_are_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    _client_with(monkeypatch, lambda request: httpx.Response(302, headers={"Location": "http://169.254.169.254/"}))
    with pytest.raises(VexSourceError) as exc:
        await vs.fetch_vex_document("https://example.com/vex.json")
    assert exc.value.kind == "http_status"


async def test_large_documents_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vs.settings, "sca_vex_source_max_bytes", 100)
    _client_with(monkeypatch, lambda request: httpx.Response(200, content=b"{" + b" " * 200 + b"}"))
    with pytest.raises(VexSourceError) as exc:
        await vs.fetch_vex_document("https://example.com/vex.json")
    assert exc.value.kind == "too_large"


async def test_html_is_not_a_vex_document(monkeypatch: pytest.MonkeyPatch) -> None:
    _client_with(monkeypatch, lambda request: httpx.Response(200, text="<html></html>"))
    with pytest.raises(VexSourceError) as exc:
        await vs.fetch_vex_document("https://example.com/vex.json")
    assert exc.value.kind == "invalid_json"
