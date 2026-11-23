"""DQL search: free terms over a fixed field list, refused queries reported,
product-line slugs searchable.

On the demo instance ``"Dynamics 365"`` found 146 entries and ``Microsoft``
21,098, but ``"Dynamics 365" "Microsoft"`` (and even ``dynamics microsoft``)
found none: ``default_field: "*"`` expanded both terms to every field of the
index, OpenSearch refused the query over max_clause_count, and async_search
turned the refusal into an empty page.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import vulnerabilities as vuln_api
from app.db import opensearch
from app.models.vulnerability import VulnerabilityDocument
from app.schemas.vulnerability import VulnerabilityQuery
from app.services import vulnerability_service as vs
from app.services.vulnerability_service import DQL_DEFAULT_FIELDS, DqlQueryError, VulnerabilityService


def _query_string(dql: str) -> dict[str, Any]:
    service = VulnerabilityService.__new__(VulnerabilityService)
    body = service._build_query(VulnerabilityQuery(dqlQuery=dql))
    clauses = [c["query_string"] for c in body["query"]["bool"]["must"] if "query_string" in c]
    assert len(clauses) == 1
    return clauses[0]


def test_free_terms_search_a_fixed_field_list() -> None:
    clause = _query_string('"Dynamics 365" "Microsoft"')
    assert clause["query"] == '"Dynamics 365" "Microsoft"'
    assert clause["fields"] == list(DQL_DEFAULT_FIELDS)
    assert "default_field" not in clause
    assert clause["lenient"] is True
    assert clause["default_operator"] == "AND"


def test_two_terms_stay_far_below_the_clause_limit() -> None:
    # Each free term becomes one clause per field.
    assert 2 * len(DQL_DEFAULT_FIELDS) < 100


def test_every_default_field_is_in_the_index_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, Any] = {}

    class _Indices:
        def exists(self, index: str) -> bool:
            return False

        def create(self, index: str, body: dict[str, Any]) -> None:
            created.update(body)

    class _Client:
        indices = _Indices()

    monkeypatch.setattr(opensearch, "get_client", lambda: _Client())
    monkeypatch.setattr(opensearch, "refresh_exact_field_paths", lambda *_a, **_k: None, raising=False)
    opensearch.ensure_vulnerability_index("dql-test")
    properties = created["mappings"]["properties"]

    def has(path: str) -> bool:
        node: Any = {"properties": properties}
        for part in path.split("."):
            node = (node.get("properties") or {}).get(part)
            if node is None:
                return False
        return True

    missing = [field for field in DQL_DEFAULT_FIELDS if not has(field)]
    assert missing == []


# --------------------------------------------------------------------------
# A refused query is an error, not "0 entries"
# --------------------------------------------------------------------------

class _RequestError(opensearch.RequestError):
    def __init__(self, info: dict[str, Any]) -> None:
        self._info = info

    @property
    def info(self) -> dict[str, Any]:  # type: ignore[override]
        return self._info

    @property
    def error(self) -> str:  # type: ignore[override]
        return "search_phase_execution_exception"

    def __str__(self) -> str:
        return "RequestError(400, 'search_phase_execution_exception')"


TOO_MANY = {
    "error": {
        "root_cause": [{"type": "too_many_clauses", "reason": "maxClauseCount is set to 1024"}],
        "type": "search_phase_execution_exception",
        "reason": "all shards failed",
    }
}


def test_request_error_reason_takes_the_root_cause() -> None:
    assert opensearch._request_error_reason(_RequestError(TOO_MANY)) == "maxClauseCount is set to 1024"
    failed = {"error": {"root_cause": [], "reason": "all shards failed", "caused_by": {"reason": "Cannot parse 'a AND'"}}}
    assert opensearch._request_error_reason(_RequestError(failed)) == "Cannot parse 'a AND'"


@pytest.fixture
def refusing_search(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    flags: list[bool] = []

    async def search(_index: str, _body: dict[str, Any], *, raise_request_errors: bool = False, **_kw: Any) -> dict[str, Any]:
        flags.append(raise_request_errors)
        if raise_request_errors:
            raise opensearch.SearchRequestRejected("maxClauseCount is set to 1024")
        return {"hits": {"hits": [], "total": {"value": 0}}}

    async def no_catalog(**_kwargs: Any) -> tuple[list[str], list[str], list[str]]:
        return [], [], []

    monkeypatch.setattr(vs, "async_search", search)
    monkeypatch.setattr(vs, "_resolve_catalog_filters", no_catalog)
    return flags


async def test_a_refused_dql_query_raises(refusing_search: list[bool]) -> None:
    service = VulnerabilityService.__new__(VulnerabilityService)
    with pytest.raises(DqlQueryError, match="maxClauseCount"):
        await service.search_paginated(VulnerabilityQuery(dqlQuery="a b"), limit=10, offset=0)
    assert refusing_search == [True]


async def test_a_keyword_search_keeps_the_quiet_path(refusing_search: list[bool]) -> None:
    service = VulnerabilityService.__new__(VulnerabilityService)
    result = await service.search_paginated(VulnerabilityQuery(searchTerm="dynamics"), limit=10, offset=0)
    assert result.total == 0 and refusing_search == [False]


def test_the_list_route_answers_400_with_the_reason() -> None:
    class _Service:
        async def search_paginated(self, *_a: Any, **_k: Any) -> Any:
            raise DqlQueryError("The search query was rejected: Cannot parse 'a AND'")

    app = FastAPI()
    app.include_router(vuln_api.router, prefix="/vulnerabilities")
    app.dependency_overrides[vuln_api.get_vulnerability_service] = lambda: _Service()
    response = TestClient(app).get("/vulnerabilities", params={"dqlQuery": "a AND"})
    assert response.status_code == 400
    assert "Cannot parse" in response.json()["detail"]


# --------------------------------------------------------------------------
# Product-line slugs in productSlugs
# --------------------------------------------------------------------------

def _document(**fields: Any) -> VulnerabilityDocument:
    base = {"vuln_id": "CVE-2023-24896", "title": "t", "summary": "s", "ingested_at": datetime.now(tz=UTC)}
    return VulnerabilityDocument(**{**base, **fields})


def test_a_product_line_slug_joins_product_slugs() -> None:
    doc = _document(
        vendor_slugs=["microsoft"],
        product_slugs=["dynamics-365"],
        impacted_products=[{
            "vendor": {"name": "microsoft", "slug": "microsoft"},
            "product": {"name": "dynamics 365", "slug": "dynamics-365"},
            "versions": ["< 10.0.32"],
            "vulnerable": True,
            "environments": ["finance and operations"],
        }],
    )
    slugs = doc.opensearch_document()["productSlugs"]
    assert slugs[0] == "dynamics-365"
    assert "dynamics-365-for-finance-and-operations" in slugs
    assert "dynamics-365-finance-and-operations" in slugs


def test_other_products_keep_their_slugs() -> None:
    doc = _document(
        vendor_slugs=["nginx"],
        product_slugs=["nginx"],
        impacted_products=[{
            "vendor": {"name": "nginx", "slug": "nginx"},
            "product": {"name": "nginx", "slug": "nginx"},
            "versions": ["< 1.31.9"],
            "vulnerable": True,
        }],
    )
    assert doc.opensearch_document()["productSlugs"] == ["nginx"]


# --------------------------------------------------------------------------
# Case-insensitive vendors / products / aliases (.text sub-field)
# --------------------------------------------------------------------------

KEYWORD = {"type": "keyword"}
WITH_TEXT = {"type": "keyword", "fields": {"text": {"type": "text"}}}


class _MappingClient:
    """An index whose live mapping the test sets; records put_mapping calls."""

    def __init__(self, properties: dict[str, Any], refuse: set[str] | None = None) -> None:
        self.properties = properties
        self.refuse = refuse or set()
        self.puts: list[dict[str, Any]] = []
        client = self

        class _Indices:
            def get_mapping(self, index: str) -> dict[str, Any]:
                return {index: {"mappings": {"properties": client.properties}}}

            def put_mapping(self, index: str, body: dict[str, Any]) -> None:
                (field, definition), = body["properties"].items()
                if field in client.refuse:
                    raise opensearch.RequestError(400, "illegal_argument_exception", {})
                client.puts.append(body)
                client.properties[field] = definition

        self.indices = _Indices()


@pytest.fixture
def live_index(monkeypatch: pytest.MonkeyPatch):
    def make(properties: dict[str, Any], refuse: set[str] | None = None) -> _MappingClient:
        client = _MappingClient(properties, refuse)
        monkeypatch.setattr(opensearch, "get_client", lambda: client)
        monkeypatch.setattr(opensearch.settings, "opensearch_index", "vulns")
        return client

    yield make
    opensearch._case_insensitive_paths.pop("vulns", None)
    opensearch._exact_field_paths.pop("vulns", None)


def test_subfields_are_added_to_an_existing_index(live_index) -> None:
    client = live_index({
        "vendors": {"type": "keyword", "ignore_above": 256},
        "products": WITH_TEXT,
        "aliases": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
    })
    opensearch._ensure_case_insensitive_subfields(client, "vulns")
    # vendors gains .text and keeps its own parameters; products already has
    # it; aliases is text-mapped and left alone.
    assert client.puts == [{"properties": {"vendors": {
        "type": "keyword", "ignore_above": 256, "fields": {"text": {"type": "text"}},
    }}}]


def test_a_refused_field_does_not_stop_the_others(live_index) -> None:
    client = live_index({"vendors": KEYWORD, "products": KEYWORD, "aliases": KEYWORD}, refuse={"vendors"})
    opensearch._ensure_case_insensitive_subfields(client, "vulns")
    assert [next(iter(p["properties"])) for p in client.puts] == ["products", "aliases"]


def test_case_insensitive_paths_follow_the_live_mapping(live_index) -> None:
    live_index({"vendors": WITH_TEXT, "products": KEYWORD, "aliases": {"type": "text"}})
    opensearch.refresh_exact_field_paths("vulns")
    assert opensearch.case_insensitive_field_path("vendors") == "vendors.text"
    assert opensearch.case_insensitive_field_path("products") is None
    assert opensearch.case_insensitive_field_path("aliases") == "aliases"


def test_a_new_index_declares_the_subfields(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, Any] = {}

    class _Indices:
        def exists(self, index: str) -> bool:
            return False

        def create(self, index: str, body: dict[str, Any]) -> None:
            created.update(body)

    class _Client:
        indices = _Indices()

    monkeypatch.setattr(opensearch, "get_client", lambda: _Client())
    monkeypatch.setattr(opensearch, "refresh_exact_field_paths", lambda *_a, **_k: None)
    opensearch.ensure_vulnerability_index("dql-test-2")
    properties = created["mappings"]["properties"]
    for field in opensearch.CASE_INSENSITIVE_FIELDS:
        assert properties[field] == WITH_TEXT


@pytest.mark.parametrize(
    ("dql", "expected"),
    [
        ('vendors:Microsoft', '(vendors:Microsoft OR vendors.text:Microsoft)'),
        ('products:"Dynamics 365"', '(products:"Dynamics 365" OR products.text:"Dynamics 365")'),
        ('(vendors:microsoft)', '((vendors:microsoft OR vendors.text:microsoft))'),
        ('vendors:(Microsoft OR Wazuh)', '(vendors:(Microsoft OR Wazuh) OR vendors.text:(Microsoft OR Wazuh))'),
        ('NOT vendors:micro*', 'NOT (vendors:micro* OR vendors.text:micro*)'),
        ('vendors.text:x AND myvendors:y', 'vendors.text:x AND myvendors:y'),
        ('aliases:ghsa-26vj-jqr4-v7fv', '(aliases:ghsa-26vj-jqr4-v7fv OR aliases.text:ghsa-26vj-jqr4-v7fv)'),
    ],
)
def test_display_field_clauses_also_ask_the_case_insensitive_path(live_index, dql: str, expected: str) -> None:
    live_index({"vendors": WITH_TEXT, "products": WITH_TEXT, "aliases": WITH_TEXT})
    opensearch.refresh_exact_field_paths("vulns")
    assert vs._translate_dql_fields(dql) == expected


def test_without_the_subfield_clauses_stay_as_written(live_index) -> None:
    live_index({"vendors": KEYWORD, "products": KEYWORD, "aliases": KEYWORD})
    opensearch.refresh_exact_field_paths("vulns")
    assert vs._translate_dql_fields('vendors:Microsoft AND products:"Dynamics 365"') == (
        'vendors:Microsoft AND products:"Dynamics 365"'
    )
    assert _query_string("dynamics microsoft")["fields"] == list(DQL_DEFAULT_FIELDS)


def test_free_terms_also_search_the_case_insensitive_paths(live_index) -> None:
    live_index({"vendors": WITH_TEXT, "products": WITH_TEXT, "aliases": WITH_TEXT})
    opensearch.refresh_exact_field_paths("vulns")
    fields = _query_string('"Dynamics 365" Microsoft')["fields"]
    assert fields[: len(DQL_DEFAULT_FIELDS)] == list(DQL_DEFAULT_FIELDS)
    assert {"vendors.text", "products.text", "aliases.text"} <= set(fields)
