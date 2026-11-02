"""The public search bounds what one anonymous request can make OpenSearch do.

Every list filter turned into leading-wildcard clauses without a cap, and the
search body set no timeout, so the cluster kept working after the client gave up.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1 import vulnerabilities
from app.schemas.vulnerability import MAX_QUERY_LIST_ITEM_LENGTH, MAX_QUERY_LIST_ITEMS, VulnerabilityQuery
from app.services import stats_service
from app.services.stats_service import StatsService
from app.services.vulnerability_service import SEARCH_TIMEOUT, VulnerabilityService, get_vulnerability_service


class FakeService:
    def __init__(self) -> None:
        self.queries: list[VulnerabilityQuery] = []

    async def search_paginated(self, query: VulnerabilityQuery, *, limit: int, offset: int) -> Any:
        self.queries.append(query)
        return vulnerabilities.PagedVulnerabilityResponse(items=[], total=0, limit=limit, offset=offset)


@pytest.fixture
def client_and_service() -> tuple[TestClient, FakeService]:
    service = FakeService()
    app = FastAPI()
    app.include_router(vulnerabilities.router, prefix="/vulnerabilities")
    app.dependency_overrides[get_vulnerability_service] = lambda: service
    return TestClient(app), service


@pytest.mark.parametrize("field", ["vendorFilters", "productFilters", "versionFilters", "cwes", "sources"])
def test_too_many_values_in_a_list_filter_are_refused(field: str) -> None:
    with pytest.raises(ValidationError):
        VulnerabilityQuery(**{field: [f"v{n}" for n in range(MAX_QUERY_LIST_ITEMS + 1)]})


def test_an_oversized_list_value_is_refused() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityQuery(vendorFilters=["x" * (MAX_QUERY_LIST_ITEM_LENGTH + 1)])


def test_the_limit_still_allows_a_normal_query() -> None:
    query = VulnerabilityQuery(vendorFilters=[f"v{n}" for n in range(MAX_QUERY_LIST_ITEMS)])

    assert len(query.vendor_filters) == MAX_QUERY_LIST_ITEMS


def test_the_get_route_answers_422_not_500(client_and_service: tuple[TestClient, FakeService]) -> None:
    client, service = client_and_service
    params = [("vendorFilters", f"v{n}") for n in range(MAX_QUERY_LIST_ITEMS + 1)]

    response = client.get("/vulnerabilities", params=params)

    assert response.status_code == 422
    assert service.queries == []


def test_the_get_route_still_searches(client_and_service: tuple[TestClient, FakeService]) -> None:
    client, service = client_and_service

    assert client.get("/vulnerabilities", params=[("vendorFilters", "acme")]).status_code == 200
    assert service.queries[0].vendor_filters == ["acme"]


def test_the_post_route_refuses_a_flood_of_filters(client_and_service: tuple[TestClient, FakeService]) -> None:
    client, _ = client_and_service
    body = {"vendorFilters": [f"v{n}" for n in range(1000)]}

    assert client.post("/vulnerabilities/search", json=body).status_code == 422


def test_the_search_body_carries_a_server_side_timeout() -> None:
    body = VulnerabilityService()._build_query(VulnerabilityQuery(dqlQuery="summary:*e*"))

    assert body["timeout"] == SEARCH_TIMEOUT


async def test_the_stats_overview_is_computed_once_a_minute(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    async def compute(self: StatsService) -> dict[str, Any]:
        calls.append(1)
        return {"n": len(calls)}

    monkeypatch.setattr(StatsService, "_compute_overview", compute)
    monkeypatch.setattr(stats_service, "_OVERVIEW_CACHE", {})

    first = await StatsService().get_overview()
    second = await StatsService().get_overview()

    assert first == second == {"n": 1}
    assert len(calls) == 1
