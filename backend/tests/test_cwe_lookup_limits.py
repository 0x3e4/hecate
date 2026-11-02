"""The public CWE lookups cannot keep the shared MITRE client busy.

Misses were not remembered, so each unknown ID in a 500-ID bulk request went
upstream one by one through a limiter of one request a second.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.services import cwe_service as module
from app.services.cwe_service import CWEService


class FakeClient:
    def __init__(self, known: set[str] = frozenset()) -> None:
        self.known = known
        self.asked: list[str] = []

    async def fetch_weakness(self, cwe_id: str) -> dict[str, Any] | None:
        self.asked.append(cwe_id)
        return {"ID": cwe_id, "Name": f"Weakness {cwe_id}"} if cwe_id in self.known else None


class FakeRepository:
    async def get_by_id(self, _cwe_id: str) -> None:
        return None

    async def upsert_entry(self, _entry: Any) -> None:
        return None


def service(client: FakeClient) -> CWEService:
    return CWEService(client=client, repository=FakeRepository())


async def test_a_bulk_request_sends_a_bounded_number_of_ids_upstream() -> None:
    client = FakeClient()

    await service(client).get_bulk_cwe_data([str(n) for n in range(5000, 5500)])

    assert len(client.asked) == module.MAX_UPSTREAM_PER_CALL


async def test_an_unknown_id_is_not_asked_again() -> None:
    client = FakeClient()
    cwe = service(client)

    assert await cwe._get_cwe_data("99999") is None
    assert await cwe._get_cwe_data("CWE-99999") is None

    assert client.asked == ["99999"]


@pytest.mark.parametrize("value", ["../../admin", "79?x=1", "abc", "", "123456"])
async def test_an_id_that_is_not_a_number_never_goes_upstream(value: str) -> None:
    client = FakeClient()

    assert await service(client)._get_cwe_data(value) is None
    assert client.asked == []


async def test_known_ids_still_resolve_and_duplicates_cost_one_request() -> None:
    client = FakeClient(known={"79", "89"})

    result = await service(client).get_bulk_cwe_data(["79", "CWE-79", "89"])

    assert set(result) == {"79", "89"}
    assert client.asked == ["79", "89"]
