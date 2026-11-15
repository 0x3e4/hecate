"""Publication timeline: /stats/timeline picks the bucket size, aligns the window
in the caller's zone and keeps cumulative charts absolute through ``totalBefore``."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opensearchpy.exceptions import ConnectionError as OSConnectionError

from app.api.v1 import stats as stats_api
from app.services import stats_service
from app.services.stats_service import (
    StatsService,
    TimelineRangeError,
    choose_timeline_interval,
    coarsen_timeline_interval,
    ceil_to_interval,
    floor_to_interval,
    parse_timeline_bound,
    timeline_zone,
)

VIENNA = ZoneInfo("Europe/Vienna")


@pytest.fixture(autouse=True)
def _fresh_caches():
    stats_service._TIMELINE_CACHE.clear()
    stats_service._EARLIEST_PUBLISHED.clear()
    yield
    stats_service._TIMELINE_CACHE.clear()
    stats_service._EARLIEST_PUBLISHED.clear()


def _wire(monkeypatch, *, buckets=(), before=0, earliest_ms=None, error=None):
    bodies: list[dict] = []

    async def search(_index, body, **_kwargs):
        bodies.append(body)
        if error:
            raise error
        if "first" in body.get("aggs", {}):
            return {"aggregations": {"first": {"value": earliest_ms}}}
        return {
            "aggregations": {
                "before": {"doc_count": before},
                "window": {"doc_count": sum(b["doc_count"] for b in buckets), "buckets": {"buckets": list(buckets)}},
            }
        }

    monkeypatch.setattr(stats_service, "async_search", search)
    return bodies


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


# --- interval choice -----------------------------------------------------------------

def test_auto_interval_keeps_a_window_between_roughly_20_and_200_points():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert choose_timeline_interval(start, start + timedelta(days=30)) == "day"
    assert choose_timeline_interval(start, start + timedelta(days=120)) == "day"
    assert choose_timeline_interval(start, start + timedelta(days=121)) == "week"
    assert choose_timeline_interval(start, start + timedelta(days=365 * 3)) == "week"
    assert choose_timeline_interval(start, start + timedelta(days=1097)) == "month"
    assert choose_timeline_interval(start, start + timedelta(days=365 * 40)) == "month"


def test_an_explicit_interval_too_fine_for_the_range_is_coarsened():
    start = datetime(2000, 1, 1, tzinfo=UTC)
    assert coarsen_timeline_interval("day", start, start + timedelta(days=90)) == "day"
    # 10 years per day would be 3,650 points: weeks (~520) instead.
    assert coarsen_timeline_interval("day", start, start + timedelta(days=3650)) == "week"
    # 40 years per week would be ~2,080 points: months.
    assert coarsen_timeline_interval("week", start, start + timedelta(days=365 * 40)) == "month"
    assert coarsen_timeline_interval("month", start, start + timedelta(days=365 * 79)) == "month"


# --- alignment and parsing -----------------------------------------------------------

def test_buckets_align_to_local_midnight_monday_and_first_of_month():
    moment = datetime(2026, 11, 12, 23, 30, tzinfo=UTC)  # Fri 13 Nov, 00:30 in Vienna
    assert floor_to_interval(moment, "day", VIENNA) == datetime(2026, 11, 13, tzinfo=VIENNA)
    assert floor_to_interval(moment, "week", VIENNA) == datetime(2026, 11, 9, tzinfo=VIENNA)
    assert floor_to_interval(moment, "month", VIENNA) == datetime(2026, 11, 1, tzinfo=VIENNA)
    assert ceil_to_interval(moment, "day", VIENNA) == datetime(2026, 11, 14, tzinfo=VIENNA)
    assert ceil_to_interval(moment, "month", VIENNA) == datetime(2026, 12, 1, tzinfo=VIENNA)
    boundary = datetime(2026, 11, 1, tzinfo=VIENNA)
    assert ceil_to_interval(boundary, "month", VIENNA) == boundary


def test_a_bare_date_is_local_midnight_and_an_offset_is_kept():
    assert parse_timeline_bound("2026-03-29", VIENNA) == datetime(2026, 3, 29, tzinfo=VIENNA)
    assert parse_timeline_bound("2026-03-29T10:00:00Z", VIENNA) == datetime(2026, 3, 29, 10, tzinfo=UTC)
    assert parse_timeline_bound("2026-03-29T10:00:00", VIENNA) == datetime(2026, 3, 29, 10, tzinfo=VIENNA)
    with pytest.raises(TimelineRangeError):
        parse_timeline_bound("last tuesday", VIENNA)


def test_an_unknown_zone_falls_back_to_utc():
    assert timeline_zone("Mars/Olympus_Mons")[1] == "UTC"
    assert timeline_zone(None)[1] == "UTC"
    assert timeline_zone("Europe/Vienna")[1] == "Europe/Vienna"


# --- the service ---------------------------------------------------------------------

async def test_timeline_response_shape_and_query(monkeypatch):
    day1 = datetime(2026, 11, 1, tzinfo=VIENNA)
    buckets = [
        {"key": _ms(day1 + timedelta(days=i)), "key_as_string": f"2026-11-{i + 1:02d}", "doc_count": 10 + i}
        for i in range(3)
    ]
    bodies = _wire(monkeypatch, buckets=buckets, before=1234)
    result = await StatsService().get_timeline(
        from_="2026-11-01", to="2026-11-04", interval="auto", tz="Europe/Vienna"
    )

    assert result["interval"] == "day"
    assert result["tz"] == "Europe/Vienna"
    assert result["totalBefore"] == 1234
    assert result["total"] == 33
    assert result["from"] == "2026-11-01T00:00:00+01:00"
    assert result["to"] == "2026-11-04T00:00:00+01:00"
    assert result["points"][0] == {"key": "2026-11-01", "count": 10, "timestamp": _ms(day1)}

    aggs = bodies[0]["aggs"]
    histogram = aggs["window"]["aggs"]["buckets"]["date_histogram"]
    assert histogram["calendar_interval"] == "day"
    assert histogram["time_zone"] == "Europe/Vienna"
    assert histogram["min_doc_count"] == 0
    assert histogram["extended_bounds"] == {"min": _ms(day1), "max": _ms(datetime(2026, 11, 4, tzinfo=VIENNA)) - 1}
    assert aggs["before"]["filter"]["range"]["published"] == {"lt": _ms(day1)}
    assert aggs["window"]["filter"]["range"]["published"] == {
        "gte": _ms(day1),
        "lt": _ms(datetime(2026, 11, 4, tzinfo=VIENNA)),
    }


async def test_an_invalid_zone_buckets_in_utc(monkeypatch):
    bodies = _wire(monkeypatch)
    result = await StatsService().get_timeline(from_="2026-01-01", to="2026-02-01", tz="Not/AZone")
    assert result["tz"] == "UTC"
    assert bodies[0]["aggs"]["window"]["aggs"]["buckets"]["date_histogram"]["time_zone"] == "UTC"
    assert result["from"] == "2026-01-01T00:00:00+00:00"


async def test_a_wide_window_is_monthly_and_starts_on_the_first(monkeypatch):
    bodies = _wire(monkeypatch)
    result = await StatsService().get_timeline(from_="2016-05-17T08:00:00Z", to="2026-05-17T08:00:00Z", tz="UTC")
    assert result["interval"] == "month"
    assert result["from"] == "2016-05-01T00:00:00+00:00"
    assert result["to"] == "2026-06-01T00:00:00+00:00"
    assert bodies[0]["aggs"]["window"]["aggs"]["buckets"]["date_histogram"]["format"] == "yyyy-MM"


async def test_an_explicit_interval_is_honoured(monkeypatch):
    _wire(monkeypatch)
    result = await StatsService().get_timeline(from_="2026-01-01", to="2026-03-01", interval="week", tz="UTC")
    assert result["interval"] == "week"
    assert result["from"] == "2025-12-29T00:00:00+00:00"  # the Monday on or before


async def test_without_from_the_window_starts_at_the_earliest_publication(monkeypatch):
    bodies = _wire(monkeypatch, earliest_ms=_ms(datetime(1999, 3, 10, 12, tzinfo=UTC)))
    result = await StatsService().get_timeline(to="2026-11-14", tz="UTC")
    assert result["interval"] == "month"
    assert result["from"] == "1999-03-01T00:00:00+00:00"
    assert "first" in bodies[0]["aggs"]


@pytest.mark.parametrize(
    ("from_", "to"),
    [
        ("2026-02-01", "2026-01-01"),  # inverted
        ("2026-01-01", "2026-01-01"),  # empty
        ("1960-01-01", "2026-01-01"),  # before 1970
        ("1970-01-01", "2060-01-01"),  # far in the future
        ("garbage", None),
    ],
)
async def test_absurd_ranges_are_rejected(monkeypatch, from_, to):
    _wire(monkeypatch)
    with pytest.raises(TimelineRangeError):
        await StatsService().get_timeline(from_=from_, to=to, tz="UTC")


async def test_an_unknown_interval_is_rejected(monkeypatch):
    _wire(monkeypatch)
    with pytest.raises(TimelineRangeError):
        await StatsService().get_timeline(from_="2026-01-01", to="2026-02-01", interval="hour")


async def test_the_same_window_is_served_from_the_cache(monkeypatch):
    bodies = _wire(monkeypatch)
    service = StatsService()
    await service.get_timeline(from_="2026-01-01", to="2026-02-01", tz="UTC")
    # An unaligned bound inside the same buckets resolves to the same window.
    await service.get_timeline(from_="2026-01-01T05:00:00Z", to="2026-02-01", tz="UTC")
    assert len(bodies) == 1


# --- the route -----------------------------------------------------------------------

def _client(monkeypatch, **wire) -> TestClient:
    _wire(monkeypatch, **wire)
    app = FastAPI()
    app.include_router(stats_api.router, prefix="/stats")
    return TestClient(app)


def test_route_returns_the_timeline(monkeypatch):
    client = _client(monkeypatch)
    response = client.get("/stats/timeline", params={"from": "2026-01-01", "to": "2026-01-31", "tz": "Europe/Vienna"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"from", "to", "tz", "interval", "totalBefore", "total", "points"}
    assert body["interval"] == "day"


def test_route_answers_422_for_a_bad_range_and_interval(monkeypatch):
    client = _client(monkeypatch)
    assert client.get("/stats/timeline", params={"from": "2026-02-01", "to": "2026-01-01"}).status_code == 422
    assert client.get("/stats/timeline", params={"from": "2026-01-01", "interval": "hour"}).status_code == 422


def test_route_answers_503_when_opensearch_is_down(monkeypatch):
    client = _client(monkeypatch, error=OSConnectionError("N/A", "down", None))
    assert client.get("/stats/timeline", params={"from": "2026-01-01", "to": "2026-01-31"}).status_code == 503
