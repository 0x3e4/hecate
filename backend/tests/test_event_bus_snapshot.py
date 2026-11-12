"""The event bus remembers job states so a (re)connecting client can settle stale ones."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.services import event_bus as eb
from app.services.event_bus import EventBus, JobEvent


def _event(name: str, event_type: str, status: str, **metadata: object) -> JobEvent:
    return JobEvent(event_type=event_type, job_name=name, status=status,
                    started_at=datetime.now(tz=UTC), metadata=dict(metadata))


def test_snapshot_holds_running_and_finished_jobs_with_their_last_state() -> None:
    bus = EventBus()
    bus.publish(_event("sca_scan_1", "job_started", "running"))
    bus.publish(_event("sca_scan_2", "job_started", "running"))
    bus.publish(_event("sca_scan_1", "job_completed", "completed"))

    snapshot = {e.job_name: e.status for e in bus.snapshot()}

    assert snapshot == {"sca_scan_1": "completed", "sca_scan_2": "running"}


def test_progress_keeps_the_runs_start_and_metadata() -> None:
    bus = EventBus()
    started = _event("ai_investigation_CVE-1", "job_started", "running", runId="r1")
    bus.publish(started)
    bus.publish(JobEvent(event_type="job_progress", job_name="ai_investigation_CVE-1",
                         status="running", started_at=datetime.now(tz=UTC) + timedelta(minutes=5),
                         progress={"step": 2}))

    [kept] = bus.snapshot()

    assert kept.event_type == "job_started"
    assert kept.started_at == started.started_at
    assert kept.metadata == {"runId": "r1"}
    assert kept.progress == {"step": 2}


def test_new_vulnerability_events_are_not_remembered() -> None:
    bus = EventBus()
    bus.publish(_event("nvd", "new_vulnerabilities", "completed"))
    assert bus.snapshot() == []


def test_finished_jobs_age_out_before_running_ones(monkeypatch) -> None:
    bus = EventBus()
    bus.publish(_event("done", "job_completed", "completed"))
    bus.publish(_event("busy", "job_started", "running"))
    later = datetime.now(tz=UTC) + eb.FINISHED_RETENTION + timedelta(seconds=1)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return later

    monkeypatch.setattr(eb, "datetime", Clock)

    assert [e.job_name for e in bus.snapshot()] == ["busy"]


def test_the_memory_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(eb, "MAX_REMEMBERED_JOBS", 3)
    bus = EventBus()
    for i in range(5):
        bus.publish(_event(f"job_{i}", "job_started", "running"))
    assert [e.job_name for e in bus.snapshot()] == ["job_2", "job_3", "job_4"]
