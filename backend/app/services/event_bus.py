"""In-memory async event bus for SSE broadcasting.

Subscribers receive events via per-subscriber ``asyncio.Queue`` instances.
The scheduler / job tracker publishes events which are then fanned out
to all active SSE connections.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

log = structlog.get_logger()


@dataclass(slots=True)
class JobEvent:
    """A single job lifecycle event."""

    event_type: str  # job_started | job_completed | job_failed | job_progress
    job_name: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    progress: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventType": self.event_type,
            "jobName": self.job_name,
            "status": self.status,
            "startedAt": self.started_at.isoformat() if self.started_at else None,
            "finishedAt": self.finished_at.isoformat() if self.finished_at else None,
            "durationSeconds": self.duration_seconds,
            "progress": self.progress,
            "metadata": self.metadata,
            "error": self.error,
        }


# Lifecycle events are remembered so a client that (re)connects learns what
# is running now and how the jobs it missed ended. Without that, a client that
# missed a job's last event kept showing it as running until a page reload.
_LIFECYCLE_EVENTS = {"job_started", "job_completed", "job_failed", "job_progress"}
FINISHED_RETENTION = timedelta(minutes=15)
RUNNING_RETENTION = timedelta(hours=24)
MAX_REMEMBERED_JOBS = 500


class EventBus:
    """Fan-out event bus backed by per-subscriber asyncio queues."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[JobEvent]] = set()
        # job_name -> (newest lifecycle event, when it was recorded)
        self._latest: dict[str, tuple[JobEvent, datetime]] = {}

    def _remember(self, event: JobEvent) -> None:
        if event.event_type not in _LIFECYCLE_EVENTS:
            return
        now = datetime.now(tz=UTC)
        previous = self._latest.get(event.job_name)
        if event.event_type == "job_progress" and previous and previous[0].status == "running":
            # Progress keeps the run's own start time and metadata (runId etc.).
            kept = previous[0]
            event = JobEvent(
                event_type=kept.event_type,
                job_name=kept.job_name,
                status="running",
                started_at=kept.started_at,
                progress=event.progress,
                metadata=kept.metadata,
            )
        self._latest.pop(event.job_name, None)  # re-insert: dict order = recency
        self._latest[event.job_name] = (event, now)
        self._prune(now)

    def _prune(self, now: datetime) -> None:
        for name, (event, seen) in list(self._latest.items()):
            limit = RUNNING_RETENTION if event.status == "running" else FINISHED_RETENTION
            if now - seen > limit:
                del self._latest[name]
        while len(self._latest) > MAX_REMEMBERED_JOBS:
            del self._latest[next(iter(self._latest))]

    def snapshot(self) -> list[JobEvent]:
        """Running jobs plus the outcome of jobs that finished recently, oldest first."""
        self._prune(datetime.now(tz=UTC))
        return [event for event, _ in self._latest.values()]

    def subscribe(self) -> asyncio.Queue[JobEvent]:
        queue: asyncio.Queue[JobEvent] = asyncio.Queue(maxsize=256)
        self._subscribers.add(queue)
        log.debug("event_bus.subscriber_added", count=len(self._subscribers))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[JobEvent]) -> None:
        self._subscribers.discard(queue)
        log.debug("event_bus.subscriber_removed", count=len(self._subscribers))

    def publish(self, event: JobEvent) -> None:
        self._remember(event)
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                log.warning("event_bus.queue_full", job=event.job_name)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Module-level singleton --------------------------------------------------

_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def publish_job_started(job_name: str, started_at: datetime, **metadata: Any) -> None:
    get_event_bus().publish(
        JobEvent(
            event_type="job_started",
            job_name=job_name,
            status="running",
            started_at=started_at,
            metadata=metadata,
        )
    )


def publish_job_completed(
    job_name: str,
    started_at: datetime,
    finished_at: datetime,
    **result: Any,
) -> None:
    get_event_bus().publish(
        JobEvent(
            event_type="job_completed",
            job_name=job_name,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=(finished_at - started_at).total_seconds(),
            metadata=result,
        )
    )


def publish_job_failed(
    job_name: str,
    started_at: datetime,
    finished_at: datetime,
    error: str,
    **metadata: Any,
) -> None:
    get_event_bus().publish(
        JobEvent(
            event_type="job_failed",
            job_name=job_name,
            status="failed",
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=(finished_at - started_at).total_seconds(),
            error=error,
            metadata=metadata,
        )
    )


def publish_job_progress(job_name: str, progress: dict[str, Any]) -> None:
    get_event_bus().publish(
        JobEvent(
            event_type="job_progress",
            job_name=job_name,
            status="running",
            started_at=datetime.now(tz=UTC),
            progress=progress,
        )
    )


def publish_new_vulnerabilities(source: str, count: int) -> None:
    """Emit an event when new vulnerabilities have been ingested."""
    if count <= 0:
        return
    get_event_bus().publish(
        JobEvent(
            event_type="new_vulnerabilities",
            job_name=source,
            status="completed",
            started_at=datetime.now(tz=UTC),
            metadata={"source": source, "count": count},
        )
    )
