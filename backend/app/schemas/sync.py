from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class SyncState(BaseModel):
    """Current state of a sync job."""

    job_name: str = Field(alias="jobName", serialization_alias="jobName")
    label: str
    status: str  # running, completed, failed, cancelled, idle
    started_at: datetime | None = Field(default=None, alias="startedAt", serialization_alias="startedAt")
    finished_at: datetime | None = Field(default=None, alias="finishedAt", serialization_alias="finishedAt")
    duration_seconds: float | None = Field(default=None, alias="durationSeconds", serialization_alias="durationSeconds")
    next_run: datetime | None = Field(default=None, alias="nextRun", serialization_alias="nextRun")
    last_result: dict | None = Field(default=None, alias="lastResult", serialization_alias="lastResult")
    error: str | None = None

    model_config = {"populate_by_name": True}


class SyncStatesResponse(BaseModel):
    """Response containing all sync states."""

    syncs: list[SyncState]


class TriggerSyncRequest(BaseModel):
    """Request to trigger a sync job."""

    initial: bool = Field(default=False, description="Whether to run as initial sync (full sync)")


class TriggerSyncResponse(BaseModel):
    """Response after triggering a sync."""

    success: bool
    message: str
    job_name: str = Field(alias="jobName", serialization_alias="jobName")

    model_config = {"populate_by_name": True}
