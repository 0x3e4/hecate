from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


class IngestionLogEntry(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    job_name: str = Field(alias="jobName", serialization_alias="jobName")
    status: str
    started_at: UtcDatetime = Field(alias="startedAt", serialization_alias="startedAt")
    finished_at: UtcDatetime | None = Field(default=None, alias="finishedAt", serialization_alias="finishedAt")
    duration_seconds: float | None = Field(default=None, alias="durationSeconds", serialization_alias="durationSeconds")
    metadata: dict[str, Any] | None = None
    progress: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    overdue: bool = Field(default=False, alias="overdue", serialization_alias="overdue")
    overdue_reason: str | None = Field(
        default=None,
        alias="overdueReason",
        serialization_alias="overdueReason",
    )

    model_config = {"populate_by_name": True}


class IngestionLogResponse(BaseModel):
    total: int
    items: list[IngestionLogEntry]
