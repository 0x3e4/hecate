from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IngestionLogEntry(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    job_name: str = Field(alias="jobName", serialization_alias="jobName")
    status: str
    started_at: datetime = Field(alias="startedAt", serialization_alias="startedAt")
    finished_at: datetime | None = Field(default=None, alias="finishedAt", serialization_alias="finishedAt")
    duration_seconds: float | None = Field(default=None, alias="durationSeconds", serialization_alias="durationSeconds")
    metadata: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    model_config = {"populate_by_name": True}


class IngestionLogResponse(BaseModel):
    total: int
    items: list[IngestionLogEntry]
