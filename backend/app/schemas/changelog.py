from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ChangeHistoryField(BaseModel):
    """Field change in a changelog entry."""

    name: str
    previous: Any = None
    current: Any = None


class LatestChange(BaseModel):
    """Latest change details for a vulnerability."""

    changed_at: str = Field(serialization_alias="changedAt")
    change_type: str = Field(serialization_alias="changeType")
    job_name: str = Field(serialization_alias="jobName")
    job_label: str | None = Field(default=None, serialization_alias="jobLabel")
    fields: list[ChangeHistoryField] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ChangelogEntry(BaseModel):
    """
    Represents a single changelog entry for a vulnerability.
    """

    vuln_id: str = Field(serialization_alias="vulnId")
    title: str
    source: str
    change_type: str = Field(
        serialization_alias="changeType",
        description="Type of change: 'created' or 'updated'",
    )
    timestamp: datetime
    cvss_score: float | None = Field(default=None, serialization_alias="cvssScore")
    severity: str | None = None
    latest_change: LatestChange | None = Field(
        default=None, serialization_alias="latestChange"
    )

    model_config = {"populate_by_name": True}


class ChangelogResponse(BaseModel):
    """
    Response containing a list of recent vulnerability changes.
    """

    entries: list[ChangelogEntry]
    total: int
