from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class CWEEntry(BaseModel):
    """
    CWE (Common Weakness Enumeration) entry model.

    Stores CWE weakness data from MITRE CWE database.
    """

    cwe_id: str = Field(description="Normalized CWE ID (e.g., '79', '89')")
    name: str = Field(description="CWE name/title")
    description: str = Field(description="Brief description of the weakness")
    extended_description: str | None = Field(default=None, description="Detailed description")

    # Metadata
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this CWE data was fetched from MITRE"
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Full raw CWE data from API for reference"
    )

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _normalize(self) -> "CWEEntry":
        # Ensure CWE ID is normalized (no "CWE-" prefix)
        if self.cwe_id:
            self.cwe_id = self.cwe_id.upper().replace("CWE-", "").strip()

        # Ensure fetched_at is timezone-aware
        if self.fetched_at.tzinfo is None:
            self.fetched_at = self.fetched_at.replace(tzinfo=UTC)

        return self
