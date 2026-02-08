from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class CAPECEntry(BaseModel):
    """
    CAPEC (Common Attack Pattern Enumeration and Classification) entry model.

    Stores CAPEC attack pattern data from MITRE CAPEC database.
    """

    capec_id: str = Field(description="Normalized CAPEC ID (e.g., '66', '108')")
    name: str = Field(description="CAPEC name/title")
    description: str = Field(description="Brief description of the attack pattern")

    # Metadata
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this CAPEC data was fetched from MITRE",
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Full parsed CAPEC data for reference",
    )

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _normalize(self) -> "CAPECEntry":
        if self.capec_id:
            self.capec_id = self.capec_id.upper().replace("CAPEC-", "").strip()

        if self.fetched_at.tzinfo is None:
            self.fetched_at = self.fetched_at.replace(tzinfo=UTC)

        return self
