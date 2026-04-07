from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LicensePolicyDocument(BaseModel):
    """A license compliance policy defining allowed/denied SPDX license IDs."""

    name: str = Field(description="Human-readable policy name")
    description: str | None = None
    allowed: list[str] = Field(default_factory=list, description="SPDX IDs treated as allowed")
    denied: list[str] = Field(default_factory=list, description="SPDX IDs treated as denied")
    reviewed: list[str] = Field(
        default_factory=list, description="Manually reviewed, acceptable licenses"
    )
    default_action: str = Field(
        default="warn", description="Action for unlisted licenses: allow | warn | deny"
    )
    is_default: bool = Field(default=False, description="Whether this is the system default policy")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
