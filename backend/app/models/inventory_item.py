from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


Deployment = Literal["onprem", "cloud", "hybrid"]


class InventoryItemDocument(BaseModel):
    """A product/version the user runs in their environment.

    Matched against the vulnerability database so CVE pages, AI analyses, and
    notifications can surface "you have X instances of this affected".
    """

    name: str = Field(description="Human-readable label (e.g. '.NET Runtime 8.0.25 — prod cluster')")
    vendor_slug: str = Field(description="Asset catalog vendor slug (e.g. 'microsoft')")
    product_slug: str = Field(description="Asset catalog product slug (e.g. '.net')")
    vendor_name: str | None = Field(default=None, description="Display name captured at create time")
    product_name: str | None = Field(default=None, description="Display name captured at create time")
    version: str = Field(description="Free-form version string (e.g. '8.0.25', '8.0.*')")
    deployment: Deployment = Field(default="onprem")
    environment: str = Field(
        default="prod",
        description="Free-form environment label (e.g. 'prod', 'staging', 'dev', 'test', 'dr')",
    )
    instance_count: int = Field(default=1, ge=1)
    owner: str | None = None
    notes: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
