from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


class CPEEntry(BaseModel):
    cpe_name: str = Field(alias="cpeName", serialization_alias="cpeName")
    title: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    deprecated: bool = False
    cpe_name_id: dict[str, Any] | None = Field(default=None, alias="cpeNameId", serialization_alias="cpeNameId")
    last_modified: UtcDatetime | None = Field(default=None, alias="lastModified", serialization_alias="lastModified")

    model_config = {"populate_by_name": True}


class CPEQuery(BaseModel):
    keyword: str | None = None
    vendor: str | None = None
    product: str | None = None
    limit: int = Field(default=25, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class CPEQueryResponse(BaseModel):
    total: int
    items: list[CPEEntry]


class CPEValueListResponse(BaseModel):
    total: int
    items: list[str]
