from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints

from app.schemas._utc import UtcDatetime

SCOPE_SCAN_SUBMIT = "scan:submit"
SCOPE_INVENTORY_REPORT = "inventory:report"

ApiTokenScope = Literal["scan:submit", "inventory:report"]


class ApiTokenCreateRequest(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    scopes: list[ApiTokenScope] = Field(min_length=1, max_length=2)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, alias="expiresInDays")
    model_config = {"populate_by_name": True}


class ApiTokenResponse(BaseModel):
    id: str
    name: str
    token_prefix: str = Field(alias="tokenPrefix", serialization_alias="tokenPrefix")
    scopes: list[str]
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    expires_at: UtcDatetime | None = Field(default=None, alias="expiresAt", serialization_alias="expiresAt")
    last_used_at: UtcDatetime | None = Field(default=None, alias="lastUsedAt", serialization_alias="lastUsedAt")
    expired: bool = False
    model_config = {"populate_by_name": True}


class ApiTokenCreatedResponse(ApiTokenResponse):
    """The one response that carries the token itself. Only its hash is stored."""

    token: str


class ApiTokenListResponse(BaseModel):
    items: list[ApiTokenResponse]
