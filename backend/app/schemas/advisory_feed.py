from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints

from app.schemas._utc import UtcDatetime

AdvisoryFeedKind = Literal["cert", "vendor", "community"]
AdvisoryFeedOrigin = Literal["env", "ui"]

# A name becomes part of every advisory's id (`{name}:{guid}`) and is shown on each row.
FeedName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
FeedUrl = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]


class AdvisoryFeedCreateRequest(BaseModel):
    name: FeedName
    url: FeedUrl
    kind: AdvisoryFeedKind = "cert"
    enabled: bool = True
    model_config = {"populate_by_name": True}


class AdvisoryFeedUpdateRequest(BaseModel):
    name: FeedName | None = None
    url: FeedUrl | None = None
    kind: AdvisoryFeedKind | None = None
    enabled: bool | None = None
    model_config = {"populate_by_name": True}


class AdvisoryFeedResponse(BaseModel):
    """A feed from `.env` (`origin: env`, read-only, no id) or one added on the System page."""

    id: str | None = None
    name: str
    url: str
    kind: AdvisoryFeedKind
    origin: AdvisoryFeedOrigin
    enabled: bool = True
    created_at: UtcDatetime | None = Field(default=None, alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime | None = Field(default=None, alias="updatedAt", serialization_alias="updatedAt")
    model_config = {"populate_by_name": True}


class AdvisoryFeedListResponse(BaseModel):
    items: list[AdvisoryFeedResponse]
    # Whether the sync job runs at all (`CERT_FEEDS_ENABLED`); UI feeds are read by the same job.
    sync_enabled: bool = Field(alias="syncEnabled", serialization_alias="syncEnabled")
    model_config = {"populate_by_name": True}
