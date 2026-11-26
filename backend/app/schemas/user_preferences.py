"""Personal display preferences of a signed-in user (OIDC).

Without a sign-in the web app keeps the same values in the browser only.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal
from zoneinfo import available_timezones

from pydantic import BaseModel, Field, field_validator

from app.schemas._utc import UtcDatetime


@lru_cache(maxsize=1)
def _known_zones() -> frozenset[str]:
    return frozenset(available_timezones())


class UserPreferences(BaseModel):
    """What the user chose; ``None`` means the browser decides (its language, its zone)."""

    language: Literal["en", "de"] | None = None
    timezone: str | None = Field(default=None, max_length=64)
    dashboard_only_my_stack: bool = Field(
        default=False, alias="dashboardOnlyMyStack", serialization_alias="dashboardOnlyMyStack"
    )

    model_config = {"populate_by_name": True, "extra": "forbid"}

    @field_validator("timezone")
    @classmethod
    def _zone(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        if value not in _known_zones():
            raise ValueError("Unknown IANA time zone.")
        return value


class UserPreferencesResponse(UserPreferences):
    """The stored preferences; ``updatedAt`` is ``None`` while the account has saved none."""

    updated_at: UtcDatetime | None = Field(default=None, alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}
