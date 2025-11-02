from __future__ import annotations

from datetime import datetime

from typing import Any

from pydantic import BaseModel, Field, field_validator


class SavedSearchBase(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    query_params: str = Field(
        alias="queryParams",
        serialization_alias="queryParams",
        description="URL query string fragment representing the saved search parameters.",
    )

    model_config = {"populate_by_name": True}

    @field_validator("query_params")
    @classmethod
    def _strip_leading_question_mark(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned.startswith("?"):
            cleaned = cleaned[1:]
        return cleaned


class SavedSearchCreate(SavedSearchBase):
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
        description="Optional DQL query when the saved search was created in DQL mode.",
    )


class SavedSearch(SavedSearchBase):
    id: str = Field(serialization_alias="id")
    created_at: datetime = Field(serialization_alias="createdAt")
    updated_at: datetime = Field(serialization_alias="updatedAt")
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
    )
