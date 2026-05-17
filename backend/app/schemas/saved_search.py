from __future__ import annotations

from datetime import datetime

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas._utc import UtcDatetime


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
    regex_query: str | None = Field(
        default=None,
        alias="regexQuery",
        serialization_alias="regexQuery",
        description="Optional regex pattern when the saved search was created in regex mode.",
        max_length=500,
    )
    query_mode: str | None = Field(
        default=None,
        alias="queryMode",
        serialization_alias="queryMode",
        description="Discriminator: keyword | dql | regex. Used to restore the UI mode.",
    )


class SavedSearchUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    query_params: str | None = Field(
        default=None,
        alias="queryParams",
        serialization_alias="queryParams",
    )
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
    )
    regex_query: str | None = Field(
        default=None,
        alias="regexQuery",
        serialization_alias="regexQuery",
        max_length=500,
    )
    query_mode: str | None = Field(
        default=None,
        alias="queryMode",
        serialization_alias="queryMode",
    )

    model_config = {"populate_by_name": True}

    @field_validator("query_params")
    @classmethod
    def _strip_leading_question_mark(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if cleaned.startswith("?"):
            cleaned = cleaned[1:]
        return cleaned


class SavedSearch(SavedSearchBase):
    id: str = Field(serialization_alias="id")
    created_at: UtcDatetime = Field(serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(serialization_alias="updatedAt")
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
    )
    regex_query: str | None = Field(
        default=None,
        alias="regexQuery",
        serialization_alias="regexQuery",
    )
    query_mode: str | None = Field(
        default=None,
        alias="queryMode",
        serialization_alias="queryMode",
    )
