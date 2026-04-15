from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas._utc import UtcDatetime


class NotificationStatusResponse(BaseModel):
    enabled: bool = Field(alias="enabled", serialization_alias="enabled")
    reachable: bool = Field(alias="reachable", serialization_alias="reachable")
    url: str = Field(alias="url", serialization_alias="url")
    tags: str | None = Field(default=None, alias="tags", serialization_alias="tags")

    model_config = {"populate_by_name": True}


class NotificationTestResponse(BaseModel):
    success: bool = Field(alias="success", serialization_alias="success")
    message: str = Field(alias="message", serialization_alias="message")

    model_config = {"populate_by_name": True}


# --- Notification Rules ---


class NotificationRuleCreate(BaseModel):
    """Payload for creating / updating a notification rule."""

    name: str = Field(min_length=1, max_length=200)
    enabled: bool = Field(default=True)
    rule_type: str = Field(
        alias="ruleType",
        serialization_alias="ruleType",
        description="event | saved_search | vendor | product | dql | scan | inventory",
    )
    apprise_tag: str = Field(
        default="all",
        alias="appriseTag",
        serialization_alias="appriseTag",
    )

    # --- type-specific fields (optional, depending on rule_type) ---

    # event
    event_types: list[str] = Field(
        default_factory=list,
        alias="eventTypes",
        serialization_alias="eventTypes",
        description="scan_completed, scan_failed, sync_failed, new_vulnerabilities",
    )

    # saved_search
    saved_search_id: str | None = Field(
        default=None,
        alias="savedSearchId",
        serialization_alias="savedSearchId",
    )

    # vendor / product
    vendor_slug: str | None = Field(
        default=None,
        alias="vendorSlug",
        serialization_alias="vendorSlug",
    )
    product_slug: str | None = Field(
        default=None,
        alias="productSlug",
        serialization_alias="productSlug",
    )

    # dql
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
    )

    # scan
    scan_severity_threshold: str | None = Field(
        default=None,
        alias="scanSeverityThreshold",
        serialization_alias="scanSeverityThreshold",
        description="Minimum severity to trigger: critical, high, medium, low",
    )
    scan_target_filter: str | None = Field(
        default=None,
        alias="scanTargetFilter",
        serialization_alias="scanTargetFilter",
        description="Target name filter (supports * wildcards)",
    )

    model_config = {"populate_by_name": True}


class NotificationRuleResponse(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    name: str = Field(alias="name", serialization_alias="name")
    enabled: bool = Field(alias="enabled", serialization_alias="enabled")
    rule_type: str = Field(alias="ruleType", serialization_alias="ruleType")
    apprise_tag: str = Field(alias="appriseTag", serialization_alias="appriseTag")

    event_types: list[str] = Field(
        default_factory=list,
        alias="eventTypes",
        serialization_alias="eventTypes",
    )
    saved_search_id: str | None = Field(
        default=None,
        alias="savedSearchId",
        serialization_alias="savedSearchId",
    )
    vendor_slug: str | None = Field(
        default=None,
        alias="vendorSlug",
        serialization_alias="vendorSlug",
    )
    product_slug: str | None = Field(
        default=None,
        alias="productSlug",
        serialization_alias="productSlug",
    )
    dql_query: str | None = Field(
        default=None,
        alias="dqlQuery",
        serialization_alias="dqlQuery",
    )
    scan_severity_threshold: str | None = Field(
        default=None,
        alias="scanSeverityThreshold",
        serialization_alias="scanSeverityThreshold",
    )
    scan_target_filter: str | None = Field(
        default=None,
        alias="scanTargetFilter",
        serialization_alias="scanTargetFilter",
    )

    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")
    last_evaluated_at: UtcDatetime | None = Field(
        default=None,
        alias="lastEvaluatedAt",
        serialization_alias="lastEvaluatedAt",
    )
    last_triggered_at: UtcDatetime | None = Field(
        default=None,
        alias="lastTriggeredAt",
        serialization_alias="lastTriggeredAt",
    )

    model_config = {"populate_by_name": True}


class NotificationRuleListResponse(BaseModel):
    total: int
    items: list[NotificationRuleResponse]

    model_config = {"populate_by_name": True}


# --- Apprise Channel Management ---


class NotificationChannelResponse(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    url: str = Field(alias="url", serialization_alias="url")
    tag: str = Field(default="all", alias="tag", serialization_alias="tag")
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")

    model_config = {"populate_by_name": True}


class NotificationChannelListResponse(BaseModel):
    items: list[NotificationChannelResponse] = Field(default_factory=list, alias="items", serialization_alias="items")

    model_config = {"populate_by_name": True}


class NotificationChannelAddRequest(BaseModel):
    url: str = Field(min_length=1, alias="url", serialization_alias="url")
    tag: str = Field(default="all", alias="tag", serialization_alias="tag")

    model_config = {"populate_by_name": True}


# --- Notification Message Templates ---


class NotificationTemplateCreate(BaseModel):
    """Payload for creating / updating a notification message template."""

    event_key: str = Field(
        min_length=1,
        max_length=100,
        alias="eventKey",
        serialization_alias="eventKey",
        description="Event key: new_vulnerabilities, scan_completed, scan_failed, sync_failed, watch_rule_match",
    )
    tag: str = Field(
        default="all",
        alias="tag",
        serialization_alias="tag",
        description="Apprise tag this template applies to, or 'all' for global default",
    )
    title_template: str = Field(
        min_length=1,
        max_length=500,
        alias="titleTemplate",
        serialization_alias="titleTemplate",
        description="Title template with {placeholders}",
    )
    body_template: str = Field(
        min_length=1,
        max_length=5000,
        alias="bodyTemplate",
        serialization_alias="bodyTemplate",
        description="Body template with {placeholders}",
    )

    model_config = {"populate_by_name": True}


class NotificationTemplateResponse(BaseModel):
    id: str = Field(alias="id", serialization_alias="id")
    event_key: str = Field(alias="eventKey", serialization_alias="eventKey")
    tag: str = Field(default="all", alias="tag", serialization_alias="tag")
    title_template: str = Field(alias="titleTemplate", serialization_alias="titleTemplate")
    body_template: str = Field(alias="bodyTemplate", serialization_alias="bodyTemplate")
    created_at: UtcDatetime = Field(alias="createdAt", serialization_alias="createdAt")
    updated_at: UtcDatetime = Field(alias="updatedAt", serialization_alias="updatedAt")

    model_config = {"populate_by_name": True}


class NotificationTemplateListResponse(BaseModel):
    items: list[NotificationTemplateResponse] = Field(
        default_factory=list,
        alias="items",
        serialization_alias="items",
    )

    model_config = {"populate_by_name": True}
