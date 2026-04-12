"""Shared UTC coercion for schema datetime fields.

Some data sources (notably OpenSearch `_source` reads of date fields indexed as
naive strings, and any legacy MongoDB documents still stored as naive) deliver
datetimes without tzinfo. When the frontend parses an ISO string without a
suffix via ``new Date()``, it applies the browser's local timezone and shifts
the displayed time by the user's offset.

Annotate schema datetime fields with :data:`UtcDatetime` so every outgoing JSON
value is stamped UTC-aware. Backend writes are already UTC by convention, so
this is a safe normalization rather than a conversion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BeforeValidator


def _coerce_utc(value: Any) -> Any:
    if value is None:
        return value
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
    return value


UtcDatetime = Annotated[datetime, BeforeValidator(_coerce_utc)]
