"""OpenAPI descriptions for routes that answer with something other than a model.

FastAPI documents a route through its ``response_model``. File downloads, ZIPs
and the event stream have none, so without these they show up in Swagger with
an empty response.
"""
from __future__ import annotations

from typing import Any


def download(media_type: str, description: str, *, binary: bool = False) -> dict[int | str, dict[str, Any]]:
    """``responses=`` for a route that returns a file (sent as an attachment)."""
    schema: dict[str, Any] = (
        {"type": "string", "format": "binary"} if binary else {"type": "object", "description": description}
    )
    return {200: {"description": description, "content": {media_type: {"schema": schema}}}}


def event_stream(description: str) -> dict[int | str, dict[str, Any]]:
    """``responses=`` for a Server-Sent Events endpoint."""
    return {200: {"description": description, "content": {"text/event-stream": {"schema": {"type": "string"}}}}}
