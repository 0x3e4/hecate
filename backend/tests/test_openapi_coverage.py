"""Every API route is in the OpenAPI schema with a typed body and a described response.

Integrators read Swagger (/api/docs) and the in-app API page, so a route that is
missing there, takes a free-form dict or answers with an empty schema is a bug.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from fastapi.routing import APIRoute

from app.main import app


def _routes(routes: list[Any], prefix: str = "") -> Iterator[tuple[str, APIRoute]]:
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif type(route).__name__ == "_IncludedRouter":
            # FastAPI 0.139 keeps included routers nested.
            yield from _routes(route.original_router.routes, prefix + (route.include_context.prefix or ""))


def _operations() -> Iterator[tuple[str, dict[str, Any] | None]]:
    paths = app.openapi()["paths"]
    for path, route in _routes(app.routes):
        if not path.startswith("/api/"):
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            yield f"{method} {path}", paths.get(path.replace(":path}", "}"), {}).get(method.lower())


def _free_form(schema: dict[str, Any]) -> bool:
    return schema.get("type") == "object" and not schema.get("properties") and "$ref" not in schema


def test_api_routes_exist():
    assert sum(1 for _ in _operations()) > 150


def test_every_api_route_is_documented():
    assert [key for key, op in _operations() if op is None] == []


def test_request_bodies_are_typed():
    untyped = []
    for key, op in _operations():
        for media in ((op or {}).get("requestBody") or {}).get("content", {}).values():
            if _free_form(media.get("schema", {})):
                untyped.append(key)
    assert untyped == []


def test_responses_are_described():
    missing = []
    for key, op in _operations():
        responses = (op or {}).get("responses", {})
        success = [code for code in responses if code.startswith("2") or code.startswith("3")]
        if not success:
            missing.append(key)
            continue
        for code in success:
            content = responses[code].get("content")
            if content is None:
                if code not in ("204", "302", "307"):
                    missing.append(f"{key} {code}")
                continue
            for media_type, media in content.items():
                schema = media.get("schema") or {}
                if not schema or (_free_form(schema) and not schema.get("description") and "additionalProperties" not in schema):
                    missing.append(f"{key} {code} {media_type}")
    assert missing == []
