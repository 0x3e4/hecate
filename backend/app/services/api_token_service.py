from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pymongo.errors import PyMongoError

from app.repositories.api_token_repository import ApiTokenRepository
from app.schemas.api_token import ApiTokenCreatedResponse, ApiTokenCreateRequest, ApiTokenResponse

log = structlog.get_logger()

TOKEN_PREFIX = "hct_"
_VISIBLE_PREFIX_LENGTH = 12
_MAX_TOKEN_LENGTH = 128


def _hash_token(token: str) -> str:
    # A token carries 256 random bits, so a slow password hash would add nothing
    # and would put PBKDF2 on the path of every failed request.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_token(value: str) -> bool:
    """Whether ``value`` is worth a database lookup."""
    return value.startswith(TOKEN_PREFIX) and len(value) <= _MAX_TOKEN_LENGTH


def _is_expired(document: dict[str, Any], now: datetime) -> bool:
    expires_at = document.get("expires_at")
    return expires_at is not None and expires_at <= now


def _to_response(document: dict[str, Any], now: datetime) -> dict[str, Any]:
    return {
        "id": document["_id"],
        "name": document["name"],
        "token_prefix": document["token_prefix"],
        "scopes": document["scopes"],
        "created_at": document["created_at"],
        "expires_at": document.get("expires_at"),
        "last_used_at": document.get("last_used_at"),
        "expired": _is_expired(document, now),
    }


class ApiTokenService:
    def __init__(self, repository: ApiTokenRepository) -> None:
        self.repository = repository

    async def list_tokens(self) -> list[ApiTokenResponse]:
        now = datetime.now(tz=UTC)
        documents = await self.repository.list_all()
        return [ApiTokenResponse(**_to_response(doc, now)) for doc in documents]

    async def create_token(self, request: ApiTokenCreateRequest) -> ApiTokenCreatedResponse:
        now = datetime.now(tz=UTC)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        days = request.expires_in_days
        document = {
            "_id": str(uuid.uuid4()),
            "name": request.name,
            "token_hash": _hash_token(token),
            "token_prefix": token[:_VISIBLE_PREFIX_LENGTH],
            "scopes": sorted(set(request.scopes)),
            "created_at": now,
            "expires_at": now + timedelta(days=days) if days else None,
            "last_used_at": None,
        }
        await self.repository.insert(document)
        return ApiTokenCreatedResponse(**_to_response(document, now), token=token)

    async def revoke_token(self, token_id: str) -> dict[str, Any] | None:
        return await self.repository.delete(token_id)

    async def authenticate(self, token: str) -> dict[str, Any] | None:
        """Return the stored token, or ``None`` when it is unknown or expired."""
        document = await self.repository.get_by_hash(_hash_token(token))
        now = datetime.now(tz=UTC)
        if document is None or _is_expired(document, now):
            return None
        try:
            await self.repository.touch(document["_id"], now)
        except PyMongoError as exc:
            # The token is valid. A missed timestamp must not fail the pipeline.
            log.warning("api_token.touch_failed", error=repr(exc))
        return document

    async def has_tokens(self, scope: str) -> bool:
        return await self.repository.any_with_scope(scope)


_api_token_service_singleton: ApiTokenService | None = None


async def get_api_token_service() -> ApiTokenService:
    global _api_token_service_singleton
    if _api_token_service_singleton is None:
        _api_token_service_singleton = ApiTokenService(await ApiTokenRepository.create())
    return _api_token_service_singleton
