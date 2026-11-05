"""
The advisory feeds Hecate reads: the ones from `.env` (`CERT_FEEDS` + `CERT_FEEDS_EXTRA`)
and the ones added on System -> Data. Both kinds go through the same sync job, the
same parser and the same limits.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.core.config import settings
from app.repositories.advisory_feed_repository import AdvisoryFeedRepository, name_key
from app.schemas.advisory_feed import (
    AdvisoryFeedCreateRequest,
    AdvisoryFeedResponse,
    AdvisoryFeedUpdateRequest,
)
from app.services.http.public_host import is_public_url
from app.services.ingestion.cert_feed_client import (
    DEFAULT_KIND,
    CertFeed,
    merge_feeds,
    parse_feed_config,
    safe_url,
)
from app.utils.strings import mask_url_credentials

log = structlog.get_logger()


# Query parameters whose value is a credential, as in `?token=` on a private feed.
_SECRET_PARAM = re.compile(r"key|token|secret|pass|auth|sig|session", re.IGNORECASE)
REDACTED = "***"


def redact_feed_url(url: str) -> str:
    """
    The feed list and the audit log are public, so a credential in a feed URL is
    masked there: the `user:password@` part and the value of any query parameter
    named like a key or token. Plain public feed URLs come back unchanged.
    """
    masked = mask_url_credentials(url)
    parts = urlsplit(masked)
    if not parts.query:
        return masked
    query = [(key, REDACTED if _SECRET_PARAM.search(key) else value) for key, value in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="*"), parts.fragment))


class FeedConflictError(ValueError):
    """The name is already taken by another feed."""


class FeedNotFoundError(LookupError):
    pass


def configured_feeds() -> list[CertFeed]:
    return parse_feed_config(settings.cert_feeds, settings.cert_feeds_extra)


def _managed_feed(document: dict[str, Any]) -> CertFeed:
    return CertFeed(
        name=document["name"],
        url=document["url"],
        kind=document.get("kind") or DEFAULT_KIND,
        guard_host=True,
    )


async def active_feeds() -> list[CertFeed]:
    """Every feed the sync reads. When MongoDB is down, the `.env` feeds still run."""
    configured = configured_feeds()
    try:
        repository = await AdvisoryFeedRepository.create()
        documents = await repository.list_all()
    except PyMongoError as exc:
        log.warning("advisory_feeds.managed_unavailable", error=str(exc))
        return configured
    return merge_feeds(configured, [_managed_feed(doc) for doc in documents if doc.get("enabled", True)])


async def feed_kinds() -> dict[str, str]:
    """
    Feed name -> kind as configured now. Read when advisories are shown, so moving a
    feed to another kind applies to what it already delivered; a removed feed falls
    back to the kind stored on its advisories.
    """
    kinds: dict[str, str] = {}
    try:
        repository = await AdvisoryFeedRepository.create()
        for document in await repository.list_all():
            kinds[document["name"]] = document.get("kind") or DEFAULT_KIND
    except PyMongoError as exc:
        log.warning("advisory_feeds.kinds_unavailable", error=str(exc))
    for feed in configured_feeds():
        kinds[feed.name] = feed.kind
    return kinds


def _response(document: dict[str, Any]) -> AdvisoryFeedResponse:
    return AdvisoryFeedResponse(
        id=document["_id"],
        name=document["name"],
        url=redact_feed_url(document["url"]),
        kind=document.get("kind") or DEFAULT_KIND,
        origin="ui",
        enabled=document.get("enabled", True),
        created_at=document.get("created_at"),
        updated_at=document.get("updated_at"),
    )


class AdvisoryFeedService:
    def __init__(self, repository: AdvisoryFeedRepository) -> None:
        self.repository = repository

    async def list_feeds(self) -> list[AdvisoryFeedResponse]:
        configured = [
            AdvisoryFeedResponse(name=feed.name, url=redact_feed_url(feed.url), kind=feed.kind, origin="env")
            for feed in configured_feeds()
        ]
        managed = [_response(doc) for doc in await self.repository.list_all()]
        return [*configured, *managed]

    async def create_feed(self, request: AdvisoryFeedCreateRequest) -> AdvisoryFeedResponse:
        url = await self._checked_url(request.url)
        self._ensure_not_configured(request.name)
        now = datetime.now(UTC)
        document = {
            "_id": str(uuid.uuid4()),
            "name": request.name,
            "name_key": name_key(request.name),
            "url": url,
            "kind": request.kind,
            "enabled": request.enabled,
            "created_at": now,
            "updated_at": now,
        }
        try:
            await self.repository.insert(document)
        except DuplicateKeyError as exc:
            raise FeedConflictError(f"A feed named {request.name!r} already exists.") from exc
        return _response(document)

    async def update_feed(self, feed_id: str, request: AdvisoryFeedUpdateRequest) -> AdvisoryFeedResponse:
        existing = await self.repository.get(feed_id)
        if existing is None:
            raise FeedNotFoundError(feed_id)
        fields: dict[str, Any] = {}
        if request.name is not None and request.name != existing["name"]:
            self._ensure_not_configured(request.name)
            fields |= {"name": request.name, "name_key": name_key(request.name)}
        if request.url is not None and request.url != existing["url"]:
            fields["url"] = await self._checked_url(request.url)
        if request.kind is not None:
            fields["kind"] = request.kind
        if request.enabled is not None:
            fields["enabled"] = request.enabled
        if not fields:
            return _response(existing)
        fields["updated_at"] = datetime.now(UTC)
        try:
            updated = await self.repository.update(feed_id, fields)
        except DuplicateKeyError as exc:
            raise FeedConflictError(f"A feed named {request.name!r} already exists.") from exc
        if updated is None:
            raise FeedNotFoundError(feed_id)
        return _response(updated)

    async def delete_feed(self, feed_id: str) -> AdvisoryFeedResponse:
        deleted = await self.repository.delete(feed_id)
        if deleted is None:
            raise FeedNotFoundError(feed_id)
        return _response(deleted)

    @staticmethod
    def _ensure_not_configured(name: str) -> None:
        if name_key(name) in {name_key(feed.name) for feed in configured_feeds()}:
            raise FeedConflictError(f"{name!r} is already configured in .env.")

    @staticmethod
    async def _checked_url(value: str) -> str:
        url = safe_url(value)
        if url is None:
            raise ValueError("The feed URL must be an http(s) URL with a host.")
        if not settings.cert_feeds_allow_private_hosts and not await is_public_url(url):
            raise ValueError(
                "The feed's host does not resolve to a public address. "
                "Set CERT_FEEDS_ALLOW_PRIVATE_HOSTS=true to read a feed on the internal network."
            )
        return url


async def get_advisory_feed_service() -> AdvisoryFeedService:
    return AdvisoryFeedService(await AdvisoryFeedRepository.create())
