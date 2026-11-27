"""Server lists Hecate fetches itself: a URL, read on a schedule and applied like a pushed list.

The list behind the URL (a CMDB export, NetBox, an AWX inventory, a file on a
web server) goes through the same parser and ``apply_list`` as an upload or a
push, under its source name, so a fetched list and a pushed one behave alike.

The backend makes the request, so the URL is an SSRF surface: http(s) only,
no credentials in the URL (they go in a header, which is only sent over
https), no redirects, a size cap, and every resolved address must be public
unless ``INVENTORY_LIST_SOURCES_ALLOW_PRIVATE_HOSTS`` is set (checked on save
and before every fetch). Only parsed system names and fields reach the
inventory; the response itself is never shown. Managing sources is admin-only
(routes.py), because a source holds a credential.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import structlog

from app.core.config import settings
from app.repositories.inventory_list_source_repository import InventoryListSourceRepository
from app.schemas.inventory_system import (
    InventoryListSourceCreateRequest,
    InventoryListSourceListResponse,
    InventoryListSourcePullResponse,
    InventoryListSourceResponse,
    InventoryListSourceResult,
    InventoryListSourceUpdateRequest,
    InventorySystemImportResponse,
)
from app.services.advisory_feed_service import redact_feed_url
from app.services.http.public_host import is_public_url
from app.services.http.ssl import get_http_verify
from app.services.inventory_system_lists import MAX_LIST_BYTES, ListError, parse_system_list
from app.services.inventory_system_service import (
    InventorySystemService,
    ListTooDestructive,
    get_inventory_system_service,
)
from app.utils.strings import has_control_chars

log = structlog.get_logger()

MAX_LIST_SOURCES = 20
_ERROR_TEXT_LIMIT = 300


class ListFetchError(Exception):
    """A fetch that produced no usable list. ``kind`` is what the UI shows next to the message."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


Header = tuple[str, str] | None
Fetcher = Callable[[str, Header], Awaitable[str]]


def check_url(url: str, *, with_credential: bool) -> str:
    """The URL's shape: http(s), a host, no ``user:pass@``; a credential needs https. Raises ``ValueError``."""
    url = url.strip()
    if has_control_chars(url):
        raise ValueError("The list URL must not contain control characters.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The list URL must be an http(s) URL with a host.")
    if parts.username or parts.password:
        raise ValueError("Put the credential in the header field, not in the URL.")
    if with_credential and parts.scheme != "https":
        raise ValueError("A credential is only sent over https.")
    return url


async def _host_allowed(url: str) -> bool:
    return settings.inventory_list_sources_allow_private_hosts or await is_public_url(url)


_NOT_PUBLIC = (
    "The host does not resolve to a public address. Fetching from the internal network "
    "has to be allowed on the server first."
)


async def fetch_list(url: str, header: Header) -> str:
    """GET the list: guarded host, no redirects, at most ``MAX_LIST_BYTES``, UTF-8 text."""
    if not await _host_allowed(url):
        raise ListFetchError("not_public", _NOT_PUBLIC)
    headers = {"User-Agent": settings.ingestion_user_agent, "Accept": "*/*"}
    if header is not None:
        headers[header[0]] = header[1]
    try:
        async with httpx.AsyncClient(
            verify=get_http_verify(),
            timeout=httpx.Timeout(settings.inventory_list_source_timeout_seconds, connect=10.0),
            follow_redirects=False,
            headers=headers,
        ) as client:
            async with client.stream("GET", url) as response:
                if response.is_redirect:
                    raise ListFetchError("redirect", f"The server answered with a redirect (HTTP {response.status_code}); use the final URL.")
                if response.status_code != 200:
                    raise ListFetchError("http_status", f"The server answered HTTP {response.status_code}.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_LIST_BYTES:
                        raise ListFetchError("too_large", f"The list is larger than {MAX_LIST_BYTES // (1024 * 1024)} MB.")
    except httpx.HTTPError as exc:
        raise ListFetchError("network", f"The request failed ({type(exc).__name__}).") from exc
    try:
        return bytes(body).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ListFetchError("not_text", "The answer is not UTF-8 text.") from exc


def next_run_at(doc: dict[str, Any]) -> datetime | None:
    """When the scheduler fetches the source next; a source never fetched is due right away."""
    if not doc.get("enabled", True):
        return None
    last = doc.get("last_run_at")
    if not isinstance(last, datetime):
        return doc.get("created_at") or datetime.now(tz=UTC)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return last + timedelta(minutes=int(doc.get("interval_minutes") or 60))


def _result(result: InventorySystemImportResponse) -> dict[str, Any]:
    return {
        "format": result.format, "listed": result.listed,
        "created_count": result.created_count, "updated_count": result.updated_count,
        "unchanged_count": result.unchanged_count, "retired_count": result.retired_count,
        "restored_count": result.restored_count, "skipped_count": len(result.skipped),
    }


def _response(doc: dict[str, Any]) -> InventoryListSourceResponse:
    last = doc.get("last_result")
    return InventoryListSourceResponse(
        id=str(doc["_id"]),
        source=doc["source"],
        url=redact_feed_url(doc["url"]),
        format=doc.get("format"),
        mode=doc.get("mode") or "merge",
        interval_minutes=int(doc.get("interval_minutes") or 60),
        enabled=doc.get("enabled", True),
        auth_header_name=doc.get("auth_header_name") if doc.get("auth_header_value") else None,
        auth_set=bool(doc.get("auth_header_value")),
        last_run_at=doc.get("last_run_at"),
        last_status=doc.get("last_status"),
        last_error_kind=doc.get("last_error_kind"),
        last_error=doc.get("last_error"),
        last_result=InventoryListSourceResult(**last) if isinstance(last, dict) else None,
        next_run_at=next_run_at(doc),
        created_at=doc["created_at"],
        updated_at=doc.get("updated_at") or doc["created_at"],
    )


def _header(doc: dict[str, Any]) -> Header:
    value = doc.get("auth_header_value")
    if not value:
        return None
    return (doc.get("auth_header_name") or "Authorization", value)


async def _default_audit() -> Any:
    from app.services.audit_service import get_audit_service

    return await get_audit_service()


async def _notify_failed(source: str, error: str) -> None:
    try:
        from app.services.notification_service import get_notification_service

        await get_notification_service().notify_sync_failed(job_name=f"inventory_list:{source}", error=error)
    except Exception:  # noqa: BLE001 - notifications are fire-and-forget
        pass


class InventoryListSourceService:
    def __init__(
        self,
        repository: InventoryListSourceRepository,
        systems: InventorySystemService | None = None,
        *,
        fetcher: Fetcher = fetch_list,
        audit_factory: Callable[[], Awaitable[Any]] | None = _default_audit,
        notify_failed: Callable[[str, str], Awaitable[None]] = _notify_failed,
    ) -> None:
        self.repository = repository
        self._systems = systems
        self.fetcher = fetcher
        self.audit_factory = audit_factory
        self.notify_failed = notify_failed
        self._locks: dict[str, asyncio.Lock] = {}

    @property
    def systems(self) -> InventorySystemService:
        return self._systems or get_inventory_system_service()

    # ------------------------------------------------------------ CRUD

    async def list_sources(self) -> InventoryListSourceListResponse:
        return InventoryListSourceListResponse(
            items=[_response(doc) for doc in await self.repository.list_all()],
            allow_private_hosts=settings.inventory_list_sources_allow_private_hosts,
        )

    async def _checked(self, url: str, *, with_credential: bool) -> str:
        url = check_url(url, with_credential=with_credential)
        if not await _host_allowed(url):
            raise ValueError(_NOT_PUBLIC)
        return url

    async def create_source(self, payload: InventoryListSourceCreateRequest) -> InventoryListSourceResponse:
        """Add a source. Raises ``ValueError`` (bad URL, too many) or ``ListSourceTaken``."""
        if await self.repository.count() >= MAX_LIST_SOURCES:
            raise ValueError(f"At most {MAX_LIST_SOURCES} list sources.")
        credential = (payload.auth_header_value or "").strip()
        url = await self._checked(payload.url, with_credential=bool(credential))
        data: dict[str, Any] = {
            "source": payload.source, "url": url, "format": payload.format, "mode": payload.mode,
            "interval_minutes": payload.interval_minutes, "enabled": payload.enabled,
            "auth_header_name": (payload.auth_header_name or "Authorization") if credential else None,
            "auth_header_value": credential or None,
        }
        return _response(await self.repository.insert(str(uuid4()), data))

    async def update_source(self, source_id: str, payload: InventoryListSourceUpdateRequest) -> InventoryListSourceResponse | None:
        existing = await self.repository.get(source_id)
        if existing is None:
            return None
        sent = payload.model_fields_set
        fields: dict[str, Any] = {}
        for key in ("source", "mode", "interval_minutes", "enabled"):
            value = getattr(payload, key)
            if key in sent and value is not None and value != existing.get(key):
                fields[key] = value
        if "format" in sent and payload.format != existing.get("format"):
            fields["format"] = payload.format
        credential = existing.get("auth_header_value")
        if "auth_header_value" in sent and payload.auth_header_value is not None:
            credential = payload.auth_header_value.strip() or None
            fields["auth_header_value"] = credential
        if "auth_header_name" in sent and payload.auth_header_name:
            fields["auth_header_name"] = payload.auth_header_name
        if credential and not (fields.get("auth_header_name") or existing.get("auth_header_name")):
            fields["auth_header_name"] = "Authorization"
        if not credential:
            fields["auth_header_name"] = None
        url = existing["url"]
        if "url" in sent and payload.url is not None and payload.url.strip() != url:
            url = await self._checked(payload.url, with_credential=bool(credential))
            fields["url"] = url
        elif credential and not existing.get("auth_header_value"):
            check_url(url, with_credential=True)  # a credential added to an http URL
        fields = {k: v for k, v in fields.items() if existing.get(k) != v}
        if not fields:
            return _response(existing)
        updated = await self.repository.update(source_id, fields)
        return _response(updated) if updated else None

    async def delete_source(self, source_id: str) -> InventoryListSourceResponse | None:
        """Remove a source. Its systems stay, still naming it, until a list or someone changes them."""
        deleted = await self.repository.delete(source_id)
        self._locks.pop(source_id, None)
        return _response(deleted) if deleted else None

    # ------------------------------------------------------------ fetching

    async def pull(
        self, source_id: str, *, dry_run: bool = False, force: bool = False, scheduled: bool = False,
    ) -> InventoryListSourcePullResponse | None:
        """Fetch a source and apply it. A failure applies nothing and is kept on the source (dry runs keep nothing)."""
        lock = self._locks.setdefault(source_id, asyncio.Lock())
        async with lock:
            doc = await self.repository.get(source_id)
            if doc is None:
                return None
            result: InventorySystemImportResponse | None = None
            error_kind: str | None = None
            error: str | None = None
            try:
                content = await self.fetcher(doc["url"], _header(doc))
                parsed = parse_system_list(content, doc.get("format"))
                result = await self.systems.apply_list(
                    parsed, source=doc["source"], mode=doc.get("mode") or "merge", dry_run=dry_run, force=force,
                )
            except ListFetchError as exc:
                error_kind, error = exc.kind, exc.message
            except ListError as exc:
                error_kind, error = "invalid_list", str(exc)
            except ListTooDestructive as exc:
                error_kind, error = "too_destructive", str(exc)
            except Exception as exc:  # noqa: BLE001 - one source must not stop the others
                log.exception("inventory_list_source.pull_failed", source=doc["source"])
                error_kind, error = "internal", f"The fetch failed ({type(exc).__name__})."
            if error:
                error = error[:_ERROR_TEXT_LIMIT]
            if dry_run:
                return InventoryListSourcePullResponse(
                    ok=error is None, error_kind=error_kind, error=error, result=result, source=_response(doc),
                )

            previous = doc.get("last_status")
            fields: dict[str, Any] = {
                "last_run_at": datetime.now(tz=UTC),
                "last_status": "error" if error else "ok",
                "last_error_kind": error_kind,
                "last_error": error,
            }
            if result is not None:
                fields["last_result"] = _result(result)
            updated = await self.repository.update(source_id, fields, touch=False) or {**doc, **fields}
            changed = result is not None and (
                result.created_count or result.updated_count or result.retired_count or result.restored_count
            )
            log.info(
                "inventory_list_source.pulled", source=doc["source"], scheduled=scheduled, ok=error is None,
                error_kind=error_kind, **(_result(result) if result else {}),
            )
            first_failure = error is not None and previous != "error"
            if not scheduled or changed or first_failure:
                await self._audit(doc, result, error, scheduled)
            if scheduled and first_failure:
                await self.notify_failed(doc["source"], error or "")
            return InventoryListSourcePullResponse(
                ok=error is None, error_kind=error_kind, error=error, result=result, source=_response(updated),
            )

    async def _audit(
        self, doc: dict[str, Any], result: InventorySystemImportResponse | None, error: str | None, scheduled: bool,
    ) -> None:
        if self.audit_factory is None:
            return
        try:
            audit = await self.audit_factory()
            await audit.record_event(
                "inventory_list_pulled",
                status="failed" if error else "completed",
                metadata={"label": "Server list fetched", "source": doc["source"], "scheduled": scheduled,
                          "url": redact_feed_url(doc["url"])},
                result=_result(result) if result else None,
                error=error,
            )
        except Exception as exc:  # noqa: BLE001 - the fetch already happened
            log.warning("inventory_list_source.audit_failed", source=doc["source"], error=str(exc))

    async def pull_due(self, now: datetime | None = None) -> int:
        """Fetch every switched-on source whose interval has passed. Returns how many ran."""
        now = now or datetime.now(tz=UTC)
        ran = 0
        for doc in await self.repository.list_all():
            due = next_run_at(doc)
            if due is None:
                continue
            if due.tzinfo is None:
                due = due.replace(tzinfo=UTC)
            if due <= now:
                await self.pull(str(doc["_id"]), scheduled=True)
                ran += 1
        return ran


_service: InventoryListSourceService | None = None


async def get_inventory_list_source_service() -> InventoryListSourceService:
    global _service
    if _service is None:
        _service = InventoryListSourceService(await InventoryListSourceRepository.create())
    return _service
