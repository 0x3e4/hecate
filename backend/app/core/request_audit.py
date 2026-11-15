"""Central audit trail for every write that reaches the REST API.

A pure ASGI middleware around ``/api/v1``: it binds the request's
``AuthContext`` (so gates, services and ``AuditService.record_event`` know the
actor) and, once the response has gone out, records each ``POST`` / ``PUT`` /
``PATCH`` / ``DELETE`` (allowed or refused) as an ``api_request`` audit event:
actor, method, route template, path parameters, status, client IP.

Covered by default: a new route needs no code here. Left out:

* the POST routes that only read (``READ_POST_ROUTES``), unless the request
  flagged ``force_audit`` (a lookup that fetched upstream);
* successful requests whose handler already wrote a richer event of its own
  (API tokens, advisory feeds, saved searches, sign-out): ``record_event``
  stamps the actor onto those, so a second line would only repeat them;
* requests no route matched (scanners probing for paths).

The password probes of the unlock dialogs (``/status/system-auth``,
``/status/ai-auth``) are recorded as ``auth_password_check`` events instead.

No request body is stored, and no header. Path parameters are masked with
``mask_url_credentials`` (target ids are URLs). The write happens in a task
after the response, and a failure is only logged: auditing never fails or
slows down the request it describes.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable

import structlog
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.auth_context import (
    MUTATING_METHODS,
    PASSWORD_CHECK_ROUTES,
    READ_POST_ROUTES,
    AuthContext,
    bind_auth_context,
    get_auth_context,
    route_template,
    strip_api_prefix,
    unbind_auth_context,
)
from app.core.config import settings
from app.utils.request import get_security_client_ip
from app.utils.strings import mask_url_credentials

log = structlog.get_logger()

AUDIT_JOB_NAME = "api_request"
PASSWORD_CHECK_JOB_NAME = "auth_password_check"
_MAX_PARAM_LENGTH = 300
_MAX_ERROR_BODY = 4096

AuditSink = Callable[..., Awaitable[None]]


async def _default_sink(job_name: str, **kwargs: Any) -> None:
    from app.services.audit_service import get_audit_service

    service = await get_audit_service()
    await service.record_event(job_name, **kwargs)


# Tests replace this; production writes through AuditService.
audit_sink: AuditSink = _default_sink
# Tests set this to await the write before the request returns.
write_inline = False
_pending: set[asyncio.Task] = set()


def _clean_param(value: Any) -> str:
    text = mask_url_credentials(str(value)) or ""
    return text[:_MAX_PARAM_LENGTH]


def _error_detail(body: bytes) -> str | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, str):
        return (mask_url_credentials(detail) or "")[:300]
    return None


def build_audit_event(
    *,
    scope: Scope,
    ctx: AuthContext,
    status: int,
    error_body: bytes,
    started_at: datetime,
) -> tuple[str, dict[str, Any]] | None:
    """The (job name, record_event kwargs) for a finished request, or ``None`` to skip it."""
    method = scope.get("method", "")
    if method not in MUTATING_METHODS:
        return None
    relative = ctx.route
    if relative is None:
        template = route_template(scope)
        if template is None:
            return None
        relative = strip_api_prefix(template)
    if relative in READ_POST_ROUTES and not ctx.force_audit:
        return None

    outcome = "success" if status < 400 else ("denied" if status in (401, 403, 429) else "error")
    request = Request(scope)
    metadata: dict[str, Any] = {
        "method": method,
        "route": relative,
        "statusCode": status,
        "outcome": outcome,
        "actor": ctx.actor(),
        "clientIp": get_security_client_ip(request) or None,
    }
    params = scope.get("path_params") or {}
    if params:
        metadata["pathParams"] = {str(k): _clean_param(v) for k, v in params.items()}
    error = _error_detail(error_body) if status >= 400 and error_body else None

    if relative in PASSWORD_CHECK_ROUTES:
        metadata["label"] = f"Password check ({PASSWORD_CHECK_ROUTES[relative]})"
        job_name = PASSWORD_CHECK_JOB_NAME
    else:
        if ctx.explicit_audit and status < 400:
            return None
        metadata["label"] = f"{method} {relative}"
        job_name = AUDIT_JOB_NAME
    metadata = {k: v for k, v in metadata.items() if v is not None}
    return job_name, {
        "status": "completed" if status < 400 else "failed",
        "metadata": metadata,
        "error": error,
        "started_at": started_at,
        "finished_at": datetime.now(UTC),
    }


async def _write(job_name: str, kwargs: dict[str, Any]) -> None:
    try:
        await audit_sink(job_name, **kwargs)
    except Exception as exc:  # noqa: BLE001 - auditing must never break a request
        log.warning("audit.request_record_failed", job=job_name, error=repr(exc))


class RequestAuditMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        prefix = settings.api_prefix
        if scope["type"] != "http" or not (scope.get("path") or "").startswith(prefix + "/"):
            await self.app(scope, receive, send)
            return

        ctx = AuthContext()
        scope.setdefault("state", {})["hecate_auth"] = ctx
        token = bind_auth_context(ctx)
        mutating = scope.get("method") in MUTATING_METHODS
        started_at = datetime.now(UTC)
        status_holder = {"status": 500}
        error_chunks: list[bytes] = []

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message["status"])
            elif (
                mutating
                and message["type"] == "http.response.body"
                and status_holder["status"] >= 400
                and sum(len(c) for c in error_chunks) < _MAX_ERROR_BODY
            ):
                error_chunks.append(message.get("body", b"")[:_MAX_ERROR_BODY])
            await send(message)

        try:
            if mutating:
                # Resolve the session up front so even a request refused before any
                # gate ran (validation error, read gate) is attributed.
                try:
                    await get_auth_context(Request(scope, receive))
                except Exception as exc:  # noqa: BLE001
                    log.warning("audit.actor_resolution_failed", error=repr(exc))
            await self.app(scope, receive, send_wrapper)
        finally:
            unbind_auth_context(token)
            if mutating:
                try:
                    event = build_audit_event(
                        scope=scope,
                        ctx=ctx,
                        status=status_holder["status"],
                        error_body=b"".join(error_chunks),
                        started_at=started_at,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("audit.request_event_failed", error=repr(exc))
                    event = None
                if event is not None and write_inline:
                    await _write(*event)
                elif event is not None:
                    task = asyncio.create_task(_write(*event))
                    _pending.add(task)
                    task.add_done_callback(_pending.discard)


async def drain_pending_audit_writes() -> None:
    """Wait for queued audit writes (tests, shutdown)."""
    while _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)
