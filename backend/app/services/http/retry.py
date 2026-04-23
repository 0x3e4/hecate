from __future__ import annotations

import asyncio
import json
from typing import Any, Mapping

import httpx
import structlog

from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int,
    backoff_base: float,
    log_prefix: str,
    params: Mapping[str, Any] | None = None,
    rate_limiter: AsyncRateLimiter | None = None,
    retry_on_5xx: bool = True,
    validate_json: bool = False,
    context: Mapping[str, Any] | None = None,
) -> httpx.Response | None:
    """Execute an HTTP request with exponential-backoff retries on transient errors.

    Retry semantics:
      * Any ``httpx.HTTPError`` (covers ``ReadTimeout``, ``ReadError``,
        ``ConnectTimeout``, ``ConnectError``, ``RemoteProtocolError``) is
        treated as transient and retried.
      * ``429 Too Many Requests`` is retried and honors the ``Retry-After``
        header (seconds, integer) when present; otherwise falls back to
        exponential backoff.
      * ``5xx`` responses are retried when ``retry_on_5xx`` is True.
      * All other ``4xx`` responses are returned as-is; the caller decides
        how to interpret them (404 = not found, 403 = auth issue, etc.).
      * When ``validate_json`` is True, the body of a ``2xx`` response is
        parsed via ``response.json()`` inside the retry loop. Truncated or
        malformed JSON (``json.JSONDecodeError``, ``httpx.DecodingError``)
        is treated as transient — upstream sometimes closes the TCP
        connection mid-stream but reports a successful status, leaving a
        body that cuts off mid-token.

    On exhaustion returns ``None``. The caller decides whether this is
    fail-hard (raise) or fail-soft (skip/return-sentinel).

    The delay between attempt ``n`` and ``n+1`` is
    ``backoff_base * (2 ** n)`` seconds. With ``max_retries=5`` and
    ``backoff_base=5.0`` the total wait before giving up is
    ``5 + 10 + 20 + 40 + 80 = 155`` seconds.
    """
    last_error_str: str | None = None
    log_context = dict(context or {})

    for attempt in range(max_retries + 1):
        try:
            if rate_limiter is not None:
                async with rate_limiter.slot():
                    response = await client.request(method, url, params=params)
            else:
                response = await client.request(method, url, params=params)
        except httpx.HTTPError as exc:
            last_error_str = str(exc) or exc.__class__.__name__
            if attempt < max_retries:
                delay = backoff_base * (2 ** attempt)
                log.warning(
                    f"{log_prefix}.request_failed_retrying",
                    error=last_error_str,
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    retry_in=delay,
                    **log_context,
                )
                await asyncio.sleep(delay)
                continue
            log.error(
                f"{log_prefix}.request_failed_exhausted",
                error=last_error_str,
                attempts=attempt + 1,
                **log_context,
            )
            return None

        status = response.status_code

        if status == 429:
            last_error_str = "429 Too Many Requests"
            if attempt < max_retries:
                delay = _retry_after_seconds(response) or backoff_base * (2 ** attempt)
                log.warning(
                    f"{log_prefix}.rate_limited_retrying",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    retry_in=delay,
                    **log_context,
                )
                await asyncio.sleep(delay)
                continue
            log.error(
                f"{log_prefix}.rate_limited_exhausted",
                attempts=attempt + 1,
                **log_context,
            )
            return response

        if retry_on_5xx and status >= 500:
            last_error_str = f"{status} {response.reason_phrase}"
            if attempt < max_retries:
                delay = backoff_base * (2 ** attempt)
                log.warning(
                    f"{log_prefix}.server_error_retrying",
                    status_code=status,
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    retry_in=delay,
                    **log_context,
                )
                await asyncio.sleep(delay)
                continue
            log.error(
                f"{log_prefix}.server_error_exhausted",
                status_code=status,
                attempts=attempt + 1,
                **log_context,
            )
            return response

        if validate_json and 200 <= status < 300:
            try:
                response.json()
            except (json.JSONDecodeError, httpx.DecodingError) as exc:
                last_error_str = f"{exc.__class__.__name__}: {exc}"
                if attempt < max_retries:
                    delay = backoff_base * (2 ** attempt)
                    log.warning(
                        f"{log_prefix}.response_decode_retrying",
                        error=last_error_str,
                        attempt=attempt + 1,
                        max_retries=max_retries,
                        retry_in=delay,
                        **log_context,
                    )
                    await asyncio.sleep(delay)
                    continue
                log.error(
                    f"{log_prefix}.response_decode_exhausted",
                    error=last_error_str,
                    attempts=attempt + 1,
                    **log_context,
                )
                return None

        return response

    return None


def _retry_after_seconds(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None
