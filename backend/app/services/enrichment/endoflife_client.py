from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()


class EndOfLifeClient:
    """Client for the endoflife.date v1 API.

    Two endpoints are used:

    * ``GET /products`` — the full product catalog (``result`` is a list of
      ``{name, label, aliases, category, tags}``). There is no server-side
      search, so callers fetch once and filter locally.
    * ``GET /products/{name}`` — a single product with its ``releases`` array
      (each carries ``isEol`` / ``isEoas`` / ``isMaintained`` / ``eolFrom`` /
      ``eoasFrom`` / ``latest`` …) plus ``labels`` / ``links``.

    All methods are best-effort: they return ``None`` on failure so the caller
    can degrade gracefully (EOL data is enrichment, never load-bearing).
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int | None = None,
        retry_backoff: float | None = None,
    ) -> None:
        self.base_url = (base_url or settings.endoflife_base_url).rstrip("/")
        timeout = timeout_seconds or settings.endoflife_timeout_seconds
        headers = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/json",
        }
        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(
            settings.endoflife_rate_limit_seconds
        )
        self._max_retries = (
            max_retries if max_retries is not None else settings.endoflife_max_retries
        )
        self._retry_backoff = (
            retry_backoff
            if retry_backoff is not None
            else settings.endoflife_retry_backoff_seconds
        )

    async def fetch_products(self) -> list[dict[str, Any]] | None:
        """Return the product catalog (``result`` list) or ``None`` on failure."""
        url = f"{self.base_url}/products"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="endoflife_client",
            validate_json=True,
            context={"op": "fetch_products"},
        )
        if response is None:
            log.warning("endoflife_client.fetch_products_failed")
            return None
        try:
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            log.warning("endoflife_client.fetch_products_failed", error=str(exc))
            return None
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, list):
            return None
        return [entry for entry in result if isinstance(entry, dict)]

    async def fetch_product(self, name: str) -> dict[str, Any] | None:
        """Return a single product's ``result`` object or ``None`` (incl. 404)."""
        slug = quote(name.strip(), safe="")
        if not slug:
            return None
        url = f"{self.base_url}/products/{slug}"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="endoflife_client",
            validate_json=True,
            context={"op": "fetch_product", "product": name},
        )
        if response is None:
            log.warning("endoflife_client.fetch_product_failed", product=name)
            return None
        if response.status_code == 404:
            log.debug("endoflife_client.product_not_found", product=name)
            return None
        try:
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            log.warning("endoflife_client.fetch_product_failed", product=name, error=str(exc))
            return None
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            return None
        return result

    async def close(self) -> None:
        await self._client.aclose()
