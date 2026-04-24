"""Client for the deps.dev v3 Package API.

Used to enrich OSV MAL-* records whose upstream OSSF source publishes a
conservative `introduced: "0"` range (meaning "every published version is
suspect because the attacker owns the namespace"). For typosquat-style
malicious packages that's usually 1–5 versions, but `introduced: "0"`
surfaces as an unhelpful "all versions" chip in the UI. deps.dev gives us
the authoritative published-version list per ecosystem so we can replace
the blanket range with concrete values.

https://docs.deps.dev/api/v3/api/#packageservice_getpackage
"""

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


# OSV `affected[].package.ecosystem` → deps.dev system name. deps.dev uses
# uppercase system identifiers in the URL path. Ecosystems not in this map
# (Pub, Hex, GitHub Actions, etc.) aren't covered by deps.dev — the caller
# should skip them and leave the OSV record as-is.
_OSV_TO_DEPS_DEV_SYSTEM: dict[str, str] = {
    "npm": "NPM",
    "pypi": "PYPI",
    "maven": "MAVEN",
    "go": "GO",
    "nuget": "NUGET",
    "crates.io": "CARGO",
    "cargo": "CARGO",
}


def osv_to_deps_dev_system(osv_ecosystem: str | None) -> str | None:
    if not osv_ecosystem:
        return None
    return _OSV_TO_DEPS_DEV_SYSTEM.get(osv_ecosystem.lower())


class DepsDevClient:
    """Thin async wrapper around deps.dev's Package endpoint."""

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
        self.base_url = (base_url or settings.deps_dev_base_url).rstrip("/")
        timeout = timeout_seconds or settings.deps_dev_timeout_seconds
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
            settings.deps_dev_rate_limit_seconds
        )
        self._max_retries = (
            max_retries if max_retries is not None else settings.deps_dev_max_retries
        )
        self._retry_backoff = (
            retry_backoff
            if retry_backoff is not None
            else settings.deps_dev_retry_backoff_seconds
        )

    async def fetch_package_versions(
        self,
        *,
        system: str,
        name: str,
    ) -> list[str] | None:
        """Return the list of published versions for a package.

        - `system` is the deps.dev uppercase identifier (NPM / PYPI / …);
          callers convert via `osv_to_deps_dev_system()`.
        - `name` is passed literally except for URL-path encoding — deps.dev
          expects the raw package name, including the `@scope/name` form for
          scoped npm.
        - Returns `None` on 404 (unknown package), auth / transport error, or
          an unexpected payload shape. Returns an empty list only when the
          response literally had `versions: []` (shouldn't happen in practice).
        """
        mapped_system = system.upper()
        # quote w/ safe set preserves common name chars while encoding slashes
        # and '@' — deps.dev's path parsing requires the encoded form.
        quoted_name = quote(name, safe="")
        url = f"{self.base_url}/systems/{mapped_system}/packages/{quoted_name}"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="deps_dev_client",
            validate_json=True,
            context={"system": mapped_system, "package": name},
        )
        if response is None:
            return None
        if response.status_code == 404:
            log.debug("deps_dev_client.not_found", system=mapped_system, package=name)
            return None
        if response.status_code >= 400:
            log.warning(
                "deps_dev_client.http_error",
                status=response.status_code,
                system=mapped_system,
                package=name,
                body_preview=response.text[:200],
            )
            return None
        try:
            data = response.json()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "deps_dev_client.json_parse_failed",
                error=str(exc),
                system=mapped_system,
                package=name,
            )
            return None
        versions_raw: Any = data.get("versions") if isinstance(data, dict) else None
        if not isinstance(versions_raw, list):
            return None

        out: list[str] = []
        for v in versions_raw:
            if not isinstance(v, dict):
                continue
            key = v.get("versionKey")
            if isinstance(key, dict):
                version_str = key.get("version")
                if isinstance(version_str, str) and version_str.strip():
                    out.append(version_str.strip())
        return out

    async def close(self) -> None:
        await self._client.aclose()
