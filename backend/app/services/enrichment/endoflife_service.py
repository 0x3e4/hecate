from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from app.core.config import settings
from app.schemas.inventory import EolProductOption, EolStatusResponse
from app.services.enrichment.endoflife_client import EndOfLifeClient
from app.services.inventory_matcher import _compare_versions
from app.utils.strings import slugify

log = structlog.get_logger()


_STATUS_LABELS = {
    "active": "Active support",
    "security": "Security support",
    "eol": "End of life",
    "unknown": "Unknown",
}


class _TtlCache:
    """Minimal async-safe TTL cache keyed by an arbitrary string.

    Used for the (slow-changing) endoflife.date catalog and per-product
    responses. ``None`` is a cacheable value (a confirmed miss / fetch failure)
    so a flaky upstream doesn't get hammered on every request.
    """

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get_or_fetch(self, key: str, fetch):
        now = time.monotonic()
        entry = self._entries.get(key)
        if entry is not None and now < entry[0]:
            return entry[1]
        async with self._lock:
            entry = self._entries.get(key)
            now = time.monotonic()
            if entry is not None and now < entry[0]:
                return entry[1]
            value = await fetch()
            self._entries[key] = (time.monotonic() + self._ttl, value)
            return value

    def clear(self) -> None:
        self._entries.clear()


class EndOfLifeService:
    """Resolve inventory items to endoflife.date support / EOL status.

    Auto-matching is intentionally conservative (exact slug/alias intersection)
    so we never mislink a product. Everything is best-effort and cached for
    ``endoflife_cache_ttl_hours`` — EOL data changes ~daily.
    """

    def __init__(self, client: EndOfLifeClient | None = None) -> None:
        self._client = client or EndOfLifeClient()
        ttl = max(1, settings.endoflife_cache_ttl_hours) * 3600.0
        self._catalog_cache = _TtlCache(ttl)
        self._product_cache = _TtlCache(ttl)

    @property
    def enabled(self) -> bool:
        return settings.endoflife_enabled

    async def _catalog(self) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        data = await self._catalog_cache.get_or_fetch(
            "catalog", self._client.fetch_products
        )
        return data or []

    async def _product(self, name: str) -> dict[str, Any] | None:
        if not self.enabled or not name:
            return None
        key = name.strip().lower()
        return await self._product_cache.get_or_fetch(
            key, lambda: self._client.fetch_product(key)
        )

    async def list_products(self, search: str | None = None) -> list[EolProductOption]:
        catalog = await self._catalog()
        needle = (search or "").strip().lower()
        options: list[EolProductOption] = []
        for entry in catalog:
            name = str(entry.get("name") or "")
            label = str(entry.get("label") or name)
            if not name:
                continue
            aliases = [str(a) for a in (entry.get("aliases") or []) if isinstance(a, str)]
            if needle:
                haystack = " ".join([name, label, *aliases]).lower()
                if needle not in haystack:
                    continue
            options.append(
                EolProductOption(
                    name=name,
                    label=label,
                    category=entry.get("category"),
                    aliases=aliases,
                )
            )
        options.sort(key=lambda o: o.label.lower())
        return options

    async def resolve_product(
        self, product_slug: str | None, product_name: str | None = None
    ) -> str | None:
        """Best-effort auto-match: inventory product → endoflife.date product slug.

        Conservative exact-key intersection only (no fuzzy/substring matching).
        Returns the endoflife.date product ``name`` or ``None``.
        """
        if not self.enabled:
            return None
        item_keys = {
            slugify(product_slug or ""),
            slugify(product_name or ""),
            (product_slug or "").strip().lower(),
        }
        item_keys.discard("")
        if not item_keys:
            return None

        catalog = await self._catalog()
        # Pass 1: direct product-name match (strongest signal).
        for entry in catalog:
            name = str(entry.get("name") or "")
            if name and name.lower() in item_keys:
                return name
        # Pass 2: label / alias slug match.
        for entry in catalog:
            name = str(entry.get("name") or "")
            if not name:
                continue
            keys = {slugify(str(entry.get("label") or ""))}
            for alias in entry.get("aliases") or []:
                if isinstance(alias, str) and alias:
                    keys.add(alias.lower())
                    keys.add(slugify(alias))
            keys.discard("")
            if item_keys & keys:
                return name
        return None

    async def get_status(
        self, eol_product: str | None, version: str
    ) -> EolStatusResponse:
        if not eol_product:
            return EolStatusResponse(linked=False)
        product = await self._product(eol_product)
        if not product:
            return EolStatusResponse(linked=False)

        label = str(product.get("label") or eol_product)
        links = product.get("links") if isinstance(product.get("links"), dict) else {}
        product_link = links.get("html") if isinstance(links, dict) else None
        releases = [r for r in (product.get("releases") or []) if isinstance(r, dict)]

        release = _match_release(version, releases)
        # Overall-latest fallback when the version doesn't map to a known cycle
        # (endoflife lists releases newest-first).
        if release is None and releases:
            overall_latest = _release_latest(releases[0])
            return EolStatusResponse(
                linked=True,
                product=str(product.get("name") or eol_product),
                product_label=label,
                product_link=product_link,
                status="unknown",
                status_label=_STATUS_LABELS["unknown"],
                latest_version=overall_latest[0],
                latest_release_date=overall_latest[1],
                latest_link=overall_latest[2],
                is_outdated=_is_outdated(version, overall_latest[0]),
            )
        if release is None:
            return EolStatusResponse(
                linked=True,
                product=str(product.get("name") or eol_product),
                product_label=label,
                product_link=product_link,
                status="unknown",
                status_label=_STATUS_LABELS["unknown"],
            )

        status = _release_status(release)
        latest_name, latest_date, latest_link = _release_latest(release)
        return EolStatusResponse(
            linked=True,
            product=str(product.get("name") or eol_product),
            product_label=label,
            product_link=product_link,
            matched_cycle=str(release.get("name") or release.get("label") or ""),
            status=status,
            status_label=_STATUS_LABELS[status],
            release_date=_as_date(release.get("releaseDate")),
            eoas_date=_as_date(release.get("eoasFrom")),
            eol_date=_as_date(release.get("eolFrom")),
            is_lts=bool(release.get("isLts")),
            latest_version=latest_name,
            latest_release_date=latest_date,
            latest_link=latest_link,
            is_outdated=_is_outdated(version, latest_name),
        )


# --- pure helpers ---


def _as_date(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _match_release(version: str, releases: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the release whose ``name`` is the longest dotted-prefix of ``version``."""
    v = (version or "").strip()
    if not v:
        return None
    best: dict[str, Any] | None = None
    best_len = -1
    for rel in releases:
        name = str(rel.get("name") or "").strip()
        if not name:
            continue
        if v == name or v.startswith(name + "."):
            if len(name) > best_len:
                best = rel
                best_len = len(name)
    return best


def _release_latest(release: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    latest = release.get("latest")
    if isinstance(latest, dict):
        return (
            _as_date(latest.get("name")),
            _as_date(latest.get("date")),
            _as_date(latest.get("link")),
        )
    return (None, None, None)


def _release_status(release: dict[str, Any]) -> str:
    if release.get("isEol"):
        return "eol"
    if release.get("isEoas"):
        return "security"
    if release.get("isMaintained") or release.get("isEol") is False:
        return "active"
    return "unknown"


def _is_outdated(version: str, latest: str | None) -> bool:
    if not latest:
        return False
    cmp = _compare_versions(version, latest)
    return cmp is not None and cmp < 0


_endoflife_service_singleton: EndOfLifeService | None = None


def get_endoflife_service() -> EndOfLifeService:
    global _endoflife_service_singleton
    if _endoflife_service_singleton is None:
        _endoflife_service_singleton = EndOfLifeService()
    return _endoflife_service_singleton
