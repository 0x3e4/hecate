from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any
from uuid import uuid4

import structlog

from app.repositories.inventory_repository import InventoryRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.inventory import (
    AffectedInventoryItem,
    AffectedVulnerabilityItem,
    InventoryItemCreateRequest,
    InventoryItemResponse,
    InventoryItemUpdateRequest,
)
from app.services.inventory_matcher import (
    InventoryKey,
    items_for_vuln,
    vulns_for_item,
)

log = structlog.get_logger()


_CACHE_TTL_SECONDS = 30.0


class InventoryCache:
    """Process-local cache of the full inventory list.

    The per-CVE affected-inventory lookup runs on every vulnerability detail
    load, so we amortize the MongoDB read with a short TTL. Mutation paths
    (create/update/delete) invalidate the cache directly, so the TTL only
    bounds the staleness when another process updates inventory.
    """

    def __init__(self, ttl_seconds: float = _CACHE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._expires_at: float = 0.0
        self._items: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def get(self, repo: InventoryRepository) -> list[dict[str, Any]]:
        now = time.monotonic()
        if now < self._expires_at:
            return self._items
        async with self._lock:
            if time.monotonic() < self._expires_at:
                return self._items
            items = await repo.list_all()
            self._items = items
            self._expires_at = time.monotonic() + self._ttl
            return items

    def invalidate(self) -> None:
        self._expires_at = 0.0
        self._items = []


_inventory_cache = InventoryCache()


def _map_item(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(doc["_id"]),
        "name": doc.get("name", ""),
        "vendorSlug": doc.get("vendor_slug", ""),
        "productSlug": doc.get("product_slug", ""),
        "vendorName": doc.get("vendor_name"),
        "productName": doc.get("product_name"),
        "version": doc.get("version", ""),
        "deployment": doc.get("deployment", "onprem"),
        "environment": doc.get("environment", "prod"),
        "instanceCount": int(doc.get("instance_count", 1) or 1),
        "owner": doc.get("owner"),
        "notes": doc.get("notes"),
        "createdAt": doc.get("created_at"),
        "updatedAt": doc.get("updated_at"),
    }


def to_affected_inventory_item(doc: dict[str, Any]) -> AffectedInventoryItem:
    return AffectedInventoryItem.model_validate(
        {
            "id": str(doc["_id"]) if "_id" in doc else str(doc.get("id", "")),
            "name": doc.get("name", ""),
            "vendorName": doc.get("vendor_name") or doc.get("vendorName"),
            "productName": doc.get("product_name") or doc.get("productName"),
            "version": doc.get("version", ""),
            "deployment": doc.get("deployment", "onprem"),
            "environment": doc.get("environment", "prod"),
            "instanceCount": int(doc.get("instance_count", doc.get("instanceCount", 1)) or 1),
            "owner": doc.get("owner"),
        }
    )


class InventoryService:
    """High-level CRUD + matching operations over ``InventoryRepository``.

    The service owns the process-local cache so endpoints and notification
    evaluators can share a single hot copy of the inventory list.
    """

    def __init__(self, repo: InventoryRepository | None = None) -> None:
        self._repo = repo

    async def _get_repo(self) -> InventoryRepository:
        if self._repo is None:
            self._repo = await InventoryRepository.create()
        return self._repo

    # --- CRUD ---

    async def list_items(self) -> list[InventoryItemResponse]:
        repo = await self._get_repo()
        docs = await repo.list_all()
        return [InventoryItemResponse.model_validate(_map_item(d)) for d in docs]

    async def get_item(self, item_id: str) -> InventoryItemResponse | None:
        repo = await self._get_repo()
        doc = await repo.get(item_id)
        if doc is None:
            return None
        return InventoryItemResponse.model_validate(_map_item(doc))

    async def create_item(
        self, payload: InventoryItemCreateRequest
    ) -> InventoryItemResponse:
        repo = await self._get_repo()
        item_id = str(uuid4())
        data = {
            "name": payload.name.strip(),
            "vendor_slug": payload.vendor_slug.strip().lower(),
            "product_slug": payload.product_slug.strip().lower(),
            "vendor_name": payload.vendor_name,
            "product_name": payload.product_name,
            "version": payload.version.strip(),
            "deployment": payload.deployment,
            "environment": payload.environment,
            "instance_count": payload.instance_count,
            "owner": payload.owner,
            "notes": payload.notes,
        }
        doc = await repo.insert(item_id, data)
        _inventory_cache.invalidate()
        return InventoryItemResponse.model_validate(_map_item(doc))

    async def update_item(
        self, item_id: str, payload: InventoryItemUpdateRequest
    ) -> InventoryItemResponse | None:
        repo = await self._get_repo()
        existing = await repo.get(item_id)
        if existing is None:
            return None

        updates: dict[str, Any] = {}
        if payload.name is not None:
            updates["name"] = payload.name.strip()
        if payload.vendor_slug is not None:
            updates["vendor_slug"] = payload.vendor_slug.strip().lower()
        if payload.product_slug is not None:
            updates["product_slug"] = payload.product_slug.strip().lower()
        if payload.vendor_name is not None:
            updates["vendor_name"] = payload.vendor_name
        if payload.product_name is not None:
            updates["product_name"] = payload.product_name
        if payload.version is not None:
            updates["version"] = payload.version.strip()
        if payload.deployment is not None:
            updates["deployment"] = payload.deployment
        if payload.environment is not None:
            updates["environment"] = payload.environment
        if payload.instance_count is not None:
            updates["instance_count"] = payload.instance_count
        if payload.owner is not None:
            updates["owner"] = payload.owner
        if payload.notes is not None:
            updates["notes"] = payload.notes

        if updates:
            await repo.update(item_id, updates)
            _inventory_cache.invalidate()

        doc = await repo.get(item_id)
        if doc is None:
            return None
        return InventoryItemResponse.model_validate(_map_item(doc))

    async def delete_item(self, item_id: str) -> bool:
        repo = await self._get_repo()
        deleted = await repo.delete(item_id)
        if deleted:
            _inventory_cache.invalidate()
        return deleted

    # --- Matching ---

    async def list_all_cached(self) -> list[dict[str, Any]]:
        """Return the cached raw inventory list. Use for CVE → inventory lookups."""
        repo = await self._get_repo()
        return await _inventory_cache.get(repo)

    def invalidate_cache(self) -> None:
        _inventory_cache.invalidate()

    async def affected_inventory_for_vuln(
        self, vuln: Any
    ) -> list[AffectedInventoryItem]:
        """Resolve the inventory items affected by a vulnerability document."""
        raw_items = await self.list_all_cached()
        if not raw_items:
            return []
        matches = items_for_vuln(vuln, raw_items)
        return [to_affected_inventory_item(m) for m in matches]

    async def vulns_affecting_item(
        self,
        item_id: str,
        *,
        limit: int = 200,
    ) -> list[AffectedVulnerabilityItem]:
        """Return the vulnerabilities currently affecting the inventory item."""
        repo = await self._get_repo()
        doc = await repo.get(item_id)
        if doc is None:
            return []

        vuln_repo = await VulnerabilityRepository.create()
        key = InventoryKey(
            vendor_slug=str(doc.get("vendor_slug") or ""),
            product_slug=str(doc.get("product_slug") or ""),
            version=str(doc.get("version") or ""),
        )
        if not key.vendor_slug or not key.product_slug or not key.version:
            return []

        hits = await vulns_for_item(vuln_repo, key, limit=limit)

        results: list[AffectedVulnerabilityItem] = []
        for h in hits:
            cvss = h.get("cvss") or {}
            if not isinstance(cvss, dict):
                cvss = {}
            results.append(
                AffectedVulnerabilityItem.model_validate(
                    {
                        "vulnId": h.get("vuln_id") or h.get("_id"),
                        "title": h.get("title"),
                        "severity": cvss.get("severity"),
                        "cvssScore": cvss.get("base_score"),
                        "epssScore": h.get("epss_score"),
                        "exploited": h.get("exploited"),
                        "published": h.get("published"),
                    }
                )
            )

        # Sort by severity rank then CVSS score (descending).
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4}
        results.sort(
            key=lambda r: (
                severity_rank.get((r.severity or "").lower(), 5),
                -(r.cvss_score or 0.0),
            )
        )
        return results

    async def new_vulns_for_watch_rule(
        self,
        *,
        since: datetime,
        limit: int = 100,
    ) -> list[tuple[dict[str, Any], list[AffectedInventoryItem]]]:
        """Return vulns published since ``since`` that affect any inventory item.

        Used by the notification watch-rule evaluator (``inventory`` rule type).
        Queries MongoDB directly with the compound ``(vendor_slugs, product_slugs)``
        index plus a ``published`` lower-bound filter, then runs the CPE matcher
        against the cached inventory list to drop version mismatches. Returns a
        list of ``(vuln_doc, affected_items)`` pairs so the caller can render
        both the CVE info and the per-vuln environment impact in notifications.
        """
        raw_inventory = await self.list_all_cached()
        if not raw_inventory:
            return []

        pairs_vendor = sorted({
            (str(i.get("vendor_slug") or "").lower())
            for i in raw_inventory
            if i.get("vendor_slug")
        })
        pairs_product = sorted({
            (str(i.get("product_slug") or "").lower())
            for i in raw_inventory
            if i.get("product_slug")
        })
        if not pairs_vendor or not pairs_product:
            return []

        vuln_repo = await VulnerabilityRepository.create()
        projection = {
            "_id": 1,
            "vuln_id": 1,
            "title": 1,
            "cvss": 1,
            "epss_score": 1,
            "exploited": 1,
            "published": 1,
            "cpe_configurations": 1,
            "cpes": 1,
            "vendor_slugs": 1,
            "product_slugs": 1,
            "vendors": 1,
            "products": 1,
            "impacted_products": 1,
            "impactedProducts": 1,
            "summary": 1,
        }
        query = {
            "vendor_slugs": {"$in": pairs_vendor},
            "product_slugs": {"$in": pairs_product},
            "published": {"$gte": since},
        }

        cursor = vuln_repo.collection.find(query, projection=projection).sort(
            "published", -1
        )
        if limit:
            cursor = cursor.limit(limit * 4)  # over-fetch; filter drops some

        hits: list[tuple[dict[str, Any], list[AffectedInventoryItem]]] = []
        async for doc in cursor:
            affected = items_for_vuln(doc, raw_inventory)
            if not affected:
                continue
            hits.append((doc, [to_affected_inventory_item(a) for a in affected]))
            if len(hits) >= limit:
                break
        return hits


_inventory_service_singleton: InventoryService | None = None


async def get_inventory_service() -> InventoryService:
    global _inventory_service_singleton
    if _inventory_service_singleton is None:
        _inventory_service_singleton = InventoryService()
    return _inventory_service_singleton
