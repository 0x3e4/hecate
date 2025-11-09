from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, UpdateOne
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.utils.strings import build_search_tokens, normalize_key, slugify


class AssetRepository:
    """
    Stores normalized vendor, product, and version metadata for asset filtering.
    """

    def __init__(
        self,
        *,
        vendors: AsyncIOMotorCollection,
        products: AsyncIOMotorCollection,
        versions: AsyncIOMotorCollection,
    ) -> None:
        self.vendors = vendors
        self.products = products
        self.versions = versions

    @classmethod
    async def create(cls) -> "AssetRepository":
        database = await get_database()
        vendor_collection = database[settings.mongo_asset_vendors_collection]
        product_collection = database[settings.mongo_asset_products_collection]
        version_collection = database[settings.mongo_asset_versions_collection]

        await vendor_collection.create_index([("displayName", ASCENDING)])
        await vendor_collection.create_index([("searchTokens", ASCENDING)])

        await product_collection.create_index([("displayName", ASCENDING)])
        await product_collection.create_index([("vendorSlugs", ASCENDING)])
        await product_collection.create_index([("searchTokens", ASCENDING)])

        await version_collection.create_index([("productSlug", ASCENDING), ("displayName", ASCENDING)])

        return cls(vendors=vendor_collection, products=product_collection, versions=version_collection)

    async def upsert_vendor(
        self,
        name: str,
        *,
        aliases: Iterable[str] = (),
        sources: Iterable[str] = (),
    ) -> str:
        slug = slugify(name)
        now = datetime.now(tz=UTC)
        alias_set = {name.strip()} | {alias.strip() for alias in aliases if alias}
        tokens = build_search_tokens(alias_set)
        update = {
            "$set": {
                "displayName": name.strip(),
                "normalizedKey": normalize_key(name),
                "searchTokens": tokens,
                "updatedAt": now,
            },
            "$addToSet": {
                "aliases": {"$each": sorted({alias for alias in alias_set if alias})},
                "sources": {"$each": sorted({source for source in sources if source})},
            },
            "$setOnInsert": {"createdAt": now},
        }
        try:
            await self.vendors.update_one({"_id": slug}, update, upsert=True)
        except PyMongoError as exc:
            raise RuntimeError(f"Failed to upsert vendor '{name}': {exc}") from exc
        return slug

    async def upsert_product(
        self,
        name: str,
        *,
        vendor_slugs: Iterable[str],
        aliases: Iterable[str] = (),
        cpe_names: Iterable[str] = (),
        sources: Iterable[str] = (),
    ) -> str:
        slug = slugify(name)
        now = datetime.now(tz=UTC)
        alias_set = {name.strip()} | {alias.strip() for alias in aliases if alias}
        alias_set |= {cpe.replace("_", " ").strip() for cpe in cpe_names if cpe}
        tokens = build_search_tokens(alias_set)
        update = {
            "$set": {
                "displayName": name.strip(),
                "normalizedKey": normalize_key(name),
                "searchTokens": tokens,
                "updatedAt": now,
            },
            "$addToSet": {
                "aliases": {"$each": sorted({alias for alias in alias_set if alias})},
                "vendorSlugs": {"$each": sorted({slug for slug in vendor_slugs if slug})},
                "sources": {"$each": sorted({source for source in sources if source})},
            },
            "$setOnInsert": {"createdAt": now},
        }
        if cpe_names:
            update["$addToSet"]["cpeNames"] = {"$each": sorted({name for name in cpe_names if name})}
        try:
            await self.products.update_one({"_id": slug}, update, upsert=True)
        except PyMongoError as exc:
            raise RuntimeError(f"Failed to upsert product '{name}': {exc}") from exc
        return slug

    async def upsert_versions(
        self,
        product_slug: str,
        *,
        versions: Iterable[str],
        sources: Iterable[str] = (),
    ) -> list[str]:
        ops: list[UpdateOne] = []
        now = datetime.now(tz=UTC)
        version_ids: list[str] = []
        source_values = sorted({source for source in sources if source})
        for version in versions:
            cleaned = version.strip()
            if not cleaned:
                continue
            version_slug = slugify(cleaned)
            document_id = f"{product_slug}:{version_slug}"
            version_ids.append(document_id)
            update = {
                "$set": {
                    "productSlug": product_slug,
                    "displayName": cleaned,
                    "updatedAt": now,
                },
                "$addToSet": {"sources": {"$each": source_values}},
                "$setOnInsert": {"createdAt": now},
            }
            ops.append(UpdateOne({"_id": document_id}, update, upsert=True))

        if ops:
            try:
                await self.versions.bulk_write(ops, ordered=False)
            except PyMongoError as exc:
                raise RuntimeError(f"Failed to upsert product versions for '{product_slug}': {exc}") from exc

        return version_ids

    async def search_vendors(self, keyword: str | None, *, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        if keyword:
            regex = {"$regex": keyword, "$options": "i"}
            query["$or"] = [{"displayName": regex}, {"aliases": regex}]

        total = await self.vendors.count_documents(query)
        cursor = (
            self.vendors.find(query)
            .sort("displayName", ASCENDING)
            .skip(offset)
            .limit(limit)
        )
        items = await cursor.to_list(length=limit)
        return total, items

    async def search_products(
        self,
        *,
        vendor_slugs: Iterable[str] | None,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        vendor_list = [slug for slug in (vendor_slugs or []) if slug]
        if vendor_list:
            query["vendorSlugs"] = {"$in": vendor_list}
        if keyword:
            regex = {"$regex": keyword, "$options": "i"}
            query["$or"] = [{"displayName": regex}, {"aliases": regex}]

        total = await self.products.count_documents(query)
        cursor = (
            self.products.find(query)
            .sort("displayName", ASCENDING)
            .skip(offset)
            .limit(limit)
        )
        items = await cursor.to_list(length=limit)
        return total, items

    async def list_versions(
        self,
        *,
        product_slug: str,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {"productSlug": product_slug}
        if keyword:
            query["displayName"] = {"$regex": keyword, "$options": "i"}

        total = await self.versions.count_documents(query)
        cursor = (
            self.versions.find(query)
            .sort("displayName", ASCENDING)
            .skip(offset)
            .limit(limit)
        )
        items = await cursor.to_list(length=limit)
        return total, items

    async def find_versions_by_ids(self, identifiers: Iterable[str]) -> list[dict[str, Any]]:
        version_ids = [identifier for identifier in identifiers if identifier]
        if not version_ids:
            return []
        cursor = self.versions.find({"_id": {"$in": version_ids}})
        return await cursor.to_list(length=len(version_ids))

    async def find_vendors_by_slugs(self, slugs: Iterable[str]) -> list[dict[str, Any]]:
        slug_list = [slug for slug in slugs if slug]
        if not slug_list:
            return []
        cursor = self.vendors.find({"_id": {"$in": slug_list}})
        return await cursor.to_list(length=len(slug_list))

    async def sample_vendors(self, *, limit: int) -> list[dict[str, Any]]:
        # Use $sample directly for true random sampling from entire collection
        # Performance is acceptable for small sample sizes (6 items)
        pipeline = [
            {"$match": {"displayName": {"$nin": [None, "", "*"]}}},
            {"$sample": {"size": limit}},
        ]
        return await self.vendors.aggregate(pipeline).to_list(length=limit)

    async def sample_products(self, *, limit: int) -> list[dict[str, Any]]:
        # Use $sample directly for true random sampling from entire collection
        # Performance is acceptable for small sample sizes (6 items)
        pipeline = [
            {"$match": {"displayName": {"$nin": [None, "", "*"]}}},
            {"$sample": {"size": limit}},
        ]
        return await self.products.aggregate(pipeline).to_list(length=limit)
