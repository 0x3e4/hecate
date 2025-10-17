from __future__ import annotations

from typing import Any

from pymongo import TEXT

from app.repositories.cpe_repository import CPERepository
from app.schemas.cpe import CPEEntry, CPEQuery, CPEQueryResponse, CPEValueListResponse


class CPEService:
    def __init__(self, repository: CPERepository) -> None:
        self.repository = repository

    async def search(self, query: CPEQuery) -> CPEQueryResponse:
        mongo_filter: dict[str, Any] = {}
        if query.vendor:
            mongo_filter["vendor"] = query.vendor
        if query.product:
            mongo_filter["product"] = query.product
        if query.keyword:
            mongo_filter["$text"] = {"$search": query.keyword}

        cursor = self.repository.collection.find(mongo_filter).sort("lastModified", -1)
        total = await self.repository.collection.count_documents(mongo_filter)
        items_raw = await cursor.skip(query.offset).limit(query.limit).to_list(length=query.limit)
        items = [CPEEntry.model_validate(item) for item in items_raw]
        return CPEQueryResponse(total=total, items=items)

    async def get(self, cpe_name: str) -> CPEEntry | None:
        document = await self.repository.collection.find_one({"cpeName": cpe_name})
        if not document:
            return None
        return CPEEntry.model_validate(document)

    async def list_vendors(self, keyword: str | None, limit: int, offset: int) -> CPEValueListResponse:
        total, items = await self.repository.distinct_vendors(keyword, limit, offset)
        return CPEValueListResponse(total=total, items=items)

    async def list_products(
        self,
        vendors: list[str] | None,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> CPEValueListResponse:
        total, items = await self.repository.distinct_products(vendors, keyword, limit, offset)
        return CPEValueListResponse(total=total, items=items)


async def get_cpe_service() -> CPEService:
    repository = await CPERepository.create()
    await repository.collection.create_index([("title", TEXT), ("vendor", TEXT), ("product", TEXT)])
    return CPEService(repository)
