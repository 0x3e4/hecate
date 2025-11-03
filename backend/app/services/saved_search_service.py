from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode

from bson import ObjectId

from app.repositories.saved_search_repository import SavedSearchRepository
from app.schemas.saved_search import SavedSearch, SavedSearchCreate


class SavedSearchService:
    """
    Business logic for managing saved vulnerability DQL searches.
    """

    async def list_saved_searches(self) -> list[SavedSearch]:
        repository = await SavedSearchRepository.create()
        documents = await repository.list_all()
        return [self._to_schema(doc) for doc in documents]

    async def get_saved_search(self, search_id: str) -> SavedSearch | None:
        repository = await SavedSearchRepository.create()
        document = await repository.get(search_id)
        if not document:
            return None
        return self._to_schema(document)

    async def create_saved_search(self, payload: SavedSearchCreate) -> SavedSearch:
        repository = await SavedSearchRepository.create()
        name = payload.name.strip()
        query_params, dql_query = self._normalize_query_params(
            payload.query_params,
            fallback_dql=payload.dql_query.strip() if payload.dql_query else None,
        )

        if not name:
            raise ValueError("Name must not be empty.")

        document = await repository.insert(name=name, query_params=query_params, dql_query=dql_query)
        return self._to_schema(document)

    async def delete_saved_search(self, search_id: str) -> bool:
        repository = await SavedSearchRepository.create()
        return await repository.delete(search_id)

    def _to_schema(self, document: dict[str, Any]) -> SavedSearch:
        query_params = document.get("queryParams") or ""
        dql_query = document.get("dqlQuery")
        if not query_params and dql_query:
            query_params = urlencode([("mode", "dql"), ("search", dql_query)], doseq=True)
        created_at = _normalize_datetime(
            document.get("createdAt") or document.get("created_at"),
            fallback=_object_id_time(document.get("_id")),
        )
        updated_at = _normalize_datetime(
            document.get("updatedAt") or document.get("updated_at"),
            fallback=created_at,
        )

        mapped = {
            "id": str(document.get("_id", "")),
            "name": document.get("name", ""),
            "query_params": query_params,
            "dql_query": dql_query,
            "created_at": created_at,
            "updated_at": updated_at,
        }
        return SavedSearch.model_validate(mapped)

    def _normalize_query_params(
        self,
        raw_params: str,
        *,
        fallback_dql: str | None,
    ) -> tuple[str, str | None]:
        cleaned = raw_params.strip().lstrip("?")
        if not cleaned:
            return "", None

        try:
            parsed: list[tuple[str, str]] = parse_qsl(cleaned, keep_blank_values=True)
        except ValueError:
            return cleaned, fallback_dql

        normalized = urlencode(parsed, doseq=True)
        mode = _extract_first(parsed, "mode")
        search_value = _extract_first(parsed, "search")
        dql_query = search_value if mode == "dql" and search_value else fallback_dql

        return normalized, dql_query


def _extract_first(pairs: Iterable[tuple[str, str]], target: str) -> str | None:
    for key, value in pairs:
        if key == target:
            return value
    return None


def _normalize_datetime(value: Any, *, fallback: datetime | None) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            dt = fallback or datetime.now(tz=UTC)
    else:
        dt = fallback or datetime.now(tz=UTC)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _object_id_time(value: Any) -> datetime:
    if isinstance(value, ObjectId):
        return value.generation_time.astimezone(UTC)
    return datetime.now(tz=UTC)


def get_saved_search_service() -> SavedSearchService:
    return SavedSearchService()
