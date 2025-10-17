import asyncio
from typing import Any

import structlog
from opensearchpy import OpenSearch, RequestError
from opensearchpy.exceptions import NotFoundError

from app.core.config import settings

_client: OpenSearch | None = None
log = structlog.get_logger()


def get_client() -> OpenSearch:
    global _client
    if _client is None:
        auth = None
        if settings.opensearch_username and settings.opensearch_password:
            auth = (settings.opensearch_username, settings.opensearch_password)

        _client = OpenSearch(
            hosts=[settings.opensearch_url],
            http_auth=auth,
            use_ssl=settings.opensearch_url.startswith("https"),
            verify_certs=settings.opensearch_url.startswith("https"),
        )
    return _client


def ensure_vulnerability_index(index_name: str) -> None:
    client = get_client()
    if client.indices.exists(index=index_name):
        return

    body: dict[str, Any] = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "cve_id": {"type": "keyword"},
                "source_id": {"type": "keyword"},
                "source": {"type": "keyword"},
                "title": {"type": "text", "analyzer": "english"},
                "summary": {"type": "text", "analyzer": "english"},
                "references": {"type": "keyword"},
                "cwes": {"type": "keyword"},
                "cpes": {"type": "keyword"},
                "aliases": {"type": "keyword"},
                "assigner": {"type": "keyword"},
                "exploited": {"type": "boolean"},
                "epss_score": {"type": "float"},
                "epss_percentile": {"type": "float"},
                "vendors": {"type": "keyword"},
                "products": {"type": "keyword"},
                "cvss": {
                    "properties": {
                        "version": {"type": "keyword"},
                        "base_score": {"type": "float"},
                        "vector": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                    }
                },
                "published": {"type": "date"},
                "modified": {"type": "date"},
                "ingested_at": {"type": "date"},
                "ai_assessment": {"type": "object", "enabled": False},
            }
        },
    }

    try:
        client.indices.create(index=index_name, body=body)
        log.info("opensearch.index_created", index=index_name)
    except RequestError as exc:
        log.warning("opensearch.index_create_failed", index=index_name, error=str(exc))


async def async_index_document(index: str, document_id: str, document: dict[str, Any]) -> None:
    client = get_client()
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: client.index(index=index, id=document_id, body=document, refresh="wait_for"),
    )


async def async_search(index: str, body: dict[str, Any]) -> dict[str, Any]:
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        return await loop.run_in_executor(
            None,
            lambda: client.search(index=index, body=body),
        )
    except NotFoundError:
        ensure_vulnerability_index(index)
        return {"hits": {"hits": [], "total": {"value": 0}}}


async def async_get(index: str, document_id: str) -> dict[str, Any] | None:
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        result = await loop.run_in_executor(
            None,
            lambda: client.get(index=index, id=document_id),
        )
        return result.get("_source")
    except NotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 - log and propagate None
        log.warning("opensearch.get_failed", index=index, id=document_id, error=str(exc))
        return None
