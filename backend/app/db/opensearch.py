import asyncio
from typing import Any

import structlog
from opensearchpy import OpenSearch, RequestError
from opensearchpy.exceptions import NotFoundError, OpenSearchException, ConnectionError as OSConnectionError

from app.core.config import settings

_client: OpenSearch | None = None
_opensearch_available: bool = True
log = structlog.get_logger()


def _mark_opensearch_available() -> None:
    global _opensearch_available
    if not _opensearch_available:
        log.info("opensearch.recovered")
    _opensearch_available = True


def _mark_opensearch_unavailable(
    *,
    error: Exception,
    operation: str,
    index: str | None = None,
    **extra: Any,
) -> None:
    global _opensearch_available
    if _opensearch_available:
        log.warning("opensearch.unavailable", operation=operation, index=index, error=str(error), **extra)
    _opensearch_available = False


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
    try:
        if client.indices.exists(index=index_name):
            _mark_opensearch_available()
            return
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="indices.exists", index=index_name)
        return

    body: dict[str, Any] = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.mapping.total_fields.limit": settings.opensearch_index_total_fields_limit,
        },
        "mappings": {
            "properties": {
                "vuln_id": {"type": "keyword"},
                "source_id": {"type": "keyword"},
                "source": {"type": "keyword"},
                "title": {"type": "text", "analyzer": "english"},
                "summary": {"type": "text", "analyzer": "english"},
                "references": {"type": "keyword"},
                "cwes": {"type": "keyword"},
                "cpes": {"type": "keyword"},
                "aliases": {"type": "keyword"},
                "rejected": {"type": "boolean"},
                "assigner": {"type": "keyword"},
                "exploited": {"type": "boolean"},
                "exploitation": {
                    "properties": {
                        "source": {"type": "keyword"},
                        "vendorProject": {"type": "keyword"},
                        "product": {"type": "keyword"},
                        "vulnerabilityName": {"type": "text", "analyzer": "english"},
                        "dateAdded": {"type": "date"},
                        "shortDescription": {"type": "text", "analyzer": "english"},
                        "requiredAction": {"type": "text", "analyzer": "english"},
                        "dueDate": {"type": "date"},
                        "knownRansomwareCampaignUse": {"type": "keyword"},
                        "notes": {"type": "text", "analyzer": "english"},
                        "catalogVersion": {"type": "keyword"},
                        "dateReleased": {"type": "date"},
                    }
                },
                "epss_score": {"type": "float"},
                "vendor_slugs": {"type": "keyword"},
                "product_slugs": {"type": "keyword"},
                "product_versions": {"type": "keyword"},
                "product_version_ids": {"type": "keyword"},
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
        _mark_opensearch_available()
    except (RequestError, OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="indices.create", index=index_name)


async def async_index_document(index: str, document_id: str, document: dict[str, Any]) -> None:
    client = get_client()
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: client.index(index=index, id=document_id, body=document, refresh="wait_for"),
        )
        _mark_opensearch_available()
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="index", index=index, document_id=document_id)


async def async_search(index: str, body: dict[str, Any], *, suppress_exceptions: bool = True) -> dict[str, Any]:
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        result = await loop.run_in_executor(
            None,
            lambda: client.search(index=index, body=body),
        )
        _mark_opensearch_available()
        return result
    except NotFoundError:
        ensure_vulnerability_index(index)
        return {"hits": {"hits": [], "total": {"value": 0}}}
    except (OSConnectionError, OpenSearchException) as exc:
        if isinstance(exc, RequestError):
            log.warning("opensearch.request_error", operation="search", index=index, error=str(exc))
        else:
            _mark_opensearch_unavailable(error=exc, operation="search", index=index)
        if suppress_exceptions:
            return {"hits": {"hits": [], "total": {"value": 0}}}
        raise


async def async_get(index: str, document_id: str) -> dict[str, Any] | None:
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        result = await loop.run_in_executor(
            None,
            lambda: client.get(index=index, id=document_id),
        )
        _mark_opensearch_available()
        return result.get("_source")
    except NotFoundError:
        return None
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="get", index=index, document_id=document_id)
        return None
    except Exception as exc:  # noqa: BLE001 - log and propagate None
        log.warning("opensearch.get_failed", index=index, id=document_id, error=str(exc))
        return None
