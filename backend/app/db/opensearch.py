import asyncio
from typing import Any

import structlog
from opensearchpy import OpenSearch, RequestError
from opensearchpy.exceptions import NotFoundError, OpenSearchException, ConnectionError as OSConnectionError

from app.core.config import settings

_client: OpenSearch | None = None
_opensearch_available: bool = True
_ensured_indices: set[str] = set()
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


def _desired_index_settings() -> dict[str, Any]:
    return {
        "index": {
            "max_result_window": settings.opensearch_index_max_result_window,
            "mapping": {
                "total_fields": {"limit": settings.opensearch_index_total_fields_limit},
            },
        }
    }


def _ensure_index_settings(client: OpenSearch, index_name: str) -> bool:
    try:
        client.indices.put_settings(index=index_name, body=_desired_index_settings())
    except (OSConnectionError, OpenSearchException) as exc:
        log.warning("opensearch.ensure_settings_failed", index=index_name, error=str(exc))
        return False
    return True


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
            timeout=10,  # 10 second timeout for queries
            max_retries=1,
            retry_on_timeout=False,
            pool_maxsize=10,  # Maximum connections in the pool
        )
    return _client


def ensure_vulnerability_index(index_name: str) -> None:
    global _ensured_indices
    client = get_client()
    try:
        if client.indices.exists(index=index_name):
            log.info("opensearch.index_already_exists", index=index_name)
            applied = _ensure_index_settings(client, index_name)
            _mark_opensearch_available()
            if applied:
                _ensured_indices.add(index_name)
            return
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="indices.exists", index=index_name)
        return

    body: dict[str, Any] = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.mapping.total_fields.limit": settings.opensearch_index_total_fields_limit,
            "index.max_result_window": settings.opensearch_index_max_result_window,
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
                "cpeConfigurations": {
                    "type": "nested",
                    "properties": {
                        "nodes": {
                            "type": "nested",
                            "properties": {
                                "operator": {"type": "keyword"},
                                "negate": {"type": "boolean"},
                                "matches": {
                                    "type": "nested",
                                    "properties": {
                                        "criteria": {"type": "keyword"},
                                        "vendor": {"type": "keyword"},
                                        "product": {"type": "keyword"},
                                        "versionStartIncluding": {"type": "keyword"},
                                        "versionStartExcluding": {"type": "keyword"},
                                        "versionEndIncluding": {"type": "keyword"},
                                        "versionEndExcluding": {"type": "keyword"},
                                        "versionStartNumeric": {"type": "long"},
                                        "versionEndNumeric": {"type": "long"},
                                        "vulnerable": {"type": "boolean"}
                                    }
                                }
                            }
                        }
                    }
                },
                "cpeVersionTokens": {
                    "type": "search_as_you_type",
                    "fields": {
                        "keyword": {"type": "keyword"},
                    },
                },
                "impactedProducts": {
                    "type": "nested",
                    "properties": {
                        "vendor": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "slug": {"type": "keyword"},
                            }
                        },
                        "product": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "slug": {"type": "keyword"},
                            }
                        },
                        "versions": {"type": "keyword"},
                        "environments": {"type": "keyword"},
                        "vulnerable": {"type": "boolean"},
                    },
                },
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
                "sources": {
                    "type": "nested",
                    "properties": {
                        "source": {"type": "keyword"},
                    }
                },
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
                "ai_assessment": {"type": "object"},
            }
        },
    }

    try:
        client.indices.create(index=index_name, body=body)
        log.info("opensearch.index_created", index=index_name)
        _mark_opensearch_available()
        _ensured_indices.add(index_name)
    except (RequestError, OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="indices.create", index=index_name)


async def async_index_document(index: str, document_id: str, document: dict[str, Any]) -> None:
    client = get_client()
    loop = asyncio.get_running_loop()

    # Ensure index exists with proper mapping before indexing
    if index not in _ensured_indices:
        ensure_vulnerability_index(index)

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

    if index not in _ensured_indices:
        ensure_vulnerability_index(index)

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


async def async_update_document(index: str, document_id: str, fields: dict[str, Any]) -> bool:
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        await loop.run_in_executor(
            None,
            lambda: client.update(
                index=index,
                id=document_id,
                body={"doc": fields, "doc_as_upsert": False},
                refresh="wait_for",
            ),
        )
        _mark_opensearch_available()
        return True
    except NotFoundError:
        log.warning("opensearch.update_not_found", index=index, id=document_id)
        return False
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(
            error=exc,
            operation="update",
            index=index,
            document_id=document_id,
        )
        return False
    except Exception as exc:  # noqa: BLE001 - defensive logging
        log.warning("opensearch.update_failed", index=index, id=document_id, error=str(exc))
        return False


async def async_update_document_script(index: str, document_id: str, script: dict[str, Any]) -> bool:
    """Update a document using a script (e.g., to append to arrays)."""
    client = get_client()
    loop = asyncio.get_running_loop()

    try:
        await loop.run_in_executor(
            None,
            lambda: client.update(
                index=index,
                id=document_id,
                body={"script": script},
                refresh="wait_for",
            ),
        )
        _mark_opensearch_available()
        return True
    except NotFoundError:
        log.warning("opensearch.update_script_not_found", index=index, id=document_id)
        return False
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(
            error=exc,
            operation="update_script",
            index=index,
            document_id=document_id,
        )
        return False
    except Exception as exc:  # noqa: BLE001 - defensive logging
        log.warning("opensearch.update_script_failed", index=index, id=document_id, error=str(exc))
        return False


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
