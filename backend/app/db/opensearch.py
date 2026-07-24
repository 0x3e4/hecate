import asyncio
import contextlib
import contextvars
import os
import ssl
import warnings
from collections.abc import Iterator
from typing import Any

from urllib3.exceptions import InsecureRequestWarning

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


VERSION_RANGES_MAPPING: dict[str, Any] = {
    "type": "nested",
    "properties": {
        "vendorSlug": {"type": "keyword"},
        "productSlug": {"type": "keyword"},
        "startNumeric": {"type": "long"},
        "endNumeric": {"type": "long"},
    },
}


def _ensure_index_mappings(client: OpenSearch, index_name: str) -> None:
    """
    Additive mapping update for indices created before newer sub-fields existed.

    Only declares fields that are safe to add: unaffectedVersions did not exist
    before this mapping was introduced, so there is no dynamic-mapping conflict.
    (patchedVersions is deliberately NOT declared here — past GHSA/OSV writes may
    have dynamically mapped it as text, and a conflicting keyword mapping would
    error; display reads come from _source, so its mapping type doesn't matter.)

    ``versionRanges`` is likewise brand new (see app.services.version_ranges), so
    declaring it here is conflict-free and lets long-lived indices gain
    affected-version search after a plain ``reindex-opensearch`` — no index
    recreation required.
    """
    mapping_body = {
        "properties": {
            "impactedProducts": {
                "type": "nested",
                "properties": {
                    "unaffectedVersions": {"type": "keyword"},
                },
            },
            "versionRanges": VERSION_RANGES_MAPPING,
        }
    }
    try:
        client.indices.put_mapping(index=index_name, body=mapping_body)
    except (OSConnectionError, OpenSearchException) as exc:
        log.warning("opensearch.ensure_mappings_failed", index=index_name, error=str(exc))


# --- Exact-match field resolution -------------------------------------------
#
# Fields such as ``vendorSlugs`` are declared ``keyword`` in
# ``ensure_vulnerability_index``, but indices created before that declaration
# existed had them dynamically mapped as analyzed ``text`` + a ``.keyword``
# sub-field. On such an index a DQL clause like ``vendorSlugs:"wordpress"``
# runs through the standard analyzer and matches every slug that merely
# *contains* the token — ``dokan-wordpress-plugin`` tokenizes to
# ``[dokan, wordpress, plugin]``.
#
# Mapping types cannot be changed in place, so instead of fighting the drift we
# detect it once and route DQL clauses to whichever path is exact on *this*
# index. Structured filters already hedge the same way with ``terms`` queries
# on both paths (see VulnerabilityService._build_query).

_exact_field_paths: dict[str, dict[str, str]] = {}


def _walk_mapping_properties(
    properties: dict[str, Any],
    prefix: str,
    out: dict[str, str],
) -> None:
    for name, definition in (properties or {}).items():
        if not isinstance(definition, dict):
            continue
        path = f"{prefix}{name}"
        field_type = definition.get("type")
        fields = definition.get("fields") or {}
        if field_type == "text" and isinstance(fields, dict) and "keyword" in fields:
            out[path] = f"{path}.keyword"
        elif field_type is not None:
            out[path] = path
        nested = definition.get("properties")
        if isinstance(nested, dict):
            _walk_mapping_properties(nested, f"{path}.", out)


def refresh_exact_field_paths(index_name: str) -> dict[str, str]:
    """Read ``index_name``'s live mapping and cache the exact-match path per field.

    Returns a ``{field: exact_path}`` map where ``exact_path`` is either the
    field itself (already ``keyword``) or ``field.keyword`` (analyzed ``text``
    with a keyword sub-field). Unknown fields are simply absent, and callers
    fall back to the field name unchanged.
    """
    client = get_client()
    resolved: dict[str, str] = {}
    try:
        mapping = client.indices.get_mapping(index=index_name)
    except (OSConnectionError, OpenSearchException) as exc:
        log.warning("opensearch.get_mapping_failed", index=index_name, error=str(exc))
        return _exact_field_paths.get(index_name, {})

    for body in (mapping or {}).values():
        properties = ((body or {}).get("mappings") or {}).get("properties") or {}
        _walk_mapping_properties(properties, "", resolved)

    _exact_field_paths[index_name] = resolved
    drifted = sorted(field for field, path in resolved.items() if path != field)
    if drifted:
        log.info(
            "opensearch.text_mapped_fields_detected",
            index=index_name,
            fields=drifted[:25],
            count=len(drifted),
        )
    return resolved


def exact_field_path(field: str, index_name: str | None = None) -> str:
    """Exact-match path for ``field`` on the live index (``field`` when unknown)."""
    index = index_name or settings.opensearch_index
    cached = _exact_field_paths.get(index)
    if cached is None:
        return field
    return cached.get(field, field)


def get_client() -> OpenSearch:
    global _client
    if _client is None:
        auth = None
        if settings.opensearch_username and settings.opensearch_password:
            auth = (settings.opensearch_username, settings.opensearch_password)

        use_ssl = settings.opensearch_url.startswith("https")
        ssl_context = None
        if use_ssl:
            verify = settings.opensearch_verify_certs
            if verify and settings.opensearch_ca_cert:
                if not os.path.isfile(settings.opensearch_ca_cert):
                    raise FileNotFoundError(
                        f"OpenSearch CA certificate not found: {settings.opensearch_ca_cert}"
                    )
                ssl_context = ssl.create_default_context(cafile=settings.opensearch_ca_cert)
            elif verify:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)

            log.info(
                "opensearch.ssl_configured",
                verify_certs=verify,
                ca_cert=settings.opensearch_ca_cert or "system-default",
            )

        _client = OpenSearch(
            hosts=[settings.opensearch_url],
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=settings.opensearch_verify_certs,
            ssl_context=ssl_context,
            ssl_show_warn=settings.opensearch_verify_certs,
            timeout=10,
            max_retries=1,
            retry_on_timeout=False,
            pool_maxsize=10,
        )
    return _client


def ensure_vulnerability_index(index_name: str) -> None:
    global _ensured_indices
    client = get_client()
    try:
        if client.indices.exists(index=index_name):
            log.info("opensearch.index_already_exists", index=index_name)
            applied = _ensure_index_settings(client, index_name)
            _ensure_index_mappings(client, index_name)
            refresh_exact_field_paths(index_name)
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
                        "unaffectedVersions": {"type": "keyword"},
                        "patchedVersions": {"type": "keyword"},
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
                "epssScore": {"type": "float"},
                "sources": {
                    "type": "nested",
                    "properties": {
                        "source": {"type": "keyword"},
                    }
                },
                "sourceNames": {"type": "keyword"},
                "vendorSlugs": {"type": "keyword"},
                "productSlugs": {"type": "keyword"},
                "productVersions": {"type": "keyword"},
                "productVersionIds": {"type": "keyword"},
                "vendors": {"type": "keyword"},
                "products": {"type": "keyword"},
                "versionRanges": VERSION_RANGES_MAPPING,
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
                "first_seen_at": {"type": "date"},
                "ai_assessment": {"type": "object"},
                "attack_path": {"type": "object"},
            }
        },
    }

    try:
        client.indices.create(index=index_name, body=body)
        log.info("opensearch.index_created", index=index_name)
        refresh_exact_field_paths(index_name)
        _mark_opensearch_available()
        _ensured_indices.add(index_name)
    except (RequestError, OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="indices.create", index=index_name)


_OS_WAIT_FOR_REFRESH: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "opensearch_wait_for_refresh", default=True
)


@contextlib.contextmanager
def opensearch_bulk_mode() -> Iterator[None]:
    """Run a block with OpenSearch writes set to ``refresh=false``.

    Bulk pipelines (NVD/EUVD/GHSA/OSV/CIRCL initial + incremental syncs)
    enter this context once per run. Inside it every ``async_index_document``
    / ``async_update_document`` / ``async_delete_document`` call returns as
    soon as the doc is durable, instead of blocking until the next
    refresh. The default ``refresh_interval`` (1 s) still makes the data
    searchable shortly after — but the per-write queue at ~1 s/PUT under
    ``wait_for`` is gone, which is what made initial syncs of tens of
    thousands of CVEs run for hours and starve concurrent manual
    refreshes for OSV+deps.dev enrichment.

    User-initiated writes (manual refresh, scan completion, deps.dev
    enrichment that runs inline after a manual refresh) do *not* enter
    this context, so they keep ``refresh=wait_for`` and the UI's read-
    after-write semantics are preserved.
    """
    token = _OS_WAIT_FOR_REFRESH.set(False)
    try:
        yield
    finally:
        _OS_WAIT_FOR_REFRESH.reset(token)


def _resolve_refresh(wait_for_refresh: bool | None) -> str | bool:
    """Pick the OpenSearch ``refresh`` argument for one write.

    Explicit kwarg wins; otherwise read the bulk-mode ContextVar.
    """
    if wait_for_refresh is None:
        wait_for_refresh = _OS_WAIT_FOR_REFRESH.get()
    return "wait_for" if wait_for_refresh else False


async def async_index_document(
    index: str,
    document_id: str,
    document: dict[str, Any],
    *,
    wait_for_refresh: bool | None = None,
) -> None:
    """Index a single document. See ``opensearch_bulk_mode`` for refresh semantics."""
    client = get_client()
    loop = asyncio.get_running_loop()

    # Ensure index exists with proper mapping before indexing
    if index not in _ensured_indices:
        ensure_vulnerability_index(index)

    refresh = _resolve_refresh(wait_for_refresh)
    try:
        await loop.run_in_executor(
            None,
            lambda: client.index(index=index, id=document_id, body=document, refresh=refresh),
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


async def async_update_document(
    index: str,
    document_id: str,
    fields: dict[str, Any],
    *,
    wait_for_refresh: bool | None = None,
) -> bool:
    client = get_client()
    loop = asyncio.get_running_loop()

    refresh = _resolve_refresh(wait_for_refresh)
    try:
        await loop.run_in_executor(
            None,
            lambda: client.update(
                index=index,
                id=document_id,
                body={"doc": fields, "doc_as_upsert": False},
                refresh=refresh,
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


async def async_update_document_script(
    index: str,
    document_id: str,
    script: dict[str, Any],
    *,
    wait_for_refresh: bool | None = None,
) -> bool:
    """Update a document using a script (e.g., to append to arrays)."""
    client = get_client()
    loop = asyncio.get_running_loop()

    refresh = _resolve_refresh(wait_for_refresh)
    try:
        await loop.run_in_executor(
            None,
            lambda: client.update(
                index=index,
                id=document_id,
                body={"script": script},
                refresh=refresh,
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


async def async_delete_document(
    index: str,
    document_id: str,
    *,
    wait_for_refresh: bool | None = None,
) -> bool:
    """Delete a document from OpenSearch by ID. Returns True if deleted, False if not found."""
    client = get_client()
    loop = asyncio.get_running_loop()

    refresh = _resolve_refresh(wait_for_refresh)
    try:
        await loop.run_in_executor(
            None,
            lambda: client.delete(index=index, id=document_id, refresh=refresh),
        )
        _mark_opensearch_available()
        return True
    except NotFoundError:
        log.warning("opensearch.delete_not_found", index=index, id=document_id)
        return False
    except (OSConnectionError, OpenSearchException) as exc:
        _mark_opensearch_unavailable(error=exc, operation="delete", index=index, document_id=document_id)
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
