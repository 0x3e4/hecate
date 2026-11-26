"""Server lists Hecate fetches itself: ``/v1/inventory/systems/sources``.

Admin-only for every method (``_admin_all`` in routes.py): a source holds a
credential and makes the backend send requests. Mounted before the systems
router, whose ``/{system_id}`` would otherwise take ``sources``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.repositories.inventory_list_source_repository import ListSourceTaken
from app.schemas.inventory_system import (
    InventoryListSourceCreateRequest,
    InventoryListSourceListResponse,
    InventoryListSourcePullRequest,
    InventoryListSourcePullResponse,
    InventoryListSourceResponse,
    InventoryListSourceUpdateRequest,
)
from app.services.audit_service import AuditService, get_audit_service
from app.services.inventory_list_source_service import (
    InventoryListSourceService,
    get_inventory_list_source_service,
)

router = APIRouter()


def _taken(name: str | None) -> HTTPException:
    return HTTPException(status_code=409, detail=f"A list source named {name!r} already exists.")


def _audit_result(source: InventoryListSourceResponse) -> dict:
    # Never the credential; the URL is masked like in the response.
    return {
        "source": source.source, "url": source.url, "format": source.format, "mode": source.mode,
        "intervalMinutes": source.interval_minutes, "enabled": source.enabled, "authSet": source.auth_set,
    }


@router.get("", response_model=InventoryListSourceListResponse)
async def list_list_sources(
    service: InventoryListSourceService = Depends(get_inventory_list_source_service),
) -> InventoryListSourceListResponse:
    """Every list source with its last fetch and when it runs next. Credentials are never returned."""
    return await service.list_sources()


@router.post("", response_model=InventoryListSourceResponse, status_code=201)
async def create_list_source(
    payload: InventoryListSourceCreateRequest,
    service: InventoryListSourceService = Depends(get_inventory_list_source_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> InventoryListSourceResponse:
    """Add a source. Its host must resolve to public addresses unless private hosts are allowed on the server."""
    try:
        created = await service.create_source(payload)
    except ListSourceTaken:
        raise _taken(payload.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await audit_service.record_event(
        "inventory_list_source_added",
        metadata={"label": "Server list source added", "source": created.source},
        result=_audit_result(created),
    )
    return created


@router.put("/{source_id}", response_model=InventoryListSourceResponse)
async def update_list_source(
    source_id: str,
    payload: InventoryListSourceUpdateRequest,
    service: InventoryListSourceService = Depends(get_inventory_list_source_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> InventoryListSourceResponse:
    """Change a source (partial). Send ``url`` only when it changed: the response masks tokens in it."""
    try:
        updated = await service.update_source(source_id, payload)
    except ListSourceTaken:
        raise _taken(payload.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="List source not found")
    await audit_service.record_event(
        "inventory_list_source_updated",
        metadata={"label": "Server list source updated", "source": updated.source},
        result=_audit_result(updated),
    )
    return updated


@router.delete("/{source_id}", status_code=204)
async def delete_list_source(
    source_id: str,
    service: InventoryListSourceService = Depends(get_inventory_list_source_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """Remove a source. Its systems stay; nothing is retired."""
    deleted = await service.delete_source(source_id)
    if deleted is None:
        raise HTTPException(status_code=404, detail="List source not found")
    await audit_service.record_event(
        "inventory_list_source_removed",
        metadata={"label": "Server list source removed", "source": deleted.source},
        result=_audit_result(deleted),
    )


@router.post("/{source_id}/pull", response_model=InventoryListSourcePullResponse)
async def pull_list_source(
    source_id: str,
    payload: InventoryListSourcePullRequest,
    service: InventoryListSourceService = Depends(get_inventory_list_source_service),
) -> InventoryListSourcePullResponse:
    """Fetch the source now. ``dryRun`` reports what it would change; ``force`` applies a replace past the half-of-the-list guard.

    A failed fetch answers 200 with ``ok: false``: the failure is the source's
    state, kept on it like a scheduled one.
    """
    result = await service.pull(source_id, dry_run=payload.dry_run, force=payload.force)
    if result is None:
        raise HTTPException(status_code=404, detail="List source not found")
    return result
