"""Systems of the inventory: ``/v1/inventory/systems``.

Mounted in routes.py before the inventory router, whose ``/{item_id}`` would
otherwise take ``systems`` for an item id. Writes go through the same editor
gate as inventory items.
"""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from app.core.write_auth import require_inventory_sync

from app.repositories.inventory_system_repository import SystemNameTaken
from app.schemas.inventory_system import (
    InventorySystemCreateRequest,
    InventorySystemImportRequest,
    InventorySystemImportResponse,
    ListFormat,
    ListMode,
    InventorySystemListResponse,
    InventorySystemResponse,
    InventorySystemUpdateRequest,
)
from app.services.inventory_system_lists import MAX_LIST_BYTES, ListError, parse_system_list
from app.services.inventory_system_service import ListTooDestructive, get_inventory_system_service

log = structlog.get_logger()

router = APIRouter()
# Server lists: an editor in the UI, or a script with an inventory:sync token.
# Mounted without the router-level editor gate; each route takes require_inventory_sync.
sync_router = APIRouter()


def _taken(name: str) -> HTTPException:
    return HTTPException(status_code=409, detail=f"A system named {name!r} already exists.")


@router.get("", response_model=InventorySystemListResponse)
async def list_systems() -> InventorySystemListResponse:
    """All systems with their last report, report status, latest findings and linked products."""
    return await get_inventory_system_service().list_systems()


@router.post("", response_model=InventorySystemResponse, status_code=201)
async def create_system(payload: InventorySystemCreateRequest) -> InventorySystemResponse:
    """Add a system. An SBOM-import target of the same name is linked to it."""
    try:
        return await get_inventory_system_service().create_system(payload)
    except SystemNameTaken:
        raise _taken(payload.name)


@router.get("/{system_id}", response_model=InventorySystemResponse)
async def get_system(system_id: str) -> InventorySystemResponse:
    system = await get_inventory_system_service().get_system(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return system


@router.put("/{system_id}", response_model=InventorySystemResponse)
async def update_system(system_id: str, payload: InventorySystemUpdateRequest) -> InventorySystemResponse:
    """Change a system (partial). Kind and exposure reach its target too."""
    try:
        system = await get_inventory_system_service().update_system(system_id, payload)
    except SystemNameTaken:
        raise _taken(payload.name or "")
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return system


@router.delete("/{system_id}", status_code=204)
async def delete_system(system_id: str) -> None:
    """Remove a system. Its findings and scan history stay, as an SCA target."""
    if not await get_inventory_system_service().delete_system(system_id):
        raise HTTPException(status_code=404, detail="System not found")


async def _apply(
    content: str, fmt: str | None, source: str, mode: str, dry_run: bool, force: bool, token: str | None,
) -> InventorySystemImportResponse:
    try:
        parsed = parse_system_list(content, fmt)
        result = await get_inventory_system_service().apply_list(
            parsed, source=source, mode=mode, dry_run=dry_run, force=force,
        )
    except ListError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ListTooDestructive as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if not dry_run:
        log.info(
            "inventory_system.list_applied", source=source, mode=mode, token=token, format=result.format,
            listed=result.listed, created=result.created_count, updated=result.updated_count,
            retired=result.retired_count, restored=result.restored_count,
        )
    return result


@sync_router.post("/import", response_model=InventorySystemImportResponse)
async def import_system_list(
    payload: InventorySystemImportRequest,
    token: str | None = Depends(require_inventory_sync),
) -> InventorySystemImportResponse:
    """Apply a server list (CSV, text, Ansible INI / YAML / ``ansible-inventory --list`` JSON, Hecate JSON).

    ``merge`` adds and updates systems; ``replace`` also retires the systems
    this ``source`` named before and no longer does. ``dryRun`` reports
    without writing. 409 when a replace would retire more than half of the
    source's systems and ``force`` is not set.
    """
    return await _apply(payload.content, payload.format, payload.source, payload.mode, payload.dry_run, payload.force, token)


@sync_router.post("/import/upload", response_model=InventorySystemImportResponse)
async def import_system_list_upload(
    file: UploadFile = File(...),
    format: ListFormat | None = Query(default=None, description="Detected when omitted"),
    source: str = Query(default="upload", pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$"),
    mode: ListMode = Query(default="merge"),
    dry_run: bool = Query(default=False, alias="dryRun"),
    force: bool = Query(default=False),
    token: str | None = Depends(require_inventory_sync),
) -> InventorySystemImportResponse:
    """The same as ``POST /import`` with the list as a file (``curl -F file=@hosts.ini``)."""
    raw = await file.read(MAX_LIST_BYTES + 1)
    if len(raw) > MAX_LIST_BYTES:
        raise HTTPException(status_code=413, detail=f"List too large (max {MAX_LIST_BYTES // (1024 * 1024)} MB)")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="The list is not UTF-8 text.")
    return await _apply(content, format, source, mode, dry_run, force, token)
