"""Systems of the inventory: ``/v1/inventory/systems``.

Mounted in routes.py before the inventory router, whose ``/{item_id}`` would
otherwise take ``systems`` for an item id. Writes go through the same editor
gate as inventory items.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.repositories.inventory_system_repository import SystemNameTaken
from app.schemas.inventory_system import (
    InventorySystemCreateRequest,
    InventorySystemListResponse,
    InventorySystemResponse,
    InventorySystemUpdateRequest,
)
from app.services.inventory_system_service import get_inventory_system_service

router = APIRouter()


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
