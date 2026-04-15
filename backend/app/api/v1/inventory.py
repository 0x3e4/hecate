from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.schemas.inventory import (
    AffectedVulnerabilitiesResponse,
    InventoryItemCreateRequest,
    InventoryItemListResponse,
    InventoryItemResponse,
    InventoryItemUpdateRequest,
)
from app.services.inventory_service import InventoryService, get_inventory_service

router = APIRouter()


@router.get("", response_model=InventoryItemListResponse)
async def list_inventory_items(
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryItemListResponse:
    items = await service.list_items()
    return InventoryItemListResponse(items=items, total=len(items))


@router.post("", response_model=InventoryItemResponse, status_code=201)
async def create_inventory_item(
    request: InventoryItemCreateRequest,
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryItemResponse:
    return await service.create_item(request)


@router.get("/{item_id}", response_model=InventoryItemResponse)
async def get_inventory_item(
    item_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryItemResponse:
    item = await service.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    return item


@router.put("/{item_id}", response_model=InventoryItemResponse)
async def update_inventory_item(
    item_id: str,
    request: InventoryItemUpdateRequest,
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryItemResponse:
    updated = await service.update_item(item_id, request)
    if updated is None:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    return updated


@router.delete("/{item_id}", status_code=204)
async def delete_inventory_item(
    item_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> None:
    deleted = await service.delete_item(item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Inventory item not found")


@router.get(
    "/{item_id}/affected-vulnerabilities",
    response_model=AffectedVulnerabilitiesResponse,
)
async def get_affected_vulnerabilities(
    item_id: str,
    limit: int = 200,
    service: InventoryService = Depends(get_inventory_service),
) -> AffectedVulnerabilitiesResponse:
    item = await service.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    vulns = await service.vulns_affecting_item(item_id, limit=max(1, min(limit, 1000)))
    return AffectedVulnerabilitiesResponse(
        itemId=item_id,
        total=len(vulns),
        vulnerabilities=vulns,
    )
