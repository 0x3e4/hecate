from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.write_auth import require_inventory_report
from app.schemas.inventory import (
    AffectedVulnerabilitiesResponse,
    EolProductListResponse,
    EolStatusResponse,
    InventoryHistoryResponse,
    InventoryItemCreateRequest,
    InventoryItemListResponse,
    InventoryItemResponse,
    InventoryItemUpdateRequest,
    InventoryReportRequest,
    InventoryReportResponse,
)
from app.services.enrichment.endoflife_service import get_endoflife_service
from app.services.inventory_service import InventoryService, get_inventory_service

router = APIRouter()
# Mounted without the admin gate: pipelines hold an inventory:report token.
report_router = APIRouter()


@report_router.post("/report", response_model=InventoryReportResponse)
async def report_inventory_versions(
    request: InventoryReportRequest,
    token_name: str | None = Depends(require_inventory_report),
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryReportResponse:
    """Record deployed versions, e.g. from a pipeline after a rollout.

    Answers per entry, so one unknown product does not fail a whole batch. The
    history names the token: ``reportedBy`` is free text the caller chooses.
    """
    reported_by = request.reported_by
    if token_name:
        reported_by = f"{token_name} ({reported_by})" if reported_by else token_name
    results = await service.report_versions(request.items, reported_by=reported_by)
    return InventoryReportResponse(results=results)


@router.get("/eol/products", response_model=EolProductListResponse)
async def list_eol_products(search: str | None = None) -> EolProductListResponse:
    """List endoflife.date products for the manual-link picker (cached)."""
    products = await get_endoflife_service().list_products(search)
    return EolProductListResponse(products=products, total=len(products))


@router.get("", response_model=InventoryItemListResponse)
async def list_inventory_items(
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryItemListResponse:
    items = await service.list_items()
    return InventoryItemListResponse(items=items, total=len(items))


@router.get("/history", response_model=InventoryHistoryResponse)
async def list_inventory_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryHistoryResponse:
    """Recent changes across all items, including deleted ones."""
    total, items = await service.list_history(limit=limit, offset=offset)
    return InventoryHistoryResponse(total=total, items=items)


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


@router.get("/{item_id}/history", response_model=InventoryHistoryResponse)
async def get_inventory_item_history(
    item_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: InventoryService = Depends(get_inventory_service),
) -> InventoryHistoryResponse:
    total, items = await service.list_history(item_id=item_id, limit=limit, offset=offset)
    return InventoryHistoryResponse(total=total, items=items)


@router.get("/{item_id}/eol", response_model=EolStatusResponse)
async def get_inventory_item_eol(
    item_id: str,
    service: InventoryService = Depends(get_inventory_service),
) -> EolStatusResponse:
    """Return the endoflife.date support status for an inventory item."""
    status = await service.get_item_eol_status(item_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    return status
