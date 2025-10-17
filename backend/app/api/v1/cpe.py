from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query

from app.schemas.cpe import CPEEntry, CPEQuery, CPEQueryResponse, CPEValueListResponse
from app.services.cpe_service import CPEService, get_cpe_service

router = APIRouter()


@router.get("/entries", response_model=CPEQueryResponse)
async def list_cpe_entries(
    keyword: str | None = Query(default=None, description="Filter by vendor/product keyword"),
    vendor: str | None = Query(default=None, description="Exact vendor filter"),
    product: str | None = Query(default=None, description="Exact product filter"),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: CPEService = Depends(get_cpe_service),
) -> CPEQueryResponse:
    query = CPEQuery(keyword=keyword, vendor=vendor, product=product, limit=limit, offset=offset)
    return await service.search(query)


@router.get("/entries/{cpe_name}", response_model=CPEEntry)
async def get_cpe_entry(
    cpe_name: str,
    service: CPEService = Depends(get_cpe_service),
) -> CPEEntry:
    result = await service.get(cpe_name)
    if result is None:
        raise HTTPException(status_code=404, detail="CPE entry not found")
    return result


@router.get("/vendors", response_model=CPEValueListResponse)
async def list_vendors(
    keyword: str | None = Query(default=None, description="Optional search term for vendors"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: CPEService = Depends(get_cpe_service),
) -> CPEValueListResponse:
    return await service.list_vendors(keyword=keyword, limit=limit, offset=offset)


@router.get("/products", response_model=CPEValueListResponse)
async def list_products(
    vendors: List[str] = Query(default_factory=list, description="Optional vendor filter (repeatable)"),
    keyword: str | None = Query(default=None, description="Optional search term for products"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: CPEService = Depends(get_cpe_service),
) -> CPEValueListResponse:
    vendor_list = vendors or None
    return await service.list_products(vendors=vendor_list, keyword=keyword, limit=limit, offset=offset)
