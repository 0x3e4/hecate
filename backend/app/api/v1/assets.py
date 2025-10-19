from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query

from app.schemas.assets import CatalogProductList, CatalogVendorList, CatalogVersionList
from app.services.asset_catalog_service import AssetCatalogService, get_asset_catalog_service

router = APIRouter()


@router.get("/vendors", response_model=CatalogVendorList)
async def list_vendors(
    keyword: str | None = Query(default=None, description="Optional search keyword"),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: AssetCatalogService = Depends(get_asset_catalog_service),
) -> CatalogVendorList:
    total, items = await service.search_vendors(keyword, limit=limit, offset=offset)
    return CatalogVendorList(total=total, items=items)


@router.get("/products", response_model=CatalogProductList)
async def list_products(
    vendor_slugs: List[str] = Query(default_factory=list, alias="vendorSlugs", description="Filter by vendor slug"),
    keyword: str | None = Query(default=None, description="Optional search keyword"),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: AssetCatalogService = Depends(get_asset_catalog_service),
) -> CatalogProductList:
    vendor_filter = vendor_slugs or None
    total, items = await service.search_products(
        vendor_slugs=vendor_filter,
        keyword=keyword,
        limit=limit,
        offset=offset,
    )
    return CatalogProductList(total=total, items=items)


@router.get("/versions", response_model=CatalogVersionList)
async def list_versions(
    product_slug: str = Query(..., alias="productSlug", description="Catalog product slug"),
    keyword: str | None = Query(default=None, description="Optional search keyword"),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: AssetCatalogService = Depends(get_asset_catalog_service),
) -> CatalogVersionList:
    total, items = await service.list_versions(
        product_slug=product_slug,
        keyword=keyword,
        limit=limit,
        offset=offset,
    )
    return CatalogVersionList(total=total, items=items)
