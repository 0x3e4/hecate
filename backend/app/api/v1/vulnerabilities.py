from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.schemas.vulnerability import (
    PagedVulnerabilityResponse,
    VulnerabilityDetail,
    VulnerabilityPreview,
    VulnerabilityQuery,
)
from app.services.vulnerability_service import VulnerabilityService, get_vulnerability_service

router = APIRouter()


@router.post("/search", response_model=list[VulnerabilityPreview])
async def search_vulnerabilities(
    query: VulnerabilityQuery,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityPreview]:
    return await service.search(query)


@router.post("/refresh")
async def trigger_refresh(
    payload: dict[str, Any],
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> dict[str, str]:
    """
    Trigger vulnerability feed refresh.
    """
    await service.trigger_refresh(payload)
    return {"status": "scheduled"}


@router.get("", response_model=PagedVulnerabilityResponse)
async def list_vulnerabilities(
    search: str | None = Query(default=None, description="Keyword search across CVE/EUVD/GHSA"),
    dql: str | None = Query(
        default=None,
        alias="dqlQuery",
        description="Raw OpenSearch query (DQL syntax). Overrides the keyword search when present.",
    ),
    vendorFilters: list[str] = Query(default_factory=list),
    productFilters: list[str] = Query(default_factory=list),
    vendorSlugs: list[str] = Query(default_factory=list),
    productSlugs: list[str] = Query(default_factory=list),
    versionFilters: list[str] = Query(default_factory=list),
    include_rejected: bool = Query(
        default=False,
        alias="includeRejected",
        description="Include rejected CVE records in the response.",
    ),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> PagedVulnerabilityResponse:
    query = VulnerabilityQuery(
        searchTerm=search,
        dqlQuery=dql,
        vendorFilters=vendorFilters,
        productFilters=productFilters,
        vendorSlugs=vendorSlugs,
        productSlugs=productSlugs,
        versionFilters=versionFilters,
        limit=limit,
        includeRejected=include_rejected,
    )
    return await service.search_paginated(query, limit=limit, offset=offset)


@router.get("/{identifier}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    identifier: str,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityDetail:
    """
    Retrieve a single vulnerability by its canonical identifier (CVE or source ID).
    """
    result = await service.get_by_id(identifier)
    if result is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return result
