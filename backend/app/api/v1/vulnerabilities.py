from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.schemas.vulnerability import VulnerabilityDetail, VulnerabilityPreview, VulnerabilityQuery
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
