from typing import Any

from fastapi import APIRouter, Depends

from app.schemas.vulnerability import VulnerabilityPreview, VulnerabilityQuery
from app.services.vulnerability_service import VulnerabilityService, get_vulnerability_service

router = APIRouter()


@router.post("/search", response_model=list[VulnerabilityPreview])
async def search_vulnerabilities(
    query: VulnerabilityQuery,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityPreview]:
    """
    Query OpenSearch for matching vulnerabilities.
    Currently returns stubbed data until backend integrations land.
    """
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
