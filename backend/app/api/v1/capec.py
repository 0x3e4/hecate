from fastapi import APIRouter, Depends, HTTPException

from app.schemas.capec import (
    CAPECBulkRequest,
    CAPECBulkResponse,
    CAPECFromCWEsRequest,
    CAPECFromCWEsResponse,
    CAPECInfo,
)
from app.services.capec_service import CAPECService, get_capec_service

router = APIRouter()


@router.post("/from-cwes", response_model=CAPECFromCWEsResponse)
async def get_capec_from_cwes(
    request: CAPECFromCWEsRequest,
    capec_service: CAPECService = Depends(get_capec_service),
) -> CAPECFromCWEsResponse:
    """
    Resolve CWE IDs to related CAPEC attack patterns.
    Returns CAPEC information for attack patterns linked to the given CWEs.
    """
    if not request.cwe_ids:
        return CAPECFromCWEsResponse(capecs={})

    capec_descriptions = await capec_service.get_capecs_for_cwes(request.cwe_ids)

    capecs: dict[str, CAPECInfo] = {}
    for capec_id, desc in capec_descriptions.items():
        capecs[capec_id] = CAPECInfo(
            id=f"CAPEC-{capec_id}",
            name=desc.name,
            description=desc.description if desc.description else desc.name,
            severity=desc.severity or None,
            likelihood=desc.likelihood or None,
            abstraction=desc.abstraction or None,
        )

    return CAPECFromCWEsResponse(capecs=capecs)


@router.post("/bulk", response_model=CAPECBulkResponse)
async def get_capec_bulk(
    request: CAPECBulkRequest,
    capec_service: CAPECService = Depends(get_capec_service),
) -> CAPECBulkResponse:
    """
    Fetch CAPEC information for multiple CAPEC IDs.
    Returns a mapping of normalized CAPEC IDs to their names and descriptions.
    """
    if not request.capec_ids:
        return CAPECBulkResponse(capecs={})

    descriptions = await capec_service.get_bulk_descriptions(request.capec_ids)

    capecs: dict[str, CAPECInfo] = {}
    for capec_id in request.capec_ids:
        normalized_id = capec_service._normalize_capec_id(capec_id)
        description = descriptions.get(normalized_id, "Description not available")

        if description in ("See CAPEC database for details", "Description not available"):
            continue

        capecs[normalized_id] = CAPECInfo(
            id=f"CAPEC-{normalized_id}",
            name=description,
            description=description,
        )

    return CAPECBulkResponse(capecs=capecs)


@router.get("/{capec_id}", response_model=CAPECInfo)
async def get_capec(
    capec_id: str,
    capec_service: CAPECService = Depends(get_capec_service),
) -> CAPECInfo:
    """
    Fetch CAPEC information for a single CAPEC ID.
    Returns the CAPEC name and description from the MITRE CAPEC database.
    """
    normalized_id = capec_service._normalize_capec_id(capec_id)
    description = await capec_service.get_description(capec_id)

    if description == "See CAPEC database for details":
        raise HTTPException(status_code=404, detail=f"CAPEC-{normalized_id} not found")

    return CAPECInfo(
        id=f"CAPEC-{normalized_id}",
        name=description,
        description=description,
    )
