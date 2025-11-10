from fastapi import APIRouter, Depends, HTTPException

from app.schemas.cwe import CWEBulkRequest, CWEBulkResponse, CWEInfo
from app.services.cwe_service import CWEService, get_cwe_service

router = APIRouter()


@router.post("/bulk", response_model=CWEBulkResponse)
async def get_cwe_bulk(
    request: CWEBulkRequest,
    cwe_service: CWEService = Depends(get_cwe_service),
) -> CWEBulkResponse:
    """
    Fetch CWE information for multiple CWE IDs.

    Returns a mapping of normalized CWE IDs to their names and descriptions.
    This endpoint is useful for enriching vulnerability data with CWE context.
    """
    if not request.cwe_ids:
        return CWEBulkResponse(cwes={})

    # Get short descriptions for all CWE IDs
    descriptions = await cwe_service.get_bulk_descriptions(request.cwe_ids, detailed=False)

    # Build response with structured CWE info
    cwes = {}
    for cwe_id in request.cwe_ids:
        normalized_id = cwe_service._normalize_cwe_id(cwe_id)
        description = descriptions.get(normalized_id, "Description not available")

        cwes[normalized_id] = CWEInfo(
            id=f"CWE-{normalized_id}",
            name=description,
            description=description,
        )

    return CWEBulkResponse(cwes=cwes)


@router.get("/{cwe_id}", response_model=CWEInfo)
async def get_cwe(
    cwe_id: str,
    cwe_service: CWEService = Depends(get_cwe_service),
) -> CWEInfo:
    """
    Fetch CWE information for a single CWE ID.

    Returns the CWE name and description from the MITRE CWE database.
    """
    normalized_id = cwe_service._normalize_cwe_id(cwe_id)
    description = await cwe_service.get_description(cwe_id)

    if description == "See CWE database for details":
        raise HTTPException(status_code=404, detail=f"CWE-{normalized_id} not found")

    return CWEInfo(
        id=f"CWE-{normalized_id}",
        name=description,
        description=description,
    )
