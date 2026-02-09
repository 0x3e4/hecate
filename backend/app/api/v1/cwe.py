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

    cwe_data = await cwe_service.get_bulk_cwe_data(request.cwe_ids)

    cwes = {}
    for normalized_id, desc in cwe_data.items():
        cwes[normalized_id] = CWEInfo(
            id=f"CWE-{normalized_id}",
            name=desc.name,
            description=desc.description if desc.description else desc.name,
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
    data = await cwe_service._get_cwe_data(cwe_id)

    if not data:
        raise HTTPException(status_code=404, detail=f"CWE-{normalized_id} not found")

    return CWEInfo(
        id=f"CWE-{normalized_id}",
        name=data.name,
        description=data.description if data.description else data.name,
    )
