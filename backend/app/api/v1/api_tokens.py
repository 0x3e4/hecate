from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.api_token import ApiTokenCreatedResponse, ApiTokenCreateRequest, ApiTokenListResponse
from app.services.api_token_service import ApiTokenService, get_api_token_service
from app.services.audit_service import AuditService, get_audit_service

router = APIRouter()


@router.get("", response_model=ApiTokenListResponse)
async def list_api_tokens(
    service: ApiTokenService = Depends(get_api_token_service),
) -> ApiTokenListResponse:
    return ApiTokenListResponse(items=await service.list_tokens())


@router.post("", response_model=ApiTokenCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_token(
    payload: ApiTokenCreateRequest,
    service: ApiTokenService = Depends(get_api_token_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ApiTokenCreatedResponse:
    """Create a token. This response is the only time it is shown."""
    created = await service.create_token(payload)
    await audit_service.record_event(
        "api_token_created",
        metadata={"label": "API token created", "tokenName": created.name},
        result={"name": created.name, "scopes": created.scopes},
    )
    return created


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_token(
    token_id: str,
    service: ApiTokenService = Depends(get_api_token_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    revoked = await service.revoke_token(token_id)
    if revoked is None:
        raise HTTPException(status_code=404, detail="API token not found")
    await audit_service.record_event(
        "api_token_revoked",
        metadata={"label": "API token revoked", "tokenName": revoked["name"]},
        result={"name": revoked["name"], "scopes": revoked["scopes"]},
    )
