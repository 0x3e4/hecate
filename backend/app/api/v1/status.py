from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.config import settings

router = APIRouter()


@router.get("/health")
async def get_health() -> dict[str, str]:
    """Simple liveness probe."""
    return {
        "status": "ok",
        "environment": settings.environment,
        "service": "hecate-backend",
    }


class SystemAuthRequest(BaseModel):
    password: str = Field(alias="password", serialization_alias="password")
    model_config = {"populate_by_name": True}


class SystemAuthResponse(BaseModel):
    required: bool = Field(alias="required", serialization_alias="required")
    authenticated: bool = Field(alias="authenticated", serialization_alias="authenticated")
    model_config = {"populate_by_name": True}


@router.get("/system-auth")
async def system_auth_status() -> SystemAuthResponse:
    """Check whether a system password is required."""
    return SystemAuthResponse(
        required=bool(settings.system_password),
        authenticated=False,
    )


@router.post("/system-auth")
async def system_auth_verify(payload: SystemAuthRequest) -> SystemAuthResponse:
    """Verify the system password."""
    if not settings.system_password:
        return SystemAuthResponse(required=False, authenticated=True)
    if payload.password == settings.system_password:
        return SystemAuthResponse(required=True, authenticated=True)
    raise HTTPException(status_code=401, detail="Invalid password.")
