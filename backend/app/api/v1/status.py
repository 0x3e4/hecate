from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import httpx

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


class ScannerHealthResponse(BaseModel):
    enabled: bool = Field(alias="enabled", serialization_alias="enabled")
    reachable: bool = Field(alias="reachable", serialization_alias="reachable")
    model_config = {"populate_by_name": True}


@router.get("/scanner-health")
async def scanner_health() -> ScannerHealthResponse:
    """Check whether the scanner sidecar is reachable."""
    enabled = settings.sca_enabled
    if not enabled:
        return ScannerHealthResponse(enabled=False, reachable=False)
    url = f"{settings.sca_scanner_url}/health"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)
            reachable = response.status_code < 400
    except Exception:
        reachable = False
    return ScannerHealthResponse(enabled=True, reachable=reachable)


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


@router.get("/ai-auth")
async def ai_auth_status() -> SystemAuthResponse:
    """Check whether an AI analysis password is required."""
    return SystemAuthResponse(
        required=bool(settings.ai_analysis_password),
        authenticated=False,
    )


@router.post("/ai-auth")
async def ai_auth_verify(payload: SystemAuthRequest) -> SystemAuthResponse:
    """Verify the AI analysis password."""
    if not settings.ai_analysis_password:
        return SystemAuthResponse(required=False, authenticated=True)
    if payload.password == settings.ai_analysis_password:
        return SystemAuthResponse(required=True, authenticated=True)
    raise HTTPException(status_code=401, detail="Invalid password.")
