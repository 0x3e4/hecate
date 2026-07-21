from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import httpx

from app.core.auth_throttle import enforce_auth_throttle, record_auth_result
from app.core.config import settings
from app.core.passwords import secret_equals

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
async def system_auth_verify(payload: SystemAuthRequest, request: Request) -> SystemAuthResponse:
    """Verify the system password (constant-time + per-client throttled)."""
    if not settings.system_password:
        return SystemAuthResponse(required=False, authenticated=True)
    key = enforce_auth_throttle(request, "system-auth")
    if secret_equals(payload.password, settings.system_password):
        record_auth_result(key, True)
        return SystemAuthResponse(required=True, authenticated=True)
    record_auth_result(key, False)
    raise HTTPException(status_code=401, detail="Invalid password.")


@router.get("/ai-auth")
async def ai_auth_status() -> SystemAuthResponse:
    """Check whether an AI analysis password is required."""
    return SystemAuthResponse(
        required=bool(settings.ai_analysis_password),
        authenticated=False,
    )


@router.post("/ai-auth")
async def ai_auth_verify(payload: SystemAuthRequest, request: Request) -> SystemAuthResponse:
    """Verify the AI analysis password (constant-time + per-client throttled)."""
    if not settings.ai_analysis_password:
        return SystemAuthResponse(required=False, authenticated=True)
    key = enforce_auth_throttle(request, "ai-auth")
    if secret_equals(payload.password, settings.ai_analysis_password):
        record_auth_result(key, True)
        return SystemAuthResponse(required=True, authenticated=True)
    record_auth_result(key, False)
    raise HTTPException(status_code=401, detail="Invalid password.")
