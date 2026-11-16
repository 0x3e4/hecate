from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.auth_context import get_auth_context
from app.core.auth_throttle import SYSTEM_SECRET, AI_SECRET, enforce_auth_throttle, record_auth_result
from app.core.config import settings
from app.core.passwords import secret_equals
from app.services.http.scanner import scanner_client

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
    """Check whether the scanner sidecar is reachable and takes our secret.

    Asks /stats, not /health: /health stays open for container probes, so it
    would report a healthy scanner that rejects every scan.
    """
    enabled = settings.sca_enabled
    if not enabled:
        return ScannerHealthResponse(enabled=False, reachable=False)
    url = f"{settings.sca_scanner_url}/stats"
    try:
        async with scanner_client(timeout=5) as client:
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
    # The System page's settings are closed to this caller (require_admin_read):
    # it needs the admin role or, when one is set, the system password.
    admin_required: bool | None = Field(default=None, alias="adminRequired", serialization_alias="adminRequired")
    password_accepted: bool | None = Field(
        default=None, alias="passwordAccepted", serialization_alias="passwordAccepted"
    )
    model_config = {"populate_by_name": True}


@router.get("/system-auth")
async def system_auth_status(request: Request) -> SystemAuthResponse:
    """Check whether a system password is required.

    Not for a signed-in admin: the role opens everything the password does, so
    the System and Audit pages skip their unlock dialog.
    """
    ctx = await get_auth_context(request)
    if ctx.user is not None and ctx.user.has_role("admin"):
        return SystemAuthResponse(required=False, authenticated=True, admin_required=False, password_accepted=False)
    return SystemAuthResponse(
        required=bool(settings.system_password),
        authenticated=False,
        # Mirrors require_admin_read: with OIDC nobody below admin reads the
        # settings, without it only the system password closes them.
        admin_required=bool(settings.system_password) or settings.oidc_enabled,
        password_accepted=bool(settings.system_password),
    )


@router.post("/system-auth")
async def system_auth_verify(payload: SystemAuthRequest, request: Request) -> SystemAuthResponse:
    """Verify the system password (constant-time + per-client throttled)."""
    if not settings.system_password:
        return SystemAuthResponse(required=False, authenticated=True)
    key = enforce_auth_throttle(request, SYSTEM_SECRET)
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
    key = enforce_auth_throttle(request, AI_SECRET)
    if secret_equals(payload.password, settings.ai_analysis_password):
        record_auth_result(key, True)
        return SystemAuthResponse(required=True, authenticated=True)
    record_auth_result(key, False)
    raise HTTPException(status_code=401, detail="Invalid password.")
