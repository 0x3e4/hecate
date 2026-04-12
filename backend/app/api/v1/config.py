from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import settings

router = APIRouter()


class PublicConfigResponse(BaseModel):
    ai_enabled: bool = Field(alias="aiEnabled", serialization_alias="aiEnabled")
    sca_enabled: bool = Field(alias="scaEnabled", serialization_alias="scaEnabled")
    sca_auto_scan_enabled: bool = Field(
        alias="scaAutoScanEnabled", serialization_alias="scaAutoScanEnabled"
    )
    model_config = {"populate_by_name": True}


@router.get("/config")
async def get_public_config() -> PublicConfigResponse:
    """Runtime feature flags derived from backend settings.

    Read once by the frontend at app init. No secrets — only capability bits.
    """
    ai_enabled = bool(
        settings.openai_api_key
        or settings.anthropic_api_key
        or settings.google_gemini_api_key
    )
    return PublicConfigResponse(
        ai_enabled=ai_enabled,
        sca_enabled=settings.sca_enabled,
        sca_auto_scan_enabled=settings.sca_auto_scan_enabled,
    )
