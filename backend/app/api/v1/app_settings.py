from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.app_settings_service import (
    AI_BATCH_MAX_HARD_CAP,
    AppSettingsService,
    get_app_settings_service,
)

router = APIRouter()


class AppSettingsUpdate(BaseModel):
    ai_batch_max_vulns: int = Field(
        alias="aiBatchMaxVulns",
        ge=1,
        le=AI_BATCH_MAX_HARD_CAP,
        description="Maximum vulnerabilities analyzable together in one AI batch (1..100).",
    )
    model_config = {"populate_by_name": True}


class AppSettingsResponse(BaseModel):
    ai_batch_max_vulns: int = Field(
        alias="aiBatchMaxVulns", serialization_alias="aiBatchMaxVulns"
    )
    model_config = {"populate_by_name": True}


@router.put("/app-settings", response_model=AppSettingsResponse)
async def update_app_settings(
    payload: AppSettingsUpdate,
    service: AppSettingsService = Depends(get_app_settings_service),
) -> AppSettingsResponse:
    """Update runtime-editable app settings. Gated by the global admin write gate."""
    try:
        value = await service.set_ai_batch_max_vulns(payload.ai_batch_max_vulns)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AppSettingsResponse(aiBatchMaxVulns=value)
