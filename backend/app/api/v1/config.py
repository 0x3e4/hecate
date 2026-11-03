from urllib.parse import urlsplit

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.app_settings_service import AppSettingsService, get_app_settings_service

router = APIRouter()
logger = structlog.get_logger()


class PublicConfigResponse(BaseModel):
    ai_enabled: bool = Field(alias="aiEnabled", serialization_alias="aiEnabled")
    sca_enabled: bool = Field(alias="scaEnabled", serialization_alias="scaEnabled")
    sca_auto_scan_enabled: bool = Field(
        alias="scaAutoScanEnabled", serialization_alias="scaAutoScanEnabled"
    )
    support_page_enabled: bool = Field(
        alias="supportPageEnabled", serialization_alias="supportPageEnabled"
    )
    eol_enabled: bool = Field(alias="eolEnabled", serialization_alias="eolEnabled")
    ai_batch_max_vulns: int = Field(
        alias="aiBatchMaxVulns", serialization_alias="aiBatchMaxVulns"
    )
    docs_url: str | None = Field(default=None, alias="docsUrl", serialization_alias="docsUrl")
    model_config = {"populate_by_name": True}


def public_docs_url(value: str) -> str | None:
    """The Documentation link the sidebar shows, or None to hide it.

    Only http(s): the frontend renders it as an href, and another scheme such
    as javascript: would run on a click.
    """
    value = (value or "").strip()
    if not value:
        return None
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        logger.warning("config.docs_url_ignored", reason="not an http(s) URL")
        return None
    return value


@router.get("/config")
async def get_public_config(
    app_settings: AppSettingsService = Depends(get_app_settings_service),
) -> PublicConfigResponse:
    """Runtime feature flags derived from backend settings.

    Read once by the frontend at app init. No secrets — only capability bits
    and the editable AI batch limit.
    """
    ai_enabled = bool(
        settings.openai_api_key
        or settings.anthropic_api_key
        or settings.google_gemini_api_key
        or (settings.openai_compatible_base_url and settings.openai_compatible_model)
    )
    # Fall back to the env default if the settings store is unreachable so the
    # app still initialises (the frontend already degrades gracefully on error).
    try:
        ai_batch_max_vulns = await app_settings.get_ai_batch_max_vulns()
    except Exception:  # noqa: BLE001 - resilience at app init
        logger.warning("config.ai_batch_max_vulns_lookup_failed", exc_info=True)
        ai_batch_max_vulns = settings.ai_batch_max_vulns
    return PublicConfigResponse(
        ai_enabled=ai_enabled,
        sca_enabled=settings.sca_enabled,
        sca_auto_scan_enabled=settings.sca_auto_scan_enabled,
        support_page_enabled=settings.support_page_enabled,
        eol_enabled=settings.endoflife_enabled,
        ai_batch_max_vulns=ai_batch_max_vulns,
        docs_url=public_docs_url(settings.docs_url),
    )
