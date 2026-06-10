from __future__ import annotations

from app.core.config import settings
from app.repositories.app_settings_repository import AppSettingsRepository

# Hard safety cap shared by the request schema, the write-endpoint validation and
# this service. The configured value can be anywhere in 1..AI_BATCH_MAX_HARD_CAP.
AI_BATCH_MAX_HARD_CAP = 100

_AI_BATCH_KEY = "aiBatchMaxVulns"


class AppSettingsService:
    """Business logic for runtime-editable app settings.

    Each getter falls back to the env-based default in ``settings`` when no
    override is stored, so the feature works out of the box and degrades to the
    env value if the store is empty or unreachable.
    """

    async def get_ai_batch_max_vulns(self) -> int:
        repository = await AppSettingsRepository.create()
        document = await repository.get()
        stored = (document or {}).get(_AI_BATCH_KEY)
        if isinstance(stored, int) and 1 <= stored <= AI_BATCH_MAX_HARD_CAP:
            return stored
        return settings.ai_batch_max_vulns

    async def set_ai_batch_max_vulns(self, value: int) -> int:
        if not isinstance(value, int) or not (1 <= value <= AI_BATCH_MAX_HARD_CAP):
            raise ValueError(
                f"ai_batch_max_vulns must be an integer between 1 and {AI_BATCH_MAX_HARD_CAP}."
            )
        await (await AppSettingsRepository.create()).set_value(_AI_BATCH_KEY, value)
        return value


def get_app_settings_service() -> AppSettingsService:
    return AppSettingsService()
