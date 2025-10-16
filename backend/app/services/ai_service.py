from typing import Any

import httpx

from app.core.config import settings


class AIClient:
    """
    Thin wrapper around OpenAI-compatible APIs.
    Designed for dependency injection and later vendor abstraction.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=30.0)

    async def analyze_vulnerability(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Submit a vulnerability context to the AI provider.
        Currently returns a stub response until integration is completed.
        """
        _ = payload

        if not settings.openai_api_key:
            return {
                "status": "disabled",
                "reason": "OPENAI_API_KEY not configured",
            }

        # TODO: implement call to OpenAI or compatible endpoint
        return {"status": "pending"}
