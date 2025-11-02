from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, AsyncIterator

import httpx

try:  # pragma: no cover - optional dependency
    import google.generativeai as genai
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    genai = None  # type: ignore[assignment]

import structlog
from app.core.config import settings
from app.schemas.ai import (
    AIInvestigationResponse,
    AIProviderInfo,
    AIProviderLiteral,
)
from app.schemas.vulnerability import VulnerabilityDetail

AI_PROVIDER_LABELS: dict[AIProviderLiteral, str] = {
    "openai": "OpenAI GPT",
    "anthropic": "Anthropic Claude",
    "gemini": "Google Gemini",
}


class AIProviderError(RuntimeError):
    """Raised when a provider call fails or returns an unexpected payload."""


class AIClient:
    """
    Wrapper around the supported AI providers.
    Responsible for building prompts and normalising provider responses.
    """

    def __init__(self, client: httpx.AsyncClient | None = None, *, timeout: float = 45.0) -> None:
        self._client = client
        self._timeout = timeout

    def get_available_providers(self) -> list[AIProviderInfo]:
        """Return the configured providers."""
        providers: list[AIProviderInfo] = []
        if settings.openai_api_key:
            providers.append(AIProviderInfo(id="openai", label=AI_PROVIDER_LABELS["openai"]))
        if settings.anthropic_api_key:
            providers.append(AIProviderInfo(id="anthropic", label=AI_PROVIDER_LABELS["anthropic"]))
        if settings.google_gemini_api_key and genai is not None:
            providers.append(AIProviderInfo(id="gemini", label=AI_PROVIDER_LABELS["gemini"]))
        return providers

    async def analyze_vulnerability(
        self,
        provider: AIProviderLiteral,
        vulnerability: VulnerabilityDetail,
        *,
        language: str | None = None,
    ) -> AIInvestigationResponse:
        """
        Submit a vulnerability context to the requested provider and return the summarised response.
        """
        normalized_language = _normalize_language(language)
        system_prompt, user_prompt = _build_prompts(vulnerability, normalized_language)

        if provider == "openai":
            if not settings.openai_api_key:
                raise ValueError("OpenAI provider is not configured.")
            summary = await self._call_openai(system_prompt, user_prompt)
        elif provider == "anthropic":
            if not settings.anthropic_api_key:
                raise ValueError("Anthropic provider is not configured.")
            summary = await self._call_anthropic(system_prompt, user_prompt)
        elif provider == "gemini":
            if not settings.google_gemini_api_key:
                raise ValueError("Google Gemini provider is not configured.")
            summary = await self._call_gemini(system_prompt, user_prompt)
        else:  # pragma: no cover - defensive programming
            raise ValueError(f"Unsupported provider '{provider}'.")

        return AIInvestigationResponse(
            provider=provider,
            language=normalized_language,
            summary=summary,
            generatedAt=_isoformat_utc_now(),
        )

    @asynccontextmanager
    async def _get_client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            yield client

    async def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": (settings.openai_model or "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 600,
        }
        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with self._get_client() as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self._timeout,
                )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:  # pragma: no cover - network failure
            detail = exc.response.text[:300]
            raise AIProviderError(f"OpenAI request failed ({exc.response.status_code}): {detail}") from exc
        except httpx.HTTPError as exc:  # pragma: no cover - network failure
            raise AIProviderError(f"OpenAI request failed: {exc}") from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:  # pragma: no cover - defensive
            raise AIProviderError("OpenAI response format was not recognised.") from exc
        return content.strip()

    async def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": settings.anthropic_model or "claude-3-haiku-20240307",
            "max_tokens": 600,
            "temperature": 0.2,
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": user_prompt,
                        }
                    ],
                }
            ],
        }
        headers = {
            "x-api-key": settings.anthropic_api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        try:
            async with self._get_client() as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                    timeout=self._timeout,
                )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:  # pragma: no cover - network failure
            detail = exc.response.text[:300]
            raise AIProviderError(
                f"Anthropic request failed ({exc.response.status_code}): {detail}"
            ) from exc
        except httpx.HTTPError as exc:  # pragma: no cover - network failure
            raise AIProviderError(f"Anthropic request failed: {exc}") from exc

        content_blocks = data.get("content")
        if isinstance(content_blocks, list):
            for block in content_blocks:
                if not isinstance(block, dict):
                    continue
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
                inner_parts = block.get("content")
                if isinstance(inner_parts, list):
                    for part in inner_parts:
                        if isinstance(part, dict):
                            inner_text = part.get("text")
                            if isinstance(inner_text, str) and inner_text.strip():
                                return inner_text.strip()

        raise AIProviderError("Anthropic response did not contain any text.")

    async def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        if genai is None:
            raise AIProviderError(
                "Gemini provider requires the google-generativeai package. Install it to continue."
            )
        if not settings.google_gemini_api_key:
            raise ValueError("Google Gemini provider is not configured.")

        logger.debug(
            "gemini.request.start",
            model=settings.google_gemini_model,
            language=_normalize_language(None),
            prompt_preview=user_prompt[:200],
        )

        model_name = settings.google_gemini_model or "gemini-1.5-flash"
        generation_config = {
            "temperature": 0.2,
            "max_output_tokens": 600,
        }

        def _invoke() -> str:
            genai.configure(api_key=settings.google_gemini_api_key)
            safety_settings = None
            try:
                from google.generativeai.types import HarmBlockThreshold, HarmCategory  # type: ignore
            except (ImportError, AttributeError):  # pragma: no cover - optional
                safety_settings = None
            else:
                category_names = [
                    "HARM_CATEGORY_HARASSMENT",
                    "HARM_CATEGORY_HATE_SPEECH",
                    "HARM_CATEGORY_SEXUAL",
                    "HARM_CATEGORY_SEXUAL_CONTENT",
                    "HARM_CATEGORY_DANGEROUS",
                    "HARM_CATEGORY_DANGEROUS_CONTENT",
                ]
                threshold = getattr(HarmBlockThreshold, "BLOCK_NONE", None)
                safety_settings = {}
                for name in category_names:
                    category = getattr(HarmCategory, name, None)
                    if category is not None and threshold is not None:
                        safety_settings[category] = threshold
                if not safety_settings:
                    safety_settings = None

            model = genai.GenerativeModel(
                model_name=model_name,
                system_instruction=system_prompt,
                generation_config=generation_config,
            )
            kwargs: dict[str, Any] = {}
            if safety_settings is not None:
                kwargs["safety_settings"] = safety_settings
            response = model.generate_content(
                user_prompt,
                **kwargs,
            )
            logger.debug(
                "gemini.response.raw",
                response=str(response),
                prompt_preview=user_prompt[:200],
            )

            try:
                text = getattr(response, "text", None)
            except ValueError:
                text = None
            if isinstance(text, str) and text.strip():
                logger.debug("gemini.response.text", length=len(text))
                return text.strip()

            candidates = getattr(response, "candidates", None) or []
            for candidate in candidates:
                finish_reason = getattr(candidate, "finish_reason", None)
                if finish_reason:
                    finish_value = str(getattr(finish_reason, "name", finish_reason)).upper()
                    if finish_value in {"MAX_TOKENS", "FINISH_REASON_MAX_TOKENS"}:
                        raise AIProviderError(
                            "Gemini request stopped early due to the max token limit. "
                            "Consider reducing prompt size or requesting a higher limit."
                        )
                    if finish_value not in {"STOP", "FINISH_REASON_STOP"}:
                        raise AIProviderError(f"Gemini request ended early: {finish_reason}")
                content = getattr(candidate, "content", None)
                parts = getattr(content, "parts", None) if content is not None else None
                if not parts:
                    continue
                for part in parts:
                    part_text = getattr(part, "text", None)
                    if isinstance(part_text, str) and part_text.strip():
                        logger.debug("gemini.response.part_text", length=len(part_text))
                        return part_text.strip()

            raise AIProviderError("Gemini response did not contain any text.")

        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, _invoke)
        except AIProviderError:
            logger.exception("gemini.response.error")
            raise
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("gemini.response.exception")
            raise AIProviderError(f"Gemini request failed: {exc}") from exc


def _normalize_language(language: str | None) -> str:
    candidate = (language or settings.ai_response_language or "en").strip()
    return candidate or "en"


def _isoformat_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_prompts(vulnerability: VulnerabilityDetail, language: str) -> tuple[str, str]:
    language_instruction = (
        f"Respond in the language identified by the ISO code '{language}'. "
        "If you are unsure which language that is, default to English."
    )
    system_prompt = (
        "You are an experienced cybersecurity analyst. Provide concise and actionable insights. "
        f"{language_instruction} "
        "Structure the answer using prefixed with the labels:\n"
        "Impact:\nReplication:\nDetection:\nMitigation:\nUrgency"
    )

    context = _format_vulnerability_context(vulnerability)
    user_prompt = (
        "Assess the following vulnerability information. "
        "Focus on real-world impact, feasible replication or testing ideas, practical detection hints, "
        "mitigation or workarounds, and whether fast remediation is advised considering exploitation signals "
        "or exposure. Use only the provided data; if something is unclear, say so.\n\n"
        f"Vulnerability details:\n{context}"
    )

    return system_prompt, user_prompt


def _format_vulnerability_context(vulnerability: VulnerabilityDetail) -> str:
    lines: list[str] = []
    identifiers = [vulnerability.vuln_id]
    if vulnerability.source_id and vulnerability.source_id not in identifiers:
        identifiers.append(vulnerability.source_id)
    if vulnerability.aliases:
        aliases = [alias for alias in vulnerability.aliases if alias not in identifiers]
        identifiers.extend(aliases[:3])
    if identifiers:
        lines.append(f"Identifiers: {', '.join(filter(None, identifiers))}")
    if vulnerability.title:
        lines.append(f"Title: {vulnerability.title}")
    if vulnerability.summary:
        lines.append(f"Summary: {vulnerability.summary}")

    risk_bits: list[str] = []
    if vulnerability.severity:
        risk_bits.append(f"Severity {vulnerability.severity}")
    if vulnerability.cvss_score is not None:
        risk_bits.append(f"CVSS {vulnerability.cvss_score:.1f}")
    if vulnerability.epss_score is not None:
        risk_bits.append(f"EPSS {vulnerability.epss_score:.2f}%")
    if vulnerability.exploited:
        risk_bits.append("Known exploited: yes")
    if risk_bits:
        lines.append("Risk indicators: " + ", ".join(risk_bits))

    if vulnerability.exploitation:
        exploitation_parts: list[str] = []
        info = vulnerability.exploitation
        if info.vendor_project:
            exploitation_parts.append(f"Vendor/Project: {info.vendor_project}")
        if info.product:
            exploitation_parts.append(f"Product: {info.product}")
        if info.short_description:
            exploitation_parts.append(f"Notes: {info.short_description}")
        if exploitation_parts:
            lines.append("Known exploitation details: " + "; ".join(exploitation_parts))

    if vulnerability.vendors:
        lines.append("Vendors: " + ", ".join(vulnerability.vendors[:5]))
    if vulnerability.products:
        lines.append("Products: " + ", ".join(vulnerability.products[:5]))
    if vulnerability.cwes:
        lines.append("CWEs: " + ", ".join(vulnerability.cwes[:5]))
    if vulnerability.references:
        lines.append("References: " + "; ".join(vulnerability.references[:5]))

    if vulnerability.cpes:
        lines.append("CPEs: " + "; ".join(vulnerability.cpes[:3]))

    return "\n".join(lines)


@lru_cache(maxsize=1)
def get_ai_client() -> AIClient:
    return AIClient()

    async def analyze_vulnerability(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit a vulnerability context to the AI provider."""

        if not settings.openai_api_key:
            return {
                "status": "disabled",
                "reason": "OPENAI_API_KEY not configured",
            }

        request_payload = dict(payload)
        endpoint = request_payload.pop("endpoint", "https://api.openai.com/v1/chat/completions")
        timeout = request_payload.pop("timeout", 30.0)
        headers = request_payload.pop("headers", {}) or {}
        headers.setdefault("Authorization", f"Bearer {settings.openai_api_key}")
        headers.setdefault("Content-Type", "application/json")
        request_payload.setdefault("model", settings.openai_model or "gpt-4o-mini")

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(endpoint, headers=headers, json=request_payload)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:300]
            return {
                "status": "error",
                "reason": f"{exc.response.status_code}: {detail}",
            }
        except httpx.HTTPError as exc:
            return {
                "status": "error",
                "reason": str(exc),
            }

        data = response.json()
        return {
            "status": "ok",
            "response": data,
        }
logger = structlog.get_logger(__name__)
