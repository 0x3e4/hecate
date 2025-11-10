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
from app.services.cwe_service import get_cwe_service

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
        system_prompt, user_prompt = await _build_prompts(vulnerability, normalized_language)

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
            "temperature": 0.3,
            "max_tokens": 1500,
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
            "max_tokens": 1500,
            "temperature": 0.3,
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
            "temperature": 0.3,
            "max_output_tokens": 1500,
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


def _interpret_cvss_vector(vector: str) -> str:
    """Convert CVSS vector string into human-readable explanation."""
    if not vector or not isinstance(vector, str):
        return ""

    try:
        # Parse CVSS v3.x vector (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        parts = vector.split("/")
        if len(parts) < 2:
            return ""

        metrics = {}
        for part in parts[1:]:  # Skip version prefix
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        interpretations = []

        # Attack Vector
        av_map = {
            "N": "Network (remotely exploitable)",
            "A": "Adjacent Network (local network required)",
            "L": "Local (local access required)",
            "P": "Physical (physical access required)",
        }
        if "AV" in metrics:
            interpretations.append(f"Vector: {av_map.get(metrics['AV'], metrics['AV'])}")

        # Attack Complexity
        ac_map = {"L": "Low complexity", "H": "High complexity"}
        if "AC" in metrics:
            interpretations.append(f"Complexity: {ac_map.get(metrics['AC'], metrics['AC'])}")

        # Privileges Required
        pr_map = {"N": "No privileges required", "L": "Low privileges", "H": "High privileges"}
        if "PR" in metrics:
            interpretations.append(f"Privileges: {pr_map.get(metrics['PR'], metrics['PR'])}")

        # User Interaction
        ui_map = {"N": "No user interaction", "R": "User interaction required"}
        if "UI" in metrics:
            interpretations.append(f"User Interaction: {ui_map.get(metrics['UI'], metrics['UI'])}")

        # Impact: Confidentiality, Integrity, Availability
        impact_map = {"H": "High", "L": "Low", "N": "None"}
        impact_parts = []
        if "C" in metrics:
            impact_parts.append(f"Confidentiality {impact_map.get(metrics['C'], metrics['C'])}")
        if "I" in metrics:
            impact_parts.append(f"Integrity {impact_map.get(metrics['I'], metrics['I'])}")
        if "A" in metrics:
            impact_parts.append(f"Availability {impact_map.get(metrics['A'], metrics['A'])}")
        if impact_parts:
            interpretations.append(f"Impact: {', '.join(impact_parts)}")

        return "; ".join(interpretations) if interpretations else ""
    except Exception:  # pragma: no cover - defensive
        return ""


async def _get_cwe_description(cwe_id: str) -> str:
    """
    Get human-readable description for a CWE ID from MITRE API.
    Falls back to static description if API is unavailable.
    """
    cwe_service = get_cwe_service()

    try:
        # Try to get detailed description from MITRE API
        description = await cwe_service.get_detailed_description(cwe_id)
        return description
    except Exception as exc:  # pragma: no cover - fallback on errors
        logger.debug("ai_service.cwe_fetch_failed", cwe_id=cwe_id, error=str(exc))

        # Fallback to static mapping for common CWEs
        static_map = {
            "CWE-20": "Improper Input Validation",
            "CWE-22": "Path Traversal",
            "CWE-79": "Cross-Site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection",
            "CWE-78": "OS Command Injection",
            "CWE-119": "Buffer Overflow",
            "CWE-125": "Out-of-bounds Read",
            "CWE-200": "Information Disclosure",
            "CWE-287": "Improper Authentication",
            "CWE-306": "Missing Authentication",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-362": "Race Condition",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-416": "Use After Free",
            "CWE-434": "Unrestricted File Upload",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "XML External Entity (XXE)",
            "CWE-787": "Out-of-bounds Write",
            "CWE-798": "Hard-coded Credentials",
            "CWE-862": "Missing Authorization",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
        }

        normalized = cwe_id.upper().strip()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"

        return static_map.get(normalized, "See CWE database for details")


def _isoformat_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def _build_prompts(vulnerability: VulnerabilityDetail, language: str) -> tuple[str, str]:
    language_instruction = (
        f"Respond in the language identified by the ISO code '{language}'. "
        "If you are unsure which language that is, default to English."
    )

    # Enhanced system prompt with clear structure and examples
    system_prompt = (
        "You are an expert cybersecurity analyst specializing in vulnerability assessment and threat intelligence. "
        "Your role is to provide actionable, technical insights that help security teams prioritize and respond to vulnerabilities.\n\n"
        f"{language_instruction}\n\n"
        "Structure your analysis using these exact section headers:\n\n"
        "## Impact\n"
        "Explain the technical impact and real-world consequences. Consider: What can an attacker achieve? "
        "What systems/data are at risk? What is the blast radius?\n\n"
        "## Attack Scenario\n"
        "Describe a realistic attack scenario or proof-of-concept approach. Include: Attack vector, "
        "prerequisites, complexity, and typical attacker goals.\n\n"
        "## Detection\n"
        "Provide specific detection strategies. Include: Log sources to monitor, indicators of compromise (IOCs), "
        "behavioral patterns, and detection rules/queries where applicable.\n\n"
        "## Mitigation\n"
        "List concrete mitigation steps in priority order. Include: Patches, configuration changes, "
        "workarounds, and compensating controls.\n\n"
        "## Priority Assessment\n"
        "Provide a risk-based priority recommendation (CRITICAL/HIGH/MEDIUM/LOW) with justification. "
        "Consider: Exploitation status, EPSS score, CVSS severity, attack complexity, and exposure.\n\n"
        "Be specific and technical. Avoid generic advice. If information is missing, state it explicitly."
    )

    context = await _format_vulnerability_context(vulnerability)

    # Enhanced user prompt with few-shot guidance
    user_prompt = (
        "Analyze the following vulnerability using the structured format provided. "
        "Focus on actionable intelligence that helps security teams understand and respond to this threat.\n\n"
        "EXAMPLE FORMAT (use this structure):\n\n"
        "## Impact\n"
        "Remote code execution as SYSTEM/root via unauthenticated HTTP request. Attackers gain full control "
        "of the application server, enabling data exfiltration, lateral movement, and persistence.\n\n"
        "## Attack Scenario\n"
        "1. Attacker sends crafted POST request to /api/upload endpoint\n"
        "2. Malicious file bypasses validation due to path traversal (CWE-22)\n"
        "3. Server executes uploaded file with elevated privileges\n"
        "Prerequisites: Network access to vulnerable endpoint (typically Internet-facing)\n"
        "Complexity: Low - public exploits available\n\n"
        "## Detection\n"
        "- Monitor for unusual file uploads to system directories (e.g., /tmp, /var/www)\n"
        "- Alert on POST requests to /api/upload with directory traversal patterns (../, ../../)\n"
        "- Watch for unexpected process creation from web server user\n"
        "- Check application logs for HTTP 200 responses with suspicious filenames\n\n"
        "## Mitigation\n"
        "1. Apply vendor patch immediately (Product v2.1.4+)\n"
        "2. If patching delayed: Disable /api/upload endpoint or restrict to authenticated users\n"
        "3. Implement strict file upload validation (whitelist extensions, sanitize paths)\n"
        "4. Run web server with least privilege (drop SYSTEM/root)\n"
        "5. Deploy WAF rules blocking directory traversal patterns\n\n"
        "## Priority Assessment\n"
        "CRITICAL - Actively exploited (CISA KEV), trivial to exploit (CVSS 9.8), Internet-facing services common. "
        "High EPSS (85%) indicates widespread exploitation. Patch within 24-48 hours.\n\n"
        "---\n\n"
        "NOW ANALYZE THIS VULNERABILITY:\n\n"
        f"{context}"
    )

    return system_prompt, user_prompt


async def _format_vulnerability_context(vulnerability: VulnerabilityDetail) -> str:
    """Format vulnerability data into a rich, structured context for AI analysis."""
    sections: list[str] = []

    # === IDENTIFICATION ===
    id_parts: list[str] = [f"Primary ID: {vulnerability.vuln_id}"]
    if vulnerability.source_id and vulnerability.source_id != vulnerability.vuln_id:
        id_parts.append(f"Source ID: {vulnerability.source_id}")
    if vulnerability.aliases:
        aliases = [alias for alias in vulnerability.aliases if alias != vulnerability.vuln_id][:4]
        if aliases:
            id_parts.append(f"Aliases: {', '.join(aliases)}")
    sections.append("IDENTIFICATION:\n" + "\n".join(id_parts))

    # === VULNERABILITY OVERVIEW ===
    overview_parts: list[str] = []
    if vulnerability.title:
        overview_parts.append(f"Title: {vulnerability.title}")
    if vulnerability.summary:
        # Truncate very long summaries but keep most of it
        summary = vulnerability.summary[:800] + ("..." if len(vulnerability.summary) > 800 else "")
        overview_parts.append(f"Description: {summary}")
    if vulnerability.assigner:
        overview_parts.append(f"Assigned by: {vulnerability.assigner}")
    if overview_parts:
        sections.append("OVERVIEW:\n" + "\n".join(overview_parts))

    # === SEVERITY & RISK METRICS ===
    risk_parts: list[str] = []
    if vulnerability.severity:
        risk_parts.append(f"Severity: {vulnerability.severity}")
    if vulnerability.cvss_score is not None:
        risk_parts.append(f"CVSS Base Score: {vulnerability.cvss_score:.1f}/10.0")

    # Decode CVSS vector for better understanding
    if vulnerability.cvss and hasattr(vulnerability.cvss, "vector"):
        cvss_interpretation = _interpret_cvss_vector(vulnerability.cvss.vector)
        if cvss_interpretation:
            risk_parts.append(f"CVSS Breakdown: {cvss_interpretation}")

    if vulnerability.epss_score is not None:
        # EPSS is 0-1, convert to percentage
        epss_percent = vulnerability.epss_score * 100 if vulnerability.epss_score <= 1.0 else vulnerability.epss_score
        risk_parts.append(f"EPSS (Exploitation Probability): {epss_percent:.1f}%")

    if risk_parts:
        sections.append("SEVERITY & RISK:\n" + "\n".join(risk_parts))

    # === EXPLOITATION STATUS ===
    if vulnerability.exploited or vulnerability.exploitation:
        exploit_parts: list[str] = []
        if vulnerability.exploited:
            exploit_parts.append("⚠ ACTIVELY EXPLOITED IN THE WILD")

        if vulnerability.exploitation:
            info = vulnerability.exploitation
            if info.source:
                exploit_parts.append(f"Source: {info.source}")
            if info.vendor_project:
                exploit_parts.append(f"Affected: {info.vendor_project}")
            if info.product:
                exploit_parts.append(f"Product: {info.product}")
            if info.short_description:
                exploit_parts.append(f"Details: {info.short_description}")
            if info.required_action:
                exploit_parts.append(f"Required Action: {info.required_action}")
            if info.due_date:
                exploit_parts.append(f"Remediation Due: {info.due_date}")
            if info.known_ransomware_campaign_use:
                exploit_parts.append(f"Ransomware Use: {info.known_ransomware_campaign_use}")

        sections.append("EXPLOITATION STATUS:\n" + "\n".join(exploit_parts))

    # === AFFECTED PRODUCTS ===
    affected_parts: list[str] = []
    if vulnerability.impacted_products:
        for idx, impacted in enumerate(vulnerability.impacted_products[:5]):
            vendor = impacted.vendor.name if impacted.vendor else "Unknown"
            product = impacted.product.name if impacted.product else "Unknown"
            versions = ", ".join(impacted.versions[:10]) if impacted.versions else "All versions"
            envs = f" ({', '.join(impacted.environments)})" if impacted.environments else ""
            affected_parts.append(f"- {vendor} {product}: {versions}{envs}")
        if len(vulnerability.impacted_products) > 5:
            affected_parts.append(f"... and {len(vulnerability.impacted_products) - 5} more products")
    elif vulnerability.vendors or vulnerability.products:
        if vulnerability.vendors:
            affected_parts.append(f"Vendors: {', '.join(vulnerability.vendors[:8])}")
        if vulnerability.products:
            affected_parts.append(f"Products: {', '.join(vulnerability.products[:8])}")
        if vulnerability.product_versions:
            versions_str = ', '.join(vulnerability.product_versions[:10])
            if len(vulnerability.product_versions) > 10:
                versions_str += f" (+{len(vulnerability.product_versions) - 10} more)"
            affected_parts.append(f"Versions: {versions_str}")

    if affected_parts:
        sections.append("AFFECTED PRODUCTS:\n" + "\n".join(affected_parts))

    # === WEAKNESS CLASSIFICATION ===
    weakness_parts: list[str] = []
    if vulnerability.cwes:
        cwe_descriptions = []
        for cwe in vulnerability.cwes[:5]:
            cwe_desc = await _get_cwe_description(cwe)
            cwe_descriptions.append(f"- {cwe}: {cwe_desc}")
        weakness_parts.extend(cwe_descriptions)
    if weakness_parts:
        sections.append("WEAKNESS TYPES (CWE):\n" + "\n".join(weakness_parts))

    # === REFERENCES ===
    if vulnerability.references:
        ref_list = []
        for ref in vulnerability.references[:8]:
            # Shorten very long URLs for readability
            display_ref = ref if len(ref) <= 100 else ref[:97] + "..."
            ref_list.append(f"- {display_ref}")
        if len(vulnerability.references) > 8:
            ref_list.append(f"... and {len(vulnerability.references) - 8} more references")
        sections.append("REFERENCES:\n" + "\n".join(ref_list))

    # === TIMELINE ===
    timeline_parts: list[str] = []
    if vulnerability.published:
        timeline_parts.append(f"Published: {vulnerability.published.strftime('%Y-%m-%d')}")
    if vulnerability.modified:
        timeline_parts.append(f"Last Modified: {vulnerability.modified.strftime('%Y-%m-%d')}")
    if timeline_parts:
        sections.append("TIMELINE:\n" + "\n".join(timeline_parts))

    return "\n\n".join(sections)


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
