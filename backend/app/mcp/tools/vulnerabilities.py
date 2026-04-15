"""MCP tools for vulnerability search and lookup."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, mcp_dcr_client_id, require_write_scope
from app.mcp.oauth import get_dcr_client_name
from app.mcp.security import sanitize_search_input
from app.mcp.server import get_rate_limiter

# Only allow safe vulnerability ID characters.
_VULN_ID_PATTERN = re.compile(r"^[A-Za-z0-9\-\.]+$")


def register(mcp: FastMCP) -> None:
    """Register vulnerability tools on the MCP server."""

    @mcp.tool()
    async def search_vulnerabilities(
        query: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        version: str | None = None,
        severity: list[str] | None = None,
        exploited_only: bool = False,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search the Hecate vulnerability database by keyword, vendor, product, version, or severity.

        Use this to find vulnerabilities affecting specific software. Examples:
        - search_vulnerabilities(query="log4j") — find Log4j vulnerabilities
        - search_vulnerabilities(vendor="apache", product="tomcat") — find Tomcat vulns
        - search_vulnerabilities(product="openssl", severity=["CRITICAL", "HIGH"]) — critical OpenSSL vulns
        - search_vulnerabilities(exploited_only=True, limit=20) — actively exploited vulnerabilities
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "query": query, "vendor": vendor, "product": product,
            "version": version, "severity": severity,
            "exploited_only": exploited_only, "limit": limit,
        }

        # Rate limiting
        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="search_vulnerabilities", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded. Please wait before making more requests."}]

        try:
            # Input validation
            capped_limit = max(1, min(limit, settings.mcp_max_results))

            if severity:
                valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
                severity = [s.upper() for s in severity if s.upper() in valid_severities]

            # Sanitize free-text input (strips Lucene operators)
            safe_query = sanitize_search_input(query) if query else None

            # Build VulnerabilityQuery — never uses dql_query (injection prevention)
            from app.schemas.vulnerability import VulnerabilityQuery
            from app.services.vulnerability_service import VulnerabilityService

            vuln_query = VulnerabilityQuery(
                search_term=safe_query,
                vendor_filters=[vendor] if vendor else [],
                product_filters=[product] if product else [],
                severity=severity or [],
                exploited_only=exploited_only,
                limit=capped_limit,
            )

            service = VulnerabilityService()
            results = await service.search(vuln_query)

            output = [_serialize_preview(r) for r in results]
            await log_tool_invocation(
                tool_name="search_vulnerabilities", inputs=tool_inputs,
                result_count=len(output), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="search_vulnerabilities", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"Search failed: {str(exc)[:200]}"}]

    @mcp.tool()
    async def get_vulnerability(vulnerability_id: str) -> dict[str, Any]:
        """Get full details of a specific vulnerability by its ID (e.g. CVE-2024-1234, GHSA-xxxx-xxxx, EUVD-2024-12345).

        Returns CVSS scores, CWE weaknesses, affected products/versions, references, and exploitation status.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"vulnerability_id": vulnerability_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_vulnerability", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded. Please wait before making more requests."}

        try:
            # Validate ID format
            vuln_id = vulnerability_id.strip()
            if not vuln_id or len(vuln_id) > 100 or not _VULN_ID_PATTERN.match(vuln_id):
                return {"error": "Invalid vulnerability ID format."}

            from app.services.vulnerability_service import VulnerabilityService

            service = VulnerabilityService()
            detail = await service.get_by_id(vuln_id)

            if detail is None:
                await log_tool_invocation(
                    tool_name="get_vulnerability", inputs=tool_inputs,
                    result_count=0, started_at=started_at,
                )
                return {"error": f"Vulnerability '{vuln_id}' not found in database."}

            output = _serialize_detail(detail)
            await log_tool_invocation(
                tool_name="get_vulnerability", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_vulnerability", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def prepare_vulnerability_ai_analysis(
        vulnerability_id: str,
        language: str | None = None,
        additional_context: str | None = None,
    ) -> dict[str, Any]:
        """Return the Hecate system prompt + context for analyzing a single CVE/GHSA/EUVD.

        The calling AI assistant should read `systemPrompt` and `userPrompt`, produce the analysis
        using its own model (no server-side API call, no extra cost), and then save the result by
        calling `save_vulnerability_ai_analysis(vulnerability_id, summary)`. Read-only — does not
        require write scope. Use the paired save tool to persist the analysis.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "vulnerability_id": vulnerability_id,
            "language": language,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="prepare_vulnerability_ai_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            vuln_id = vulnerability_id.strip()
            if not vuln_id or len(vuln_id) > 100 or not _VULN_ID_PATTERN.match(vuln_id):
                return {"error": "Invalid vulnerability ID format."}

            from app.services.ai_service import build_vulnerability_prompts
            from app.services.inventory_service import get_inventory_service
            from app.services.vulnerability_service import VulnerabilityService

            service = VulnerabilityService()
            vulnerability = await service.get_by_id(vuln_id)
            if vulnerability is None:
                return {"error": f"Vulnerability '{vuln_id}' not found."}

            inventory_service = await get_inventory_service()
            try:
                affected_items = await inventory_service.affected_inventory_for_vuln(vulnerability)
            except Exception:
                affected_items = []
            affected_inventory = [a.model_dump(by_alias=True) for a in affected_items]

            system_prompt, user_prompt = await build_vulnerability_prompts(
                vulnerability,
                language=language,
                additional_context=additional_context,
                affected_inventory=affected_inventory,
            )

            output = {
                "vulnerabilityId": vuln_id,
                "systemPrompt": system_prompt,
                "userPrompt": user_prompt,
                "affectedInventory": affected_inventory,
                "instructions": (
                    "Read the systemPrompt and userPrompt, generate the analysis using your own model, "
                    "then call save_vulnerability_ai_analysis(vulnerability_id, summary) to persist it. "
                    "The server will append an attribution footer identifying your client."
                ),
                "saveTool": "save_vulnerability_ai_analysis",
            }
            await log_tool_invocation(
                tool_name="prepare_vulnerability_ai_analysis", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="prepare_vulnerability_ai_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Prepare failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def save_vulnerability_ai_analysis(
        vulnerability_id: str,
        summary: str,
        language: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist an AI analysis produced by the calling assistant onto a vulnerability document.

        Use this after `prepare_vulnerability_ai_analysis`. The server stamps the stored record with a
        triggeredBy attribution like "Claude Code - MCP" and appends it as a footer in the summary.
        Requires write scope. `client_name` overrides the DCR-detected client label.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "vulnerability_id": vulnerability_id,
            "language": language, "client_name": client_name,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="save_vulnerability_ai_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="save_vulnerability_ai_analysis", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            vuln_id = vulnerability_id.strip()
            if not vuln_id or len(vuln_id) > 100 or not _VULN_ID_PATTERN.match(vuln_id):
                return {"error": "Invalid vulnerability ID format."}
            if not summary or not summary.strip():
                return {"error": "summary must not be empty."}
            if len(summary) > 200_000:
                return {"error": "summary too large (200k char limit)."}

            from app.services.ai_service import _append_attribution_footer, _normalize_language
            from app.services.vulnerability_service import VulnerabilityService

            triggered_by = _mcp_triggered_by(client_name)
            stored_summary = _append_attribution_footer(summary.strip(), triggered_by)

            assessment = {
                "provider": "mcp-client",
                "language": _normalize_language(language),
                "summary": stored_summary,
                "generatedAt": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
                "triggeredBy": triggered_by,
            }
            service = VulnerabilityService()
            ok = await service.save_ai_assessment(vuln_id, assessment)
            if not ok:
                return {"error": f"Vulnerability '{vuln_id}' not found or save failed."}

            await log_tool_invocation(
                tool_name="save_vulnerability_ai_analysis", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return {
                "vulnerabilityId": vuln_id,
                "triggeredBy": triggered_by,
                "generatedAt": assessment["generatedAt"],
                "status": "saved",
            }

        except Exception as exc:
            await log_tool_invocation(
                tool_name="save_vulnerability_ai_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Save failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def prepare_vulnerabilities_ai_batch_analysis(
        vulnerability_ids: list[str],
        language: str | None = None,
        additional_context: str | None = None,
    ) -> dict[str, Any]:
        """Return the Hecate batch system/user prompts for 1-10 vulnerabilities.

        The calling assistant should produce the combined analysis locally and then persist it with
        `save_vulnerabilities_ai_batch_analysis`. Read-only — no write scope needed.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"vulnerability_ids": vulnerability_ids, "language": language}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="prepare_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            if not vulnerability_ids:
                return {"error": "Provide 1-10 vulnerability IDs."}
            if len(vulnerability_ids) > 10:
                return {"error": "Maximum 10 vulnerability IDs per batch."}

            clean_ids: list[str] = []
            for raw in vulnerability_ids:
                vid = raw.strip()
                if not vid or len(vid) > 100 or not _VULN_ID_PATTERN.match(vid):
                    return {"error": f"Invalid vulnerability ID: {raw!r}"}
                clean_ids.append(vid)

            from app.services.ai_service import build_vulnerability_batch_prompts
            from app.services.inventory_service import get_inventory_service
            from app.services.vulnerability_service import VulnerabilityService

            service = VulnerabilityService()
            vulnerabilities = []
            for vid in clean_ids:
                detail = await service.get_by_id(vid)
                if detail is None:
                    return {"error": f"Vulnerability '{vid}' not found."}
                vulnerabilities.append(detail)

            inventory_service = await get_inventory_service()
            affected_inventory_map: dict[str, list[dict[str, Any]]] = {}
            try:
                for detail in vulnerabilities:
                    affected_items = await inventory_service.affected_inventory_for_vuln(detail)
                    if affected_items:
                        affected_inventory_map[detail.vuln_id] = [
                            a.model_dump(by_alias=True) for a in affected_items
                        ]
            except Exception:
                affected_inventory_map = {}

            system_prompt, user_prompt = await build_vulnerability_batch_prompts(
                vulnerabilities,
                language=language,
                additional_context=additional_context,
                affected_inventory_map=affected_inventory_map,
            )

            output = {
                "vulnerabilityIds": clean_ids,
                "systemPrompt": system_prompt,
                "userPrompt": user_prompt,
                "affectedInventory": affected_inventory_map,
                "instructions": (
                    "Produce the analysis using your own model. Structure your response so that after "
                    "the executive summary, each vulnerability gets its own labeled section "
                    "(e.g. 'CVE-2024-1234:'). Then call "
                    "save_vulnerabilities_ai_batch_analysis(vulnerability_ids, summary, individual_summaries)."
                ),
                "saveTool": "save_vulnerabilities_ai_batch_analysis",
            }
            await log_tool_invocation(
                tool_name="prepare_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                result_count=len(clean_ids), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="prepare_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Prepare failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def save_vulnerabilities_ai_batch_analysis(
        vulnerability_ids: list[str],
        summary: str,
        individual_summaries: dict[str, str] | None = None,
        language: str | None = None,
        additional_context: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist a batch AI analysis produced by the calling assistant.

        Provide the executive summary and (optionally) a `individual_summaries` dict keyed by
        vulnerability ID with per-vuln text. Requires write scope.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "vulnerability_ids": vulnerability_ids,
            "language": language, "client_name": client_name,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="save_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="save_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            if not vulnerability_ids:
                return {"error": "Provide 1-10 vulnerability IDs."}
            if len(vulnerability_ids) > 10:
                return {"error": "Maximum 10 vulnerability IDs per batch."}
            if not summary or not summary.strip():
                return {"error": "summary must not be empty."}
            if len(summary) > 200_000:
                return {"error": "summary too large (200k char limit)."}

            clean_ids: list[str] = []
            for raw in vulnerability_ids:
                vid = raw.strip()
                if not vid or len(vid) > 100 or not _VULN_ID_PATTERN.match(vid):
                    return {"error": f"Invalid vulnerability ID: {raw!r}"}
                clean_ids.append(vid)

            from app.services.ai_service import _append_attribution_footer, _normalize_language
            from app.services.vulnerability_service import VulnerabilityService

            triggered_by = _mcp_triggered_by(client_name)
            final_summary = _append_attribution_footer(summary.strip(), triggered_by)

            cleaned_individual: dict[str, str] = {}
            if individual_summaries:
                for vid, text in individual_summaries.items():
                    if vid in clean_ids and text and text.strip():
                        cleaned_individual[vid] = _append_attribution_footer(text.strip(), triggered_by)
            # Fill missing entries with an empty string so the schema stays consistent
            for vid in clean_ids:
                cleaned_individual.setdefault(vid, "")

            service = VulnerabilityService()
            batch_id = await service.save_batch_analysis(
                vulnerability_ids=clean_ids,
                provider="mcp-client",
                language=_normalize_language(language),
                summary=final_summary,
                individual_summaries=cleaned_individual,
                additional_context=additional_context,
                token_usage=None,
                triggered_by=triggered_by,
            )

            await log_tool_invocation(
                tool_name="save_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                result_count=len(clean_ids), started_at=started_at,
            )
            return {
                "batchId": batch_id,
                "vulnerabilityIds": clean_ids,
                "triggeredBy": triggered_by,
                "status": "saved",
            }

        except Exception as exc:
            await log_tool_invocation(
                tool_name="save_vulnerabilities_ai_batch_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Save failed: {str(exc)[:200]}"}


def _mcp_triggered_by(client_name: str | None) -> str:
    """Build the triggered_by attribution string for an MCP tool invocation."""
    name = (client_name or "").strip()
    if not name:
        name = get_dcr_client_name(mcp_dcr_client_id.get()) or ""
    if not name:
        name = "MCP Client"
    return f"{name} - MCP"


def _serialize_preview(preview: Any) -> dict[str, Any]:
    """Serialize a VulnerabilityPreview to a compact dict for MCP output."""
    data = preview.model_dump(by_alias=True, exclude_none=True)
    # Keep only the most useful fields for MCP consumers
    return {
        "vulnId": data.get("vulnId"),
        "title": data.get("title", ""),
        "summary": (data.get("summary") or "")[:2000],
        "severity": data.get("severity"),
        "cvssScore": data.get("cvssScore"),
        "epssScore": data.get("epssScore"),
        "vendors": data.get("vendors", []),
        "products": data.get("products", []),
        "productVersions": data.get("productVersions", []),
        "exploited": data.get("exploited"),
        "published": str(data["published"]) if data.get("published") else None,
        "cwes": data.get("cwes", []),
        "aliases": data.get("aliases", []),
    }


def _serialize_detail(detail: Any) -> dict[str, Any]:
    """Serialize a VulnerabilityDetail to a comprehensive dict for MCP output."""
    data = detail.model_dump(by_alias=True, exclude_none=True)

    # Truncate large fields
    summary = (data.get("summary") or "")[:2000]
    references = (data.get("references") or [])[:20]

    # Build impacted products summary
    impacted = []
    for ip in (data.get("impactedProducts") or [])[:20]:
        entry = {
            "vendor": ip.get("vendor", {}).get("name"),
            "product": ip.get("product", {}).get("name"),
            "versions": ip.get("versions", [])[:20],
        }
        if ip.get("vulnerable") is not None:
            entry["vulnerable"] = ip["vulnerable"]
        impacted.append(entry)

    result: dict[str, Any] = {
        "vulnId": data.get("vulnId"),
        "title": data.get("title", ""),
        "summary": summary,
        "severity": data.get("severity"),
        "cvssScore": data.get("cvssScore"),
        "epssScore": data.get("epssScore"),
        "vendors": data.get("vendors", []),
        "products": data.get("products", []),
        "productVersions": data.get("productVersions", []),
        "exploited": data.get("exploited"),
        "published": str(data["published"]) if data.get("published") else None,
        "modified": str(data["modified"]) if data.get("modified") else None,
        "cwes": data.get("cwes", []),
        "aliases": data.get("aliases", []),
        "references": references,
        "impactedProducts": impacted,
    }

    # Include CVSS details if available
    cvss = data.get("cvss")
    if cvss:
        result["cvss"] = {
            "version": cvss.get("version"),
            "baseScore": cvss.get("base_score") or cvss.get("baseScore"),
            "vector": cvss.get("vector"),
            "severity": cvss.get("severity"),
        }

    # Include exploitation details
    exploitation = data.get("exploitation")
    if exploitation:
        result["exploitation"] = {
            "source": exploitation.get("source"),
            "dateAdded": exploitation.get("dateAdded"),
            "requiredAction": exploitation.get("requiredAction"),
            "dueDate": exploitation.get("dueDate"),
            "knownRansomwareCampaignUse": exploitation.get("knownRansomwareCampaignUse"),
        }

    # All CVSS metric versions (not just the primary)
    cvss_metrics = data.get("cvssMetrics")
    if cvss_metrics:
        result["cvssMetrics"] = cvss_metrics

    # CPE strings (top 20)
    cpes = data.get("cpes")
    if cpes:
        result["cpes"] = cpes[:20]

    # Latest AI assessment (if any)
    ai_assessment = data.get("aiAssessment")
    if ai_assessment:
        result["aiAssessment"] = {
            "provider": ai_assessment.get("provider"),
            "language": ai_assessment.get("language"),
            "summary": (ai_assessment.get("summary") or "")[:2000],
            "generatedAt": ai_assessment.get("generatedAt"),
            "triggeredBy": ai_assessment.get("triggeredBy"),
        }

    # Batch analyses references (compact)
    batch_analyses = data.get("batchAnalyses") or []
    if batch_analyses:
        result["batchAnalyses"] = [
            {
                "batchId": b.get("batchId"),
                "provider": b.get("provider"),
                "timestamp": b.get("timestamp"),
                "summaryExcerpt": (b.get("summaryExcerpt") or "")[:300],
                "triggeredBy": b.get("triggeredBy"),
            }
            for b in batch_analyses[:10]
        ]

    # Recent change history (last 10)
    change_history = data.get("changeHistory") or []
    if change_history:
        result["changeHistory"] = change_history[-10:]

    # Timestamps useful for freshness judgments
    for key in ("firstSeenAt", "lastChangeAt", "ingestedAt"):
        if data.get(key):
            result[key] = str(data[key])

    return result
