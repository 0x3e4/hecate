"""MCP tools for vulnerability search and lookup."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id
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

    return result
