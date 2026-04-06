"""MCP tools for CWE and CAPEC lookups."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id
from app.mcp.server import get_rate_limiter

_CWE_ID_PATTERN = re.compile(r"^(CWE-)?[0-9]+$", re.IGNORECASE)
_CAPEC_ID_PATTERN = re.compile(r"^(CAPEC-)?[0-9]+$", re.IGNORECASE)


def register(mcp: FastMCP) -> None:
    """Register CWE and CAPEC tools on the MCP server."""

    @mcp.tool()
    async def get_cwe(cwe_id: str) -> dict[str, Any]:
        """Look up a CWE (Common Weakness Enumeration) entry by ID.

        Returns the weakness name, description, consequences, and mitigations.
        Examples:
        - get_cwe(cwe_id="CWE-79") — Cross-site Scripting (XSS)
        - get_cwe(cwe_id="89") — SQL Injection
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"cwe_id": cwe_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_cwe", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            cwe_id = cwe_id.strip()
            if not cwe_id or len(cwe_id) > 20 or not _CWE_ID_PATTERN.match(cwe_id):
                return {"error": "Invalid CWE ID format. Expected: CWE-79 or 79"}

            from app.services.cwe_service import get_cwe_service

            service = get_cwe_service()
            short_desc = await service.get_description(cwe_id)
            detailed_desc = await service.get_detailed_description(cwe_id)

            normalized = cwe_id.upper().replace("CWE-", "").strip()
            output = {
                "cweId": f"CWE-{normalized}",
                "name": short_desc,
                "detail": detailed_desc,
            }

            await log_tool_invocation(
                tool_name="get_cwe", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_cwe", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"CWE lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_capec(capec_id: str) -> dict[str, Any]:
        """Look up a CAPEC (Common Attack Pattern Enumeration and Classification) entry by ID.

        Returns the attack pattern name, description, severity, and likelihood.
        Examples:
        - get_capec(capec_id="CAPEC-66") — SQL Injection attack pattern
        - get_capec(capec_id="86") — XSS via HTTP Headers
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"capec_id": capec_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_capec", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            capec_id = capec_id.strip()
            if not capec_id or len(capec_id) > 20 or not _CAPEC_ID_PATTERN.match(capec_id):
                return {"error": "Invalid CAPEC ID format. Expected: CAPEC-66 or 66"}

            from app.services.capec_service import get_capec_service

            service = get_capec_service()
            description = await service.get_description(capec_id)

            normalized = capec_id.upper().replace("CAPEC-", "").strip()
            output = {
                "capecId": f"CAPEC-{normalized}",
                "name": description,
            }

            await log_tool_invocation(
                tool_name="get_capec", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_capec", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"CAPEC lookup failed: {str(exc)[:200]}"}
