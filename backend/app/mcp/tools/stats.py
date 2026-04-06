"""MCP tools for vulnerability database statistics."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id
from app.mcp.server import get_rate_limiter


def register(mcp: FastMCP) -> None:
    """Register statistics tools on the MCP server."""

    @mcp.tool()
    async def get_vulnerability_stats() -> dict[str, Any]:
        """Get vulnerability database statistics: total counts, severity distribution, top vendors, top products, and exploited count.

        No parameters needed. Returns an overview of the current vulnerability database state.
        """
        started_at = datetime.now(tz=UTC)

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_vulnerability_stats", inputs={},
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            from app.services.stats_service import get_stats_service

            service = get_stats_service()
            overview = await service.get_overview()

            # Return a summarized version (the full stats can be very large)
            vuln_stats = overview.get("vulnerabilities", {})
            asset_stats = overview.get("assets", {})

            output: dict[str, Any] = {
                "totalVulnerabilities": vuln_stats.get("total", 0),
                "exploitedCount": vuln_stats.get("exploitedCount", 0),
                "severities": vuln_stats.get("severities", []),
                "topVendors": vuln_stats.get("topVendors", [])[:10],
                "topProducts": vuln_stats.get("topProducts", [])[:10],
                "sources": vuln_stats.get("sources", []),
                "assets": {
                    "vendorTotal": asset_stats.get("vendorTotal", 0),
                    "productTotal": asset_stats.get("productTotal", 0),
                },
            }

            await log_tool_invocation(
                tool_name="get_vulnerability_stats", inputs={},
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_vulnerability_stats", inputs={},
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Stats retrieval failed: {str(exc)[:200]}"}
