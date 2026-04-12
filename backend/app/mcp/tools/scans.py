"""MCP tools for SCA scan findings and scan management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, require_write_scope
from app.mcp.security import sanitize_search_input
from app.mcp.server import get_rate_limiter


def register(mcp: FastMCP) -> None:
    """Register scan tools on the MCP server."""

    @mcp.tool()
    async def get_scan_findings(
        search: str | None = None,
        severity: str | None = None,
        target_id: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Query SCA scan findings across all scans. Findings include vulnerable packages found by Trivy, Grype, etc.

        Examples:
        - get_scan_findings(search="log4j") — find findings related to log4j
        - get_scan_findings(severity="CRITICAL") — find critical findings
        - get_scan_findings(target_id="my-image:latest") — findings for a specific target
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"search": search, "severity": severity, "target_id": target_id, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_scan_findings", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded."}]

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_search = sanitize_search_input(search) if search else None

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, findings = await service.get_global_findings(
                search=safe_search,
                severity=severity,
                target_id=target_id,
                limit=capped_limit,
                offset=0,
            )

            output = [_serialize_finding(f) for f in findings]
            await log_tool_invocation(
                tool_name="get_scan_findings", inputs=tool_inputs,
                result_count=len(output), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_scan_findings", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"Finding search failed: {str(exc)[:200]}"}]

    @mcp.tool()
    async def trigger_scan(
        target: str,
        target_type: str = "container_image",
        scanners: list[str] | None = None,
    ) -> dict[str, Any]:
        """Submit an SCA scan for a container image or source repository.

        Requires write scope (caller's source IP must be in MCP_WRITE_IP_SAFELIST).
        Supported target types: 'container_image', 'source_repo'.
        Default scanners: trivy, grype, syft, osv-scanner, hecate.
        Examples:
        - trigger_scan(target="nginx:latest") — scan nginx container image
        - trigger_scan(target="https://github.com/org/repo.git", target_type="source_repo")
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target": target, "target_type": target_type, "scanners": scanners}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="trigger_scan", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        # Write operation — require write scope (token scope + IP safelist)
        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="trigger_scan", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            # Validate target_type
            if target_type not in ("container_image", "source_repo"):
                return {"error": "target_type must be 'container_image' or 'source_repo'."}

            # Validate target length
            target = target.strip()
            if not target or len(target) > 500:
                return {"error": "Invalid target."}

            # Validate scanners
            valid_scanners = {"trivy", "grype", "syft", "osv-scanner", "hecate", "dockle", "dive", "semgrep", "trufflehog"}
            if scanners:
                invalid = [s for s in scanners if s not in valid_scanners]
                if invalid:
                    return {"error": f"Invalid scanners: {invalid}. Valid: {sorted(valid_scanners)}"}

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            result = await service.submit_scan(
                target=target,
                target_type=target_type,
                scanners=scanners,
                source="mcp",
            )

            output = {
                "scanId": result.get("scanId") or result.get("scan_id"),
                "status": "submitted",
                "target": target,
                "targetType": target_type,
            }
            await log_tool_invocation(
                tool_name="trigger_scan", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="trigger_scan", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Scan submission failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def trigger_sync(
        source: str,
        initial: bool = False,
    ) -> dict[str, Any]:
        """Trigger a vulnerability data sync from a specific upstream source.

        Requires write scope (caller's source IP must be in MCP_WRITE_IP_SAFELIST).
        Sources: nvd, euvd, kev, cpe, cwe, capec, circl, ghsa, osv.
        Set initial=True for a full initial sync (much slower, fetches all data).
        Examples:
        - trigger_sync(source="nvd") — incremental NVD sync
        - trigger_sync(source="kev") — sync CISA Known Exploited Vulnerabilities
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"source": source, "initial": initial}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="trigger_sync", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="trigger_sync", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            valid_sources = {"nvd", "euvd", "kev", "cpe", "cwe", "capec", "circl", "ghsa", "osv"}
            source = source.strip().lower()
            if source not in valid_sources:
                return {"error": f"Invalid source '{source}'. Valid: {sorted(valid_sources)}"}

            from app.services.sync_service import get_sync_service

            sync_service = await get_sync_service()
            trigger_method = getattr(sync_service, f"trigger_{source}_sync", None)
            if trigger_method is None:
                return {"error": f"No sync handler for source '{source}'."}

            # CIRCL sync does not support initial parameter
            if source == "circl":
                result = await trigger_method()
            else:
                result = await trigger_method(initial=initial)

            output = {
                "source": source,
                "initial": initial,
                "status": result.get("status", "triggered"),
                "message": result.get("message", f"{'Initial' if initial else 'Incremental'} sync for {source.upper()} has been triggered."),
            }
            await log_tool_invocation(
                tool_name="trigger_sync", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="trigger_sync", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Sync trigger failed: {str(exc)[:200]}"}


def _serialize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Serialize a scan finding to a compact dict for MCP output."""
    return {
        "id": finding.get("_id") or finding.get("id"),
        "vulnerabilityId": finding.get("vulnerabilityId") or finding.get("vulnerability_id"),
        "packageName": finding.get("packageName") or finding.get("package_name"),
        "packageVersion": finding.get("packageVersion") or finding.get("package_version"),
        "fixedVersion": finding.get("fixedVersion") or finding.get("fixed_version"),
        "severity": finding.get("severity"),
        "scanner": finding.get("scanner"),
        "title": finding.get("title"),
        "description": (finding.get("description") or "")[:500],
        "cvssScore": finding.get("cvssScore") or finding.get("cvss_score"),
    }
