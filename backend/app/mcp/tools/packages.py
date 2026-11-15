"""MCP tool ``check_package``: may an assistant install this package?

Read-only. Same logic as ``GET /api/v1/packages/check``
(app/services/package_check_service.py): known malicious (MAL-*), known
vulnerabilities of the version, release age / unmaintained / npm publisher
change, and a verdict ``block`` | ``warn`` | ``ok`` with reasons.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id
from app.mcp.server import get_rate_limiter


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def check_package(ecosystem: str, name: str, version: str | None = None) -> dict[str, Any]:
        """Check a package before installing it: verdict block / warn / ok with reasons.

        Call this before adding or upgrading a dependency (npm install, pip
        install, go get, cargo add, ...). Follow the verdict: do not install on
        `block`; on `warn` tell the user the reasons and prefer
        `recommendedVersion` or an older, established version.

        Arguments:
        - ecosystem: npm, pypi, go, maven, cargo, nuget, rubygems or packagist
        - name: package name (npm `@scope/name`, Maven `group:artifact`, Go module path)
        - version: the version to install; omitted = the registry's latest release

        Returns `verdict`, `reasons` (level/code/message), `malicious` (MAL-*
        records and whether they cover the version), `vulnerabilities` affecting
        the version (severity, CVSS, EPSS, KEV, fixed versions), `release`
        (publishedAt, ageDays, latestVersion, freshRelease, unmaintained,
        publisherChanged, deprecated, packageFound) and `recommendedVersion`.

        Examples:
        - check_package(ecosystem="npm", name="left-pad")
        - check_package(ecosystem="pypi", name="requests", version="2.19.0")
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"ecosystem": ecosystem, "name": name, "version": version}
        if not get_rate_limiter().check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="check_package", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}
        from app.db.mongo import get_database
        from app.services.package_check_service import PackageCheckError
        from app.services.package_check_service import check_package as run_check
        from app.services.supply_chain_service import get_supply_chain_service

        try:
            database = await get_database()
            supply_chain = await get_supply_chain_service() if settings.sca_release_info_enabled else None
            result = await run_check(
                ecosystem, name, version,
                vuln_collection=database[settings.mongo_vulnerabilities_collection],
                supply_chain=supply_chain,
                max_items=max(1, min(settings.mcp_max_results, 50)),
            )
        except PackageCheckError as exc:
            await log_tool_invocation(
                tool_name="check_package", inputs=tool_inputs, success=False, error=str(exc), started_at=started_at,
            )
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            await log_tool_invocation(
                tool_name="check_package", inputs=tool_inputs, success=False,
                error=type(exc).__name__, started_at=started_at,
            )
            return {"error": "Package check failed."}
        await log_tool_invocation(
            tool_name="check_package", inputs=tool_inputs, success=True,
            result_count=len(result.get("vulnerabilities") or []), started_at=started_at,
        )
        return result
