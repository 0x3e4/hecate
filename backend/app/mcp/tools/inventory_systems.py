"""MCP tools for the systems of the inventory (servers, VMs, Kubernetes nodes).

A system is listed once by name; its package list, findings and history come
from the SBOMs or scanner reports it pushes (its SBOM-import target), and
inventory products can be linked to it. Read tools list and fetch systems with
their report status and latest findings; write tools (create / update / delete
and applying a server list) need the write scope, like ``trigger_scan``.

Systems are addressed by id or by name (case-insensitive), so an assistant can
say ``web-01.example.com`` without looking the id up first. Server lists that
Hecate fetches itself are not offered here: they hold a credential and make the
backend send requests, which stays with admins in the web UI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, require_write_scope
from app.mcp.security import sanitize_search_input
from app.mcp.server import get_rate_limiter

log = structlog.get_logger()

_REPORT_STATUSES = ("reporting", "stale", "never")
_CLEARABLE = ("kind", "exposure", "environment", "owner", "notes")


def error_text(exc: Exception) -> str:
    """One readable line: the first validation problem, else the message."""
    if isinstance(exc, ValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc") or ())
        message = first.get("msg") or "invalid value"
        return f"{where}: {message}" if where else message
    return str(exc)[:200]


def matches(system: dict[str, Any], needle: str) -> bool:
    hay = " ".join(
        str(system.get(k) or "") for k in ("name", "kind", "exposure", "environment", "owner", "notes")
    )
    hay += " " + " ".join(system.get("groups") or [])
    hay += " " + " ".join(p.get("name", "") for p in system.get("products") or [])
    return needle in hay.lower()


def register(mcp: FastMCP) -> None:
    """Register the inventory-system tools on the MCP server."""

    async def _guard(tool: str, inputs: dict[str, Any], started_at: datetime, *, write: bool) -> str | None:
        """Rate limit, then the write scope; the refusal text, or None to go on."""
        if not get_rate_limiter().check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name=tool, inputs=inputs, success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return "Rate limit exceeded."
        if write:
            allowed, reason = require_write_scope()
            if not allowed:
                await log_tool_invocation(
                    tool_name=tool, inputs=inputs, success=False, error=f"Write denied: {reason}",
                    started_at=started_at,
                )
                return f"Write access denied. {reason}"
        return None

    async def _fail(tool: str, inputs: dict[str, Any], started_at: datetime, message: str) -> dict[str, Any]:
        await log_tool_invocation(
            tool_name=tool, inputs=inputs, success=False, error=message[:300], started_at=started_at,
        )
        return {"error": message}

    async def _done(tool: str, inputs: dict[str, Any], started_at: datetime, count: int) -> None:
        await log_tool_invocation(tool_name=tool, inputs=inputs, result_count=count, started_at=started_at)

    def _dump(system: Any) -> dict[str, Any]:
        return system.model_dump(by_alias=True, mode="json")

    @mcp.tool()
    async def list_inventory_systems(
        search: str | None = None,
        report_status: str | None = None,
        kind: str | None = None,
        exposure: str | None = None,
        group: str | None = None,
        include_retired: bool = False,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List the systems of the inventory: servers, VMs, Kubernetes nodes.

        Each system has `reportStatus` (`reporting`: an SBOM or scanner report
        arrived within `staleAfterDays`; `stale`: the last one is older; `never`),
        `lastReportAt`, `latestScanId` and `latestSummary` (findings by severity of
        its last report), `kind`, `exposure` (internet / internal), `environment`,
        `owner`, `groups`, the inventory `products` linked to it and the server
        lists naming it (`listSources`). Retired systems (dropped by their server
        list) are left out unless `include_retired` is set.

        Filters: `search` (name, owner, notes, groups, product names),
        `report_status` (reporting|stale|never), `kind`
        (host|kubernetes-node|container|other), `exposure` (internet|internal),
        `group`.

        Examples:
        - list_inventory_systems(report_status="stale") — systems that stopped reporting
        - list_inventory_systems(exposure="internet", kind="host")
        """
        tool = "list_inventory_systems"
        started_at = datetime.now(tz=UTC)
        inputs = {
            "search": search, "report_status": report_status, "kind": kind, "exposure": exposure,
            "group": group, "include_retired": include_retired, "limit": limit,
        }
        refused = await _guard(tool, inputs, started_at, write=False)
        if refused:
            return {"error": refused}
        if report_status and report_status not in _REPORT_STATUSES:
            return await _fail(tool, inputs, started_at, "report_status must be reporting, stale or never.")
        try:
            from app.services.inventory_system_service import get_inventory_system_service

            listing = await get_inventory_system_service().list_systems()
            needle = sanitize_search_input(search).lower() if search else ""
            group_key = group.strip().casefold() if group else ""
            cap = max(1, min(limit, 200))
            found: list[dict[str, Any]] = []
            for system in listing.items:
                d = _dump(system)
                if d.get("retiredAt") and not include_retired:
                    continue
                if report_status and d.get("reportStatus") != report_status:
                    continue
                if kind and d.get("kind") != kind:
                    continue
                if exposure and d.get("exposure") != exposure:
                    continue
                if group_key and group_key not in {g.casefold() for g in d.get("groups") or []}:
                    continue
                if needle and not matches(d, needle):
                    continue
                found.append(d)
            await _done(tool, inputs, started_at, min(len(found), cap))
            return {"total": len(found), "staleAfterDays": listing.stale_after_days, "items": found[:cap]}
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to list systems: {error_text(exc)}")

    @mcp.tool()
    async def get_inventory_system(system: str) -> dict[str, Any]:
        """Get one system by id or name, with its report status, latest findings and linked products.

        Its packages and findings are those of its last report: pass `latestScanId`
        to `get_scan_findings_by_scan` / `get_scan_sbom`, or `targetId` to
        `get_target_scan_history`.
        """
        tool = "get_inventory_system"
        started_at = datetime.now(tz=UTC)
        inputs = {"system": system}
        refused = await _guard(tool, inputs, started_at, write=False)
        if refused:
            return {"error": refused}
        try:
            from app.services.inventory_system_service import get_inventory_system_service

            service = get_inventory_system_service()
            doc = await service.find_system(system)
            found = await service.get_system(str(doc["_id"])) if doc else None
            if found is None:
                await _done(tool, inputs, started_at, 0)
                return {"error": "System not found."}
            await _done(tool, inputs, started_at, 1)
            return _dump(found)
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to fetch the system: {error_text(exc)}")

    @mcp.tool()
    async def create_inventory_system(
        name: str,
        kind: str | None = None,
        exposure: str | None = None,
        environment: str | None = None,
        owner: str | None = None,
        notes: str | None = None,
        groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a system to the inventory. Requires write scope.

        `name` is the host name or FQDN, unique case-insensitively. `kind` ∈
        host|kubernetes-node|container|other, `exposure` ∈ internet|internal,
        `groups` are free labels (cluster, site, team). When SBOMs already arrive
        under this name, the system is linked to them at once; otherwise the first
        SBOM pushed under the name links it.
        """
        tool = "create_inventory_system"
        started_at = datetime.now(tz=UTC)
        inputs = {"name": name, "kind": kind, "exposure": exposure}
        refused = await _guard(tool, inputs, started_at, write=True)
        if refused:
            return {"error": refused}
        try:
            from app.repositories.inventory_system_repository import SystemNameTaken
            from app.schemas.inventory_system import InventorySystemCreateRequest
            from app.services.inventory_system_service import get_inventory_system_service

            payload = InventorySystemCreateRequest.model_validate({
                "name": name, "kind": kind or None, "exposure": exposure or None, "environment": environment,
                "owner": owner, "notes": notes, "groups": groups or [],
            })
            try:
                created = await get_inventory_system_service().create_system(payload)
            except SystemNameTaken:
                return await _fail(tool, inputs, started_at, f"A system named {payload.name!r} already exists.")
            await _done(tool, inputs, started_at, 1)
            return _dump(created)
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to create the system: {error_text(exc)}")

    @mcp.tool()
    async def update_inventory_system(
        system: str,
        name: str | None = None,
        kind: str | None = None,
        exposure: str | None = None,
        environment: str | None = None,
        owner: str | None = None,
        notes: str | None = None,
        groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Change a system, addressed by id or name (partial). Requires write scope.

        Only the fields you pass change. "" clears `kind`, `exposure`,
        `environment`, `owner` or `notes`; `groups` replaces the labels ([] removes
        them all). Kind and exposure also reach the system's SBOM-import target, so
        "Affected in your scans" lists internet-facing systems first.
        """
        tool = "update_inventory_system"
        started_at = datetime.now(tz=UTC)
        inputs = {"system": system}
        refused = await _guard(tool, inputs, started_at, write=True)
        if refused:
            return {"error": refused}
        try:
            from app.repositories.inventory_system_repository import SystemNameTaken
            from app.schemas.inventory_system import InventorySystemUpdateRequest
            from app.services.inventory_system_service import get_inventory_system_service

            values = {"kind": kind, "exposure": exposure, "environment": environment, "owner": owner, "notes": notes}
            payload: dict[str, Any] = {k: (v or None) for k, v in values.items() if v is not None}
            if name is not None:
                payload["name"] = name
            if groups is not None:
                payload["groups"] = groups
            if not payload:
                return await _fail(tool, inputs, started_at, "No fields to update.")
            service = get_inventory_system_service()
            doc = await service.find_system(system)
            if doc is None:
                await _done(tool, inputs, started_at, 0)
                return {"error": "System not found."}
            try:
                updated = await service.update_system(
                    str(doc["_id"]), InventorySystemUpdateRequest.model_validate(payload),
                )
            except SystemNameTaken:
                return await _fail(tool, inputs, started_at, f"A system named {name!r} already exists.")
            if updated is None:
                await _done(tool, inputs, started_at, 0)
                return {"error": "System not found."}
            await _done(tool, inputs, started_at, 1)
            return _dump(updated)
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to update the system: {error_text(exc)}")

    @mcp.tool()
    async def delete_inventory_system(system: str) -> dict[str, Any]:
        """Remove a system, addressed by id or name. Requires write scope.

        Its links to inventory products go with it; the SBOMs it pushed, their
        findings and scan history stay, as an SCA target.
        """
        tool = "delete_inventory_system"
        started_at = datetime.now(tz=UTC)
        inputs = {"system": system}
        refused = await _guard(tool, inputs, started_at, write=True)
        if refused:
            return {"error": refused}
        try:
            from app.services.inventory_system_service import get_inventory_system_service

            service = get_inventory_system_service()
            doc = await service.find_system(system)
            deleted = bool(doc) and await service.delete_system(str(doc["_id"]))
            await _done(tool, inputs, started_at, 1 if deleted else 0)
            if not deleted:
                return {"error": "System not found.", "system": system}
            return {"deleted": True, "systemId": str(doc["_id"]), "name": doc.get("name")}
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to delete the system: {error_text(exc)}")

    @mcp.tool()
    async def import_inventory_system_list(
        content: str,
        format: str | None = None,
        source: str = "mcp",
        mode: str = "merge",
        dry_run: bool = True,
        force: bool = False,
    ) -> dict[str, Any]:
        """Apply a server list to the systems. Requires write scope. Previews by default.

        `content` is the list as text: CSV (name, kind, exposure, environment,
        owner, groups, notes), one name per line, an Ansible inventory (INI, YAML or
        `ansible-inventory --list` JSON; `hecate_kind`, `hecate_exposure`,
        `hecate_environment`, `hecate_owner`, `hecate_notes` variables) or Hecate
        JSON. `format` ∈ csv|text|ansible-ini|ansible-yaml|ansible-json|json,
        detected when omitted.

        `source` names the list: `mode="merge"` adds and updates systems,
        `mode="replace"` also retires the systems this source named before and no
        longer does (never systems added by hand or by a push). A replace that
        would retire more than half of the source's systems is refused unless
        `force` is set.

        `dry_run` is true by default: the answer says what would change and nothing
        is written. Show it to the user, then call again with `dry_run=false`.
        """
        tool = "import_inventory_system_list"
        started_at = datetime.now(tz=UTC)
        # Only what the list is, never its content: the audit log is readable by admins and stays small.
        inputs = {
            "format": format, "source": source, "mode": mode, "dry_run": dry_run, "force": force,
            "content_chars": len(content or ""),
        }
        refused = await _guard(tool, inputs, started_at, write=True)
        if refused:
            return {"error": refused}
        try:
            from app.schemas.inventory_system import InventorySystemImportRequest
            from app.services.inventory_system_lists import ListError, parse_system_list
            from app.services.inventory_system_service import ListTooDestructive, get_inventory_system_service

            request = InventorySystemImportRequest.model_validate({
                "content": content, "format": format or None, "source": source, "mode": mode,
                "dryRun": dry_run, "force": force,
            })
            try:
                parsed = parse_system_list(request.content, request.format)
                result = await get_inventory_system_service().apply_list(
                    parsed, source=request.source, mode=request.mode, dry_run=request.dry_run, force=request.force,
                )
            except ListError as exc:
                return await _fail(tool, inputs, started_at, f"Not a server list: {exc}")
            except ListTooDestructive as exc:
                return await _fail(tool, inputs, started_at, str(exc))
            if not request.dry_run:
                log.info(
                    "inventory_system.list_applied", source=request.source, mode=request.mode,
                    client=mcp_client_id.get(), format=result.format, listed=result.listed,
                    created=result.created_count, updated=result.updated_count,
                    retired=result.retired_count, restored=result.restored_count,
                )
            await _done(tool, inputs, started_at, result.listed)
            return result.model_dump(by_alias=True, mode="json")
        except Exception as exc:
            return await _fail(tool, inputs, started_at, f"Failed to apply the list: {error_text(exc)}")
