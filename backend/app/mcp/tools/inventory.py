"""MCP tools for the environment inventory (CRUD + endoflife.date status).

Read tools list/return the products & versions the user has declared, each with
its endoflife.date support status (active / security / end-of-life, the
support-until date, LTS, the latest release, and the newest / next release
line). Write tools (create / update / delete) require write scope, mirroring
`trigger_scan` / `trigger_sync`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, require_write_scope
from app.mcp.security import sanitize_search_input
from app.mcp.server import get_rate_limiter


def register(mcp: FastMCP) -> None:
    """Register environment-inventory tools on the MCP server."""

    async def _attach_eol(service: Any, item_dict: dict[str, Any]) -> dict[str, Any]:
        """Best-effort endoflife.date status under the ``eol`` key (cached)."""
        try:
            eol = await service.get_item_eol_status(item_dict["id"])
            item_dict["eol"] = eol.model_dump(by_alias=True, mode="json") if eol else None
        except Exception:  # noqa: BLE001 - EOL is enrichment, never fatal
            item_dict["eol"] = None
        return item_dict

    @mcp.tool()
    async def list_inventory_items(
        search: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List environment inventory items (the products/versions you run).

        Each item includes its endoflife.date support status under `eol`:
        status (active/security/eol/unknown), `eolDate` (supported until),
        `eoasDate`, `isLts`/`ltsFrom`, `latestVersion`/`isOutdated`,
        `latestCycle`/`nextCycle`, and `productLink`.

        Examples:
        - list_inventory_items() — all items
        - list_inventory_items(search="nginx") — items matching "nginx"
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"search": search, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="list_inventory_items", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded."}]

        try:
            from app.services.inventory_service import get_inventory_service

            service = await get_inventory_service()
            items = await service.list_items()
            needle = sanitize_search_input(search).lower() if search else ""
            cap = max(1, min(limit, 200))

            results: list[dict[str, Any]] = []
            for it in items:
                d = it.model_dump(by_alias=True, mode="json")
                if needle:
                    hay = " ".join(
                        str(d.get(k) or "")
                        for k in (
                            "name", "vendorSlug", "productSlug", "vendorName",
                            "productName", "version", "environment", "owner",
                        )
                    ).lower()
                    if needle not in hay:
                        continue
                results.append(d)
                if len(results) >= cap:
                    break

            for d in results:
                await _attach_eol(service, d)

            await log_tool_invocation(
                tool_name="list_inventory_items", inputs=tool_inputs,
                result_count=len(results), started_at=started_at,
            )
            return results
        except Exception as exc:
            await log_tool_invocation(
                tool_name="list_inventory_items", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"Failed to list inventory: {str(exc)[:200]}"}]

    @mcp.tool()
    async def get_inventory_item(item_id: str) -> dict[str, Any]:
        """Get one inventory item by id, including its endoflife.date status (`eol`)."""
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"item_id": item_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_inventory_item", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            from app.services.inventory_service import get_inventory_service

            service = await get_inventory_service()
            item = await service.get_item(item_id)
            if item is None:
                await log_tool_invocation(
                    tool_name="get_inventory_item", inputs=tool_inputs,
                    result_count=0, started_at=started_at,
                )
                return {"error": "Inventory item not found."}
            d = await _attach_eol(service, item.model_dump(by_alias=True, mode="json"))
            await log_tool_invocation(
                tool_name="get_inventory_item", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return d
        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_inventory_item", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Failed to fetch inventory item: {str(exc)[:200]}"}

    @mcp.tool()
    async def create_inventory_item(
        name: str,
        vendor_slug: str,
        product_slug: str,
        version: str,
        vendor_name: str | None = None,
        product_name: str | None = None,
        deployment: str = "onprem",
        environment: str = "prod",
        instance_count: int = 1,
        owner: str | None = None,
        notes: str | None = None,
        eol_product: str | None = None,
    ) -> dict[str, Any]:
        """Create an environment inventory item. Requires write scope.

        `deployment` ∈ onprem|cloud|hybrid. `version` is exact (`8.0.25`) or a
        wildcard (`8.0.*`). Leave `eol_product` unset to auto-link the
        endoflife.date product by name; set it to override, or "" to leave unlinked.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"name": name, "vendor_slug": vendor_slug, "product_slug": product_slug, "version": version}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="create_inventory_item", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="create_inventory_item", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            from app.schemas.inventory import InventoryItemCreateRequest
            from app.services.inventory_service import get_inventory_service

            payload: dict[str, Any] = {
                "name": name,
                "vendorSlug": vendor_slug,
                "productSlug": product_slug,
                "version": version,
                "vendorName": vendor_name,
                "productName": product_name,
                "deployment": deployment,
                "environment": environment,
                "instanceCount": instance_count,
                "owner": owner,
                "notes": notes,
            }
            # Only pass eolProduct when explicitly provided, so an omitted value
            # lets the service auto-match the endoflife.date product.
            if eol_product is not None:
                payload["eolProduct"] = eol_product

            service = await get_inventory_service()
            item = await service.create_item(InventoryItemCreateRequest.model_validate(payload))
            d = item.model_dump(by_alias=True, mode="json")
            await log_tool_invocation(
                tool_name="create_inventory_item", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return d
        except Exception as exc:
            await log_tool_invocation(
                tool_name="create_inventory_item", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Failed to create inventory item: {str(exc)[:200]}"}

    @mcp.tool()
    async def update_inventory_item(
        item_id: str,
        name: str | None = None,
        vendor_slug: str | None = None,
        product_slug: str | None = None,
        vendor_name: str | None = None,
        product_name: str | None = None,
        version: str | None = None,
        deployment: str | None = None,
        environment: str | None = None,
        instance_count: int | None = None,
        owner: str | None = None,
        notes: str | None = None,
        eol_product: str | None = None,
    ) -> dict[str, Any]:
        """Update an inventory item (partial). Requires write scope.

        Only the fields you pass are changed. `eol_product`: omit to keep the
        current link (auto re-matches only if the product changed), set a value
        to override, or "" to unlink.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"item_id": item_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="update_inventory_item", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="update_inventory_item", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            from app.schemas.inventory import InventoryItemUpdateRequest
            from app.services.inventory_service import get_inventory_service

            payload: dict[str, Any] = {}
            for key, value in (
                ("name", name),
                ("vendorSlug", vendor_slug),
                ("productSlug", product_slug),
                ("vendorName", vendor_name),
                ("productName", product_name),
                ("version", version),
                ("deployment", deployment),
                ("environment", environment),
                ("instanceCount", instance_count),
                ("owner", owner),
                ("notes", notes),
                ("eolProduct", eol_product),
            ):
                if value is not None:
                    payload[key] = value

            if not payload:
                return {"error": "No fields to update."}

            service = await get_inventory_service()
            updated = await service.update_item(
                item_id, InventoryItemUpdateRequest.model_validate(payload)
            )
            if updated is None:
                await log_tool_invocation(
                    tool_name="update_inventory_item", inputs=tool_inputs,
                    result_count=0, started_at=started_at,
                )
                return {"error": "Inventory item not found."}
            d = updated.model_dump(by_alias=True, mode="json")
            await log_tool_invocation(
                tool_name="update_inventory_item", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return d
        except Exception as exc:
            await log_tool_invocation(
                tool_name="update_inventory_item", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Failed to update inventory item: {str(exc)[:200]}"}

    @mcp.tool()
    async def delete_inventory_item(item_id: str) -> dict[str, Any]:
        """Delete an inventory item by id. Requires write scope."""
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"item_id": item_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="delete_inventory_item", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="delete_inventory_item", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            from app.services.inventory_service import get_inventory_service

            service = await get_inventory_service()
            deleted = await service.delete_item(item_id)
            await log_tool_invocation(
                tool_name="delete_inventory_item", inputs=tool_inputs,
                result_count=1 if deleted else 0, started_at=started_at,
            )
            if not deleted:
                return {"error": "Inventory item not found.", "itemId": item_id}
            return {"deleted": True, "itemId": item_id}
        except Exception as exc:
            await log_tool_invocation(
                tool_name="delete_inventory_item", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Failed to delete inventory item: {str(exc)[:200]}"}
