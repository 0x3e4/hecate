"""MCP tools for VEX: set statuses on findings, import documents, manage VEX sources.

The write tools mirror the REST routes under ``/scans/vex/*`` and
``/scans/targets/{id}/vex-sources``. Like ``trigger_scan``, they need the
``mcp:write`` scope and nothing else: the scope is granted to safelisted IPs
only, so it stands where the REST routes ask for the admin or target password.
A status set through MCP counts as set by hand (``vex_updated_by`` is
``"<client> - MCP"``), so a VEX source never overwrites it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, mcp_dcr_client_id, require_write_scope
from app.mcp.oauth import get_dcr_client_name
from app.mcp.server import get_rate_limiter

VEX_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
MAX_FINDING_IDS = 500
_TEXT_LIMIT = 2000


def _actor(client_name: str | None) -> str:
    name = (client_name or "").strip()[:100] or get_dcr_client_name(mcp_dcr_client_id.get()) or "MCP Client"
    return f"{name} - MCP"


def _text(value: str | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:_TEXT_LIMIT]


async def _gate(tool_name: str, inputs: dict[str, Any], started_at: datetime, *, write: bool) -> dict[str, Any] | None:
    """Rate limit and (for writes) the write scope. Returns the error to send, or None."""
    if not get_rate_limiter().check(mcp_client_id.get()):
        await log_tool_invocation(
            tool_name=tool_name, inputs=inputs,
            success=False, error="Rate limit exceeded", started_at=started_at,
        )
        return {"error": "Rate limit exceeded."}
    if write:
        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name=tool_name, inputs=inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}
    return None


async def _resolve_target(service: Any, target_id: str) -> str | None:
    raw = (target_id or "").strip()
    if not raw or len(raw) > 2048:
        return None
    return await service.resolve_target_id(raw)


def _source_status(target: dict[str, Any]) -> dict[str, Any] | None:
    status = target.get("vex_source_status")
    if not isinstance(status, dict):
        return None
    checked = status.get("checked_at")
    return {
        "checkedAt": checked.isoformat() if hasattr(checked, "isoformat") else checked,
        "applied": status.get("applied", 0),
        "skipped": status.get("skipped", 0),
        "cleared": status.get("cleared", 0),
        "sources": [
            {
                "url": s.get("url"),
                "ok": s.get("ok"),
                "format": s.get("format"),
                "statements": s.get("statements"),
                "errorKind": s.get("error_kind"),
                "error": s.get("error"),
            }
            for s in status.get("sources") or []
            if isinstance(s, dict)
        ],
    }


def register(mcp: FastMCP) -> None:
    """Register VEX tools on the MCP server."""

    @mcp.tool()
    async def set_finding_vex(
        status: str | None,
        finding_ids: list[str] | None = None,
        target_id: str | None = None,
        vulnerability_id: str | None = None,
        justification: str | None = None,
        detail: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        """Set the VEX status of scan findings. Requires write scope.

        `status`: 'not_affected', 'affected', 'fixed', 'under_investigation', or null to clear
        (clearing needs `finding_ids`).
        Address the findings either by `finding_ids` (the `id` values from
        `get_scan_findings_by_scan`, up to 500) or by `target_id` + `vulnerability_id`, which sets
        every finding of that vulnerability on all scans of the target (and is carried forward to
        later scans). `justification` is the short reason shown in the findings table (for
        not_affected use a CISA justification such as 'vulnerable_code_not_in_execute_path');
        `detail` is the longer explanation. A status set here counts as set by hand: a VEX source
        never overwrites it.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "status": status, "finding_count": len(finding_ids or []), "target_id": target_id,
            "vulnerability_id": vulnerability_id, "client_name": client_name,
        }
        denied = await _gate("set_finding_vex", tool_inputs, started_at, write=True)
        if denied:
            return denied

        try:
            if status is not None and status not in VEX_STATUSES:
                return {"error": f"Invalid status. Allowed: {list(VEX_STATUSES)} or null to clear."}
            if bool(finding_ids) == bool(target_id or vulnerability_id):
                return {"error": "Give either finding_ids, or target_id together with vulnerability_id."}
            actor = _actor(client_name)
            justification_text = _text(justification)
            detail_text = _text(detail)

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            if finding_ids:
                ids = [f.strip() for f in finding_ids if isinstance(f, str) and f.strip()]
                if not ids or len(ids) > MAX_FINDING_IDS or any(len(f) > 100 for f in ids):
                    return {"error": f"finding_ids must hold 1 to {MAX_FINDING_IDS} finding ids."}
                updated = await service.finding_repo.bulk_update_vex_by_ids(
                    finding_ids=ids,
                    vex_status=status,
                    vex_justification=justification_text if status else None,
                    vex_detail=detail_text if status else None,
                    vex_updated_by=actor if status else None,
                )
                output: dict[str, Any] = {"updated": updated, "requested": len(ids)}
            else:
                if status is None:
                    return {"error": "Clearing a status needs finding_ids."}
                if not target_id or not vulnerability_id:
                    return {"error": "target_id and vulnerability_id are both required."}
                vid = vulnerability_id.strip()
                if not vid or len(vid) > 128:
                    return {"error": "Invalid vulnerability_id."}
                tid = await _resolve_target(service, target_id)
                if not tid:
                    return {"error": f"Scan target '{target_id[:200]}' not found."}
                updated = await service.finding_repo.bulk_update_vex_by_vulnerability(
                    target_id=tid,
                    vulnerability_id=vid,
                    vex_status=status,
                    vex_justification=justification_text or detail_text,
                    vex_updated_by=actor,
                    vex_detail=detail_text,
                )
                output = {"updated": updated, "targetId": tid, "vulnerabilityId": vid}

            output.update({"status": status, "updatedBy": actor if status else None})
            await log_tool_invocation(
                tool_name="set_finding_vex", inputs=tool_inputs,
                result_count=output["updated"], started_at=started_at,
            )
            return output
        except Exception as exc:
            await log_tool_invocation(
                tool_name="set_finding_vex", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Update failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def import_vex(
        target_id: str,
        document: dict[str, Any] | str,
    ) -> dict[str, Any]:
        """Import a CycloneDX VEX or OpenVEX document into a scan target. Requires write scope.

        `document` is the VEX document as a JSON object or JSON string; the format is detected.
        Its statements are applied to the matching findings on all scans of the target, matched
        by vulnerability id (and aliases) and, where one vulnerability has different statuses
        per package, by package. An import overwrites the status a finding has. For a document
        the vendor keeps up to date, prefer `set_target_vex_sources`, which re-reads it after
        every scan.
        """
        started_at = datetime.now(tz=UTC)
        raw_size = len(document) if isinstance(document, str) else len(json.dumps(document, default=str))
        tool_inputs = {"target_id": target_id, "document_bytes": raw_size}
        denied = await _gate("import_vex", tool_inputs, started_at, write=True)
        if denied:
            return denied

        try:
            if raw_size > settings.sca_vex_source_max_bytes:
                return {"error": f"The document is larger than {settings.sca_vex_source_max_bytes} bytes."}
            if isinstance(document, str):
                try:
                    document = json.loads(document)
                except ValueError:
                    return {"error": "document is not valid JSON."}
            if not isinstance(document, dict):
                return {"error": "document must be a JSON object."}

            from app.services.scan_service import get_scan_service
            from app.services.vex_service import VexService

            service = await get_scan_service()
            tid = await _resolve_target(service, target_id)
            if not tid:
                return {"error": f"Scan target '{target_id[:200]}' not found."}
            try:
                result = await VexService(service.finding_repo, service.scan_repo).import_vex_document(document, tid)
            except ValueError as exc:
                return {"error": str(exc)}

            output = {
                "targetId": tid,
                "format": result.get("format"),
                "applied": result["applied"],
                "skipped": result["skipped"],
                "notFound": result["not_found"],
            }
            await log_tool_invocation(
                tool_name="import_vex", inputs=tool_inputs,
                result_count=result["applied"], started_at=started_at,
            )
            return output
        except Exception as exc:
            await log_tool_invocation(
                tool_name="import_vex", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Import failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_target_vex_sources(target_id: str) -> dict[str, Any]:
        """Return a scan target's VEX source URLs and what their last fetch found.

        Per source: format and number of statements, or why it could not be used; overall the
        number of findings set, statements skipped and statuses removed.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id}
        denied = await _gate("get_target_vex_sources", tool_inputs, started_at, write=False)
        if denied:
            return denied

        try:
            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            tid = await _resolve_target(service, target_id)
            target = await service.get_target(tid) if tid else None
            if not target:
                return {"error": f"Scan target '{target_id[:200]}' not found."}
            output = {
                "targetId": tid,
                "urls": target.get("vex_sources") or [],
                "lastResult": _source_status(target),
            }
            await log_tool_invocation(
                tool_name="get_target_vex_sources", inputs=tool_inputs,
                result_count=len(output["urls"]), started_at=started_at,
            )
            return output
        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_target_vex_sources", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def set_target_vex_sources(target_id: str, urls: list[str]) -> dict[str, Any]:
        """Set the VEX source URLs of a scan target (replaces the list). Requires write scope.

        Up to 5 https URLs of CycloneDX VEX or OpenVEX documents, e.g. the raw URL of a file in
        the scanned repository (`https://raw.githubusercontent.com/<owner>/<repo>/main/vex/app.openvex.json`;
        a github.com/.../blob/... link is turned into its raw file). Hecate fetches them right
        away and again after every scan and SBOM import, and sets the matching findings unless a
        status was set by hand or imported. An empty list removes the sources and the statuses
        they set. URLs with credentials, plain http and private hosts are refused.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id, "urls": urls}
        denied = await _gate("set_target_vex_sources", tool_inputs, started_at, write=True)
        if denied:
            return denied

        try:
            from app.services.scan_service import get_scan_service
            from app.services.vex_source_service import normalize_vex_source_urls

            try:
                normalized = normalize_vex_source_urls(urls)
            except ValueError as exc:
                return {"error": str(exc)}

            service = await get_scan_service()
            tid = await _resolve_target(service, target_id)
            if not tid or not await service.target_repo.set_vex_sources(tid, normalized):
                return {"error": f"Scan target '{target_id[:200]}' not found."}
            cleared = 0
            if normalized:
                await service.apply_vex_sources(tid)
            else:
                cleared = await service.finding_repo.clear_vex_source_statuses(tid, [])
            target = await service.get_target(tid) or {}
            output: dict[str, Any] = {
                "targetId": tid,
                "urls": normalized,
                "lastResult": _source_status(target) if normalized else None,
            }
            if not normalized:
                output["cleared"] = cleared
            await log_tool_invocation(
                tool_name="set_target_vex_sources", inputs=tool_inputs,
                result_count=len(normalized), started_at=started_at,
            )
            return output
        except Exception as exc:
            await log_tool_invocation(
                tool_name="set_target_vex_sources", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Update failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def apply_target_vex_sources(target_id: str) -> dict[str, Any]:
        """Fetch a scan target's VEX sources again and apply them now. Requires write scope."""
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id}
        denied = await _gate("apply_target_vex_sources", tool_inputs, started_at, write=True)
        if denied:
            return denied

        try:
            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            tid = await _resolve_target(service, target_id)
            target = await service.get_target(tid) if tid else None
            if not target:
                return {"error": f"Scan target '{target_id[:200]}' not found."}
            if not target.get("vex_sources"):
                return {"error": "This target has no VEX sources. Add them with set_target_vex_sources."}
            await service.apply_vex_sources(tid)
            target = await service.get_target(tid) or {}
            output = {"targetId": tid, "urls": target.get("vex_sources") or [], "lastResult": _source_status(target)}
            await log_tool_invocation(
                tool_name="apply_target_vex_sources", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output
        except Exception as exc:
            await log_tool_invocation(
                tool_name="apply_target_vex_sources", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Apply failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def export_scan_vex(scan_id: str) -> dict[str, Any]:
        """Export the VEX statuses of a scan's findings as a CycloneDX 1.5 VEX document.

        Returns an empty `document` when no finding of the scan has a VEX status.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id}
        denied = await _gate("export_scan_vex", tool_inputs, started_at, write=False)
        if denied:
            return denied

        try:
            sid = (scan_id or "").strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            from app.services.scan_service import get_scan_service
            from app.services.vex_service import VexService

            service = await get_scan_service()
            if await service.get_scan(sid) is None:
                return {"error": f"Scan '{sid}' not found."}
            document = await VexService(service.finding_repo, service.scan_repo).export_cyclonedx_vex(sid)
            count = len(document.get("vulnerabilities") or [])
            await log_tool_invocation(
                tool_name="export_scan_vex", inputs=tool_inputs,
                result_count=count, started_at=started_at,
            )
            return {"scanId": sid, "statements": count, "document": document}
        except Exception as exc:
            await log_tool_invocation(
                tool_name="export_scan_vex", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Export failed: {str(exc)[:200]}"}
