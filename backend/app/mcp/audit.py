"""Dual audit logging for MCP tool invocations: structlog + web audit log."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.mcp.auth import mcp_client_id, mcp_client_ip

log = structlog.get_logger()


async def log_tool_invocation(
    *,
    tool_name: str,
    inputs: dict[str, Any],
    result_count: int | None = None,
    success: bool = True,
    error: str | None = None,
    started_at: datetime,
) -> None:
    """Log an MCP tool invocation to structlog and the web audit log."""
    finished_at = datetime.now(tz=UTC)
    duration_ms = (finished_at - started_at).total_seconds() * 1000
    client = mcp_client_id.get()
    client_ip = mcp_client_ip.get()

    # 1. Structured log (always)
    log.info(
        "mcp.tool_invocation",
        tool=tool_name,
        client=client,
        client_ip=client_ip or None,
        duration_ms=round(duration_ms, 1),
        success=success,
        results=result_count,
        error=error,
    )

    # 2. Web audit log (MongoDB ingestion_logs collection, visible on /audit page)
    try:
        from app.services.audit_service import get_audit_service

        audit_service = await get_audit_service()
        metadata: dict[str, Any] = {
            "tool": tool_name,
            "client": client,
            "inputs": _redact_sensitive(inputs),
        }
        if client_ip:
            metadata["clientIp"] = client_ip
        await audit_service.record_event(
            "mcp",
            status="completed" if success else "failed",
            started_at=started_at,
            finished_at=finished_at,
            metadata=metadata,
            result={"items_returned": result_count} if result_count is not None else None,
            error=error,
        )
    except Exception as exc:
        # Audit logging must never break tool execution
        log.warning("mcp.audit_log_failed", error=str(exc))


def _redact_sensitive(inputs: dict[str, Any]) -> dict[str, Any]:
    """Redact potentially sensitive values from audit log metadata."""
    sensitive_keys = {"password", "api_key", "token", "secret"}
    redacted: dict[str, Any] = {}
    for key, value in inputs.items():
        if any(s in key.lower() for s in sensitive_keys):
            redacted[key] = "***"
        elif isinstance(value, str) and len(value) > 500:
            redacted[key] = value[:500] + "..."
        else:
            redacted[key] = value
    return redacted
