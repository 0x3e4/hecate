"""Dual audit logging for MCP tool invocations and OAuth events.

Both streams land in the web audit log under a single unified job name ("mcp")
with a `kind` metadata field that distinguishes the two. This keeps the /audit
filter simple and shows all MCP activity grouped together in the UI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.mcp.auth import (
    mcp_client_id,
    mcp_client_ip,
    mcp_dcr_client_id,
    mcp_token_email,
    mcp_token_issued_ip,
    mcp_token_scope,
)

log = structlog.get_logger()

MCP_JOB_NAME = "mcp"


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
    duration_ms = round((finished_at - started_at).total_seconds() * 1000, 1)
    identity = mcp_client_id.get()
    request_ip = mcp_client_ip.get()
    email = mcp_token_email.get()
    scope = mcp_token_scope.get()
    authorized_from_ip = mcp_token_issued_ip.get()
    dcr_client = mcp_dcr_client_id.get()

    log.info(
        "mcp.tool_invocation",
        tool=tool_name,
        identity=identity,
        email=email or None,
        request_ip=request_ip or None,
        authorized_from_ip=authorized_from_ip or None,
        dcr_client=dcr_client or None,
        scope=scope or None,
        duration_ms=duration_ms,
        success=success,
        results=result_count,
        error=error,
    )

    try:
        from app.services.audit_service import get_audit_service

        audit_service = await get_audit_service()
        metadata: dict[str, Any] = {
            "kind": "tool_invocation",
            "tool": tool_name,
            "identity": identity,
            "inputs": _redact_sensitive(inputs),
            "durationMs": duration_ms,
        }
        if email:
            metadata["email"] = email
        if request_ip:
            metadata["requestIp"] = request_ip
        if authorized_from_ip:
            metadata["authorizedFromIp"] = authorized_from_ip
        if dcr_client:
            metadata["mcpClient"] = dcr_client
        if scope:
            metadata["scope"] = scope
        result_payload: dict[str, Any] | None = None
        if result_count is not None:
            result_payload = {"itemsReturned": result_count}
        await audit_service.record_event(
            MCP_JOB_NAME,
            status="completed" if success else "failed",
            started_at=started_at,
            finished_at=finished_at,
            metadata=metadata,
            result=result_payload,
            error=error,
        )
    except Exception as exc:
        # Audit logging must never break tool execution
        log.warning("mcp.audit_log_failed", error=str(exc))


async def log_oauth_event(
    *,
    event: str,
    provider: str,
    identity: str | None = None,
    email: str | None = None,
    client_ip: str | None = None,
    granted_scope: str | None = None,
    reason: str | None = None,
    mcp_client_id: str | None = None,
) -> None:
    """Log an MCP OAuth event to structlog and the web audit log.

    `event` values: authorize_initiated, authorize_success, authorize_denied, token_issued.
    """
    now = datetime.now(tz=UTC)
    log.info(
        "mcp.oauth.event",
        oauth_event=event,
        provider=provider,
        identity=identity,
        email=email,
        client_ip=client_ip,
        granted_scope=granted_scope,
        reason=reason,
        mcp_client=mcp_client_id,
    )

    try:
        from app.services.audit_service import get_audit_service

        audit_service = await get_audit_service()
        metadata: dict[str, Any] = {
            "kind": f"oauth_{event}",
            "oauthEvent": event,
            "provider": provider,
        }
        if identity:
            metadata["identity"] = identity
        if email:
            metadata["email"] = email
        if client_ip:
            metadata["requestIp"] = client_ip
            # During OAuth authorize the request IP is the user's browser — also
            # stamp it as authorizedFromIp so all MCP rows share the same schema.
            metadata["authorizedFromIp"] = client_ip
        if granted_scope:
            metadata["scope"] = granted_scope
        if reason:
            metadata["reason"] = reason
        if mcp_client_id:
            metadata["mcpClient"] = mcp_client_id
        status = "completed" if event in ("authorize_success", "authorize_initiated", "token_issued") else "failed"
        await audit_service.record_event(
            MCP_JOB_NAME,
            status=status,
            started_at=now,
            finished_at=now,
            metadata=metadata,
            error=reason if status == "failed" else None,
        )
    except Exception as exc:
        log.warning("mcp.oauth_audit_failed", error=str(exc))


def _redact_sensitive(inputs: dict[str, Any]) -> dict[str, Any]:
    """Redact potentially sensitive values from audit log metadata."""
    sensitive_keys = {"password", "api_key", "token", "secret", "client_secret", "code_verifier"}
    redacted: dict[str, Any] = {}
    for key, value in inputs.items():
        if any(s in key.lower() for s in sensitive_keys):
            redacted[key] = "***"
        elif isinstance(value, str) and len(value) > 500:
            redacted[key] = value[:500] + "..."
        else:
            redacted[key] = value
    return redacted
