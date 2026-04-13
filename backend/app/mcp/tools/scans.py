"""MCP tools for SCA scan findings and scan management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id, mcp_dcr_client_id, require_write_scope
from app.mcp.oauth import get_dcr_client_name
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

    @mcp.tool()
    async def get_sca_scan(
        scan_id: str | None = None,
        target: str | None = None,
        group: str | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Look up SCA scans by scan_id, target name/id, or group.

        - `scan_id`: returns a single scan with severity summary, target, scanners, status.
        - `target`: case-insensitive match against target_id or target.name; returns the latest `limit`
          scans for the matched target.
        - `group`: returns the latest scan per target in the group (one scan per target).
        Exactly one of the three should be provided.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "target": target, "group": group, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_sca_scan", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            provided = sum(1 for v in (scan_id, target, group) if v)
            if provided != 1:
                return {"error": "Provide exactly one of: scan_id, target, group."}

            capped = max(1, min(limit, 50))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()

            if scan_id:
                scan = await service.get_scan(scan_id.strip())
                if scan is None:
                    return {"error": f"Scan '{scan_id}' not found."}
                return {"scans": [_serialize_scan(scan)]}

            if target:
                target_query = target.strip()
                matched_target = await service.target_repo.get(target_query)
                if matched_target is None:
                    # fall back to case-insensitive name search via list_targets (small page)
                    _, all_targets = await service.target_repo.list_targets(limit=500, offset=0)
                    needle = target_query.lower()
                    matched_target = next(
                        (
                            t for t in all_targets
                            if (t.get("name") or "").lower() == needle
                            or (t.get("target_id") or "").lower() == needle
                        ),
                        None,
                    )
                if matched_target is None:
                    return {"error": f"No target matching '{target_query}'."}

                tid = matched_target.get("target_id")
                _, scans = await service.scan_repo.list_by_target(tid, limit=capped, offset=0)
                # Enrich each scan with deduped summary
                enriched = []
                for s in scans:
                    s["summary"] = await service._get_deduped_summary(s)  # noqa: SLF001
                    enriched.append(_serialize_scan(s))
                output = {
                    "target": {
                        "targetId": tid,
                        "name": matched_target.get("name"),
                        "type": matched_target.get("type"),
                        "group": matched_target.get("group"),
                    },
                    "scans": enriched,
                }
                await log_tool_invocation(
                    tool_name="get_sca_scan", inputs=tool_inputs,
                    result_count=len(enriched), started_at=started_at,
                )
                return output

            # group lookup
            group_query = (group or "").strip()
            _, group_targets = await service.target_repo.list_targets(
                group_filter=group_query, limit=200, offset=0
            )
            if not group_targets:
                return {"error": f"No targets in group '{group_query}'."}

            group_scans: list[dict[str, Any]] = []
            for t in group_targets:
                _, scans = await service.scan_repo.list_by_target(t["target_id"], limit=1, offset=0)
                if scans:
                    s = scans[0]
                    s["summary"] = await service._get_deduped_summary(s)  # noqa: SLF001
                    serialized = _serialize_scan(s)
                    serialized["targetName"] = t.get("name")
                    serialized["group"] = t.get("group")
                    group_scans.append(serialized)

            await log_tool_invocation(
                tool_name="get_sca_scan", inputs=tool_inputs,
                result_count=len(group_scans), started_at=started_at,
            )
            return {"group": group_query, "scans": group_scans}

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_sca_scan", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Scan lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def prepare_scan_ai_analysis(
        scan_id: str,
        language: str | None = None,
        additional_context: str | None = None,
    ) -> dict[str, Any]:
        """Return the Hecate scan-triage system prompt + scan context for a given scan_id.

        The calling AI assistant reads `systemPrompt` and `userPrompt`, produces the analysis using
        its own model (no server-side API call), then calls `save_scan_ai_analysis(scan_id, summary)`.
        Read-only — does not require write scope.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "language": language}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="prepare_scan_ai_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            sid = scan_id.strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            from app.services.ai_service import build_scan_prompts
            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            scan = await service.get_scan(sid)
            if scan is None:
                return {"error": f"Scan '{sid}' not found."}

            _, findings = await service.finding_repo.list_by_scan(
                sid, limit=500, include_dismissed=False
            )

            system_prompt, user_prompt = build_scan_prompts(
                {**scan, "_id": sid},
                findings,
                language=language,
                additional_context=additional_context,
            )

            output = {
                "scanId": sid,
                "findingCount": len(findings),
                "systemPrompt": system_prompt,
                "userPrompt": user_prompt,
                "instructions": (
                    "Read the systemPrompt and userPrompt, generate the scan triage analysis using "
                    "your own model, then call save_scan_ai_analysis(scan_id, summary) to persist it."
                ),
                "saveTool": "save_scan_ai_analysis",
            }
            await log_tool_invocation(
                tool_name="prepare_scan_ai_analysis", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="prepare_scan_ai_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Prepare failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def save_scan_ai_analysis(
        scan_id: str,
        summary: str,
        language: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist an AI scan triage produced by the calling assistant onto the scan document.

        Use this after `prepare_scan_ai_analysis`. Requires write scope. The server attaches a
        triggeredBy attribution like "Claude Code - MCP" and appends it as a footer in the summary.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "language": language, "client_name": client_name}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="save_scan_ai_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="save_scan_ai_analysis", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            sid = scan_id.strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}
            if not summary or not summary.strip():
                return {"error": "summary must not be empty."}
            if len(summary) > 200_000:
                return {"error": "summary too large (200k char limit)."}

            from app.services.ai_service import _append_attribution_footer, _normalize_language
            from app.services.scan_service import get_scan_service

            name = (client_name or "").strip() or get_dcr_client_name(mcp_dcr_client_id.get()) or "MCP Client"
            triggered_by = f"{name} - MCP"
            stored_summary = _append_attribution_footer(summary.strip(), triggered_by)

            assessment = {
                "scanId": sid,
                "provider": "mcp-client",
                "language": _normalize_language(language),
                "summary": stored_summary,
                "generatedAt": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
                "triggeredBy": triggered_by,
            }

            service = await get_scan_service()
            scan = await service.get_scan(sid)
            if scan is None:
                return {"error": f"Scan '{sid}' not found."}

            ok = await service.save_scan_ai_analysis(sid, assessment)
            if not ok:
                return {"error": f"Failed to save analysis for scan '{sid}'."}

            await log_tool_invocation(
                tool_name="save_scan_ai_analysis", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return {
                "scanId": sid,
                "triggeredBy": triggered_by,
                "generatedAt": assessment["generatedAt"],
                "status": "saved",
            }

        except Exception as exc:
            await log_tool_invocation(
                tool_name="save_scan_ai_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Save failed: {str(exc)[:200]}"}


def _serialize_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """Compact representation of a scan document for MCP output."""
    summary = scan.get("summary") or {}
    if hasattr(summary, "model_dump"):
        summary = summary.model_dump()
    return {
        "scanId": str(scan.get("_id") or scan.get("scan_id") or ""),
        "targetId": scan.get("target_id"),
        "targetName": scan.get("target_name"),
        "status": scan.get("status"),
        "scanners": scan.get("scanners"),
        "source": scan.get("source"),
        "startedAt": str(scan.get("started_at")) if scan.get("started_at") else None,
        "finishedAt": str(scan.get("finished_at")) if scan.get("finished_at") else None,
        "durationSeconds": scan.get("duration_seconds"),
        "commitSha": scan.get("commit_sha"),
        "branch": scan.get("branch"),
        "imageRef": scan.get("image_ref"),
        "summary": summary,
        "sbomComponentCount": scan.get("sbom_component_count"),
        "error": scan.get("error"),
        "hasAiAnalysis": bool(scan.get("ai_analysis") or scan.get("ai_analyses")),
    }


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
