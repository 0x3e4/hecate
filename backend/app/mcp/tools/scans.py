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


    @mcp.tool()
    async def get_scan_findings_by_scan(
        scan_id: str,
        severity: str | None = None,
        package_type: str | None = None,
        limit: int = 50,
        include_dismissed: bool = False,
    ) -> dict[str, Any]:
        """Return findings tied to a single scan, optionally filtered by severity or package_type.

        `package_type` allow-list: 'library' (regular SCA vulns), 'sast-finding' (Semgrep),
        'secret-finding' (TruffleHog), 'malicious-indicator' (Hecate malware rules / MAL-* hits),
        'compliance-check' (Dockle).
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "scan_id": scan_id, "severity": severity, "package_type": package_type,
            "limit": limit, "include_dismissed": include_dismissed,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_scan_findings_by_scan", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            sid = scan_id.strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            valid_pkg_types = {"library", "sast-finding", "secret-finding", "malicious-indicator", "compliance-check"}
            if package_type is not None and package_type not in valid_pkg_types:
                return {"error": f"Invalid package_type. Allowed: {sorted(valid_pkg_types)}"}

            capped_limit = max(1, min(limit, settings.mcp_max_results))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            # Over-fetch when package_type filter is set so we still return ~capped_limit hits
            # after the in-memory filter — the repo only supports severity+dismissed filters.
            fetch_limit = capped_limit * 4 if package_type else capped_limit
            total, findings = await service.get_scan_findings(
                sid, severity=severity, limit=fetch_limit, offset=0,
                include_dismissed=include_dismissed,
            )
            if package_type:
                findings = [f for f in findings if f.get("package_type") == package_type][:capped_limit]

            output = {
                "scanId": sid,
                "total": total,
                "returned": len(findings),
                "findings": [_serialize_finding(f) for f in findings],
            }
            await log_tool_invocation(
                tool_name="get_scan_findings_by_scan", inputs=tool_inputs,
                result_count=len(findings), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_scan_findings_by_scan", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_security_alerts(
        search: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        target_id: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        """Consolidated malicious-indicator findings (the 'Security Alerts' tab data).

        Includes Hecate malware-detector hits (HEC-* rules) and MAL-* OSV alerts. Each item is
        grouped by (title, package_name, package_version) and lists every target/scan it appeared in.
        Examples:
        - get_security_alerts(severity="critical") — critical alerts across all targets
        - get_security_alerts(category="install_hook") — npm install-hook detections
        - get_security_alerts(target_id="my-repo:main") — alerts for one target
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "search": search, "severity": severity, "category": category,
            "target_id": target_id, "limit": limit,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_security_alerts", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_search = sanitize_search_input(search) if search else None

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, alerts = await service.get_global_alerts(
                search=safe_search, severity=severity, category=category,
                target_id=target_id, limit=capped_limit, offset=0,
            )

            output = {
                "total": total,
                "returned": len(alerts),
                "alerts": [_serialize_alert(a) for a in alerts],
            }
            await log_tool_invocation(
                tool_name="get_security_alerts", inputs=tool_inputs,
                result_count=len(alerts), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_security_alerts", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Alert lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_scan_sbom(
        scan_id: str,
        search: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Return SBOM components for a single scan (deduplicated by name+version)."""
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "search": search, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_scan_sbom", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            sid = scan_id.strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_search = sanitize_search_input(search) if search else None

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, components = await service.get_scan_sbom(
                sid, search=safe_search, limit=capped_limit, offset=0,
            )

            output = {
                "scanId": sid,
                "total": total,
                "returned": len(components),
                "components": [_serialize_sbom_component(c) for c in components],
            }
            await log_tool_invocation(
                tool_name="get_scan_sbom", inputs=tool_inputs,
                result_count=len(components), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_scan_sbom", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"SBOM lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_sbom_components(
        search: str | None = None,
        type_filter: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Consolidated SBOM components from the latest completed scan of each target.

        `type_filter` matches a CycloneDX component type (e.g. 'library', 'application',
        'container', 'os-package').
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {
            "search": search, "type_filter": type_filter,
            "target_id": target_id, "limit": limit,
        }

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_sbom_components", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_search = sanitize_search_input(search) if search else None

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, components = await service.get_global_sbom(
                search=safe_search, type_filter=type_filter,
                target_id=target_id, limit=capped_limit, offset=0,
            )

            output = {
                "total": total,
                "returned": len(components),
                "components": [_serialize_sbom_component(c) for c in components],
            }
            await log_tool_invocation(
                tool_name="get_sbom_components", inputs=tool_inputs,
                result_count=len(components), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_sbom_components", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"SBOM lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_sbom_facets(
        target_id: str | None = None,
    ) -> dict[str, Any]:
        """Return ecosystem / license / type facet counts across the latest scan of each target.

        Useful for getting a high-level breakdown ("how many components in npm vs PyPI", "license
        distribution"). When `target_id` is provided, scopes to that target's latest scan only.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_sbom_facets", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            facets = await service.get_sbom_facets(target_id=target_id)

            # Service returns {"ecosystems": [(value, count), ...], "licenses": [...], "types": [...]}
            def _pairs(items: list[Any]) -> list[dict[str, Any]]:
                out: list[dict[str, Any]] = []
                for entry in items or []:
                    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                        out.append({"value": entry[0], "count": entry[1]})
                    elif isinstance(entry, dict):
                        out.append({"value": entry.get("value"), "count": entry.get("count", 0)})
                return out

            output = {
                "ecosystems": _pairs(facets.get("ecosystems", [])),
                "licenses": _pairs(facets.get("licenses", [])),
                "types": _pairs(facets.get("types", [])),
            }
            await log_tool_invocation(
                tool_name="get_sbom_facets", inputs=tool_inputs,
                result_count=len(output["ecosystems"]) + len(output["licenses"]) + len(output["types"]),
                started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_sbom_facets", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Facet lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_target_scan_history(
        target_id: str,
        limit: int = 30,
        since_iso: str | None = None,
    ) -> dict[str, Any]:
        """Return historical completed scans for a target (newest first), with severity summaries.

        `since_iso` is an ISO-8601 date/datetime — only scans started at or after this point are
        returned. Useful for chart-style timelines and severity-delta analysis.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id, "limit": limit, "since_iso": since_iso}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_target_scan_history", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            tid = target_id.strip()
            if not tid or len(tid) > 500:
                return {"error": "Invalid target_id."}

            since_dt: datetime | None = None
            if since_iso:
                try:
                    since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
                except ValueError:
                    return {"error": "since_iso must be ISO-8601 (e.g. '2026-01-15' or '2026-01-15T12:00:00Z')."}

            capped_limit = max(1, min(limit, 200))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            entries = await service.get_target_history(tid, limit=capped_limit, since=since_dt)

            output = {
                "targetId": tid,
                "count": len(entries),
                "history": [_serialize_history_entry(e) for e in entries],
            }
            await log_tool_invocation(
                tool_name="get_target_scan_history", inputs=tool_inputs,
                result_count=len(entries), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_target_scan_history", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"History lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def compare_scans(
        scan_id_a: str,
        scan_id_b: str,
    ) -> dict[str, Any]:
        """Diff two scans (typically of the same target): added / removed / changed / unchanged.

        `changed` covers same-package findings whose vulnerability_id was reassigned (e.g. a CVE
        was assigned after the previous scan). Both summaries are included for context.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id_a": scan_id_a, "scan_id_b": scan_id_b}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="compare_scans", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            a = scan_id_a.strip()
            b = scan_id_b.strip()
            if not a or not b or len(a) > 100 or len(b) > 100:
                return {"error": "Both scan_id_a and scan_id_b must be valid scan IDs."}
            if a == b:
                return {"error": "scan_id_a and scan_id_b must differ."}

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            result = await service.compare_scans(a, b)
            if "error" in result:
                return result

            await log_tool_invocation(
                tool_name="compare_scans", inputs=tool_inputs,
                result_count=len(result.get("added", [])) + len(result.get("removed", [])) + len(result.get("changed", [])),
                started_at=started_at,
            )
            return result

        except Exception as exc:
            await log_tool_invocation(
                tool_name="compare_scans", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Compare failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def get_layer_analysis(
        scan_id: str,
    ) -> dict[str, Any]:
        """Return Dive container-image layer analysis for a scan (only for container_image targets).

        Returns the per-layer breakdown — index, command, size, digest. Returns an empty layers
        list if the scan didn't run Dive or wasn't a container image.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="get_layer_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            sid = scan_id.strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            analysis = await service.get_layer_analysis(sid)
            output = _serialize_layer_analysis(sid, analysis)

            await log_tool_invocation(
                tool_name="get_layer_analysis", inputs=tool_inputs,
                result_count=len(output.get("layers", [])), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="get_layer_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Layer lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def list_scan_targets(
        type_filter: str | None = None,
        group: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List registered scan targets (use this to discover target_ids for other tools).

        `type_filter`: 'container_image', 'source_repo', 'sbom-import'.
        `group`: filter by application group; pass empty string to get ungrouped targets only.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"type_filter": type_filter, "group": group, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="list_scan_targets", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, targets = await service.list_targets(
                type_filter=type_filter, group_filter=group,
                limit=capped_limit, offset=0,
            )

            output = {
                "total": total,
                "returned": len(targets),
                "targets": [_serialize_target(t) for t in targets],
            }
            await log_tool_invocation(
                tool_name="list_scan_targets", inputs=tool_inputs,
                result_count=len(targets), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="list_scan_targets", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Target lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def list_target_groups() -> dict[str, Any]:
        """List application groups with rolled-up severity totals across all targets in each group."""
        started_at = datetime.now(tz=UTC)
        tool_inputs: dict[str, Any] = {}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="list_target_groups", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            groups = await service.list_target_groups()

            output = {
                "count": len(groups),
                "groups": [
                    {
                        "group": g.get("group"),
                        "targetCount": g.get("target_count", 0),
                        "latestSummary": g.get("latest_summary") or {},
                    }
                    for g in groups
                ],
            }
            await log_tool_invocation(
                tool_name="list_target_groups", inputs=tool_inputs,
                result_count=len(groups), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="list_target_groups", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Group lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def list_scans(
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List recent scans (newest first), optionally filtered by target_id or status.

        Status values: 'pending', 'running', 'completed', 'failed', 'cancelled'.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"target_id": target_id, "status": status, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="list_scans", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, scans = await service.scan_repo.list_all(
                target_id=target_id, status=status, limit=capped_limit, offset=0,
            )

            output = {
                "total": total,
                "returned": len(scans),
                "scans": [_serialize_scan(s) for s in scans],
            }
            await log_tool_invocation(
                tool_name="list_scans", inputs=tool_inputs,
                result_count=len(scans), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="list_scans", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Scan list failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def find_findings_by_cve(
        cve_id: str,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Find all scan findings tied to a specific CVE/GHSA/OSV ID — across every scan.

        Useful for impact analysis: "which of my scanned targets are affected by CVE-XXXX-YYYY".
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"cve_id": cve_id, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="find_findings_by_cve", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            cve = cve_id.strip().upper()
            if not cve or len(cve) > 100:
                return {"error": "Invalid cve_id."}

            capped_limit = max(1, min(limit, settings.mcp_max_results))

            from app.services.scan_service import get_scan_service

            service = await get_scan_service()
            total, findings = await service.find_by_cve(cve, limit=capped_limit, offset=0)

            output = {
                "cveId": cve,
                "total": total,
                "returned": len(findings),
                "findings": [
                    {
                        **_serialize_finding(f),
                        "scanId": str(f.get("scan_id", "")) or None,
                        "targetId": f.get("target_id"),
                    }
                    for f in findings
                ],
            }
            await log_tool_invocation(
                tool_name="find_findings_by_cve", inputs=tool_inputs,
                result_count=len(findings), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="find_findings_by_cve", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"CVE lookup failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def prepare_scan_attack_chain_analysis(
        scan_id: str,
        language: str | None = None,
        additional_context: str | None = None,
    ) -> dict[str, Any]:
        """Return Hecate's deterministic Cross-CVE Attack Chain graph + prompts for one scan.

        The chain buckets the scan's findings into ATT&CK kill-chain stages
        (foothold → credential access → privilege escalation → lateral movement → impact)
        and is fully deterministic — call this tool, run the prompt locally, then persist
        the resulting prose narrative via `save_scan_attack_chain_analysis`. Read-only.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "language": language}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="prepare_scan_attack_chain_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        try:
            sid = (scan_id or "").strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}

            from app.services.ai_service import build_scan_attack_chain_prompts
            from app.services.scan_attack_chain_service import (
                get_scan_attack_chain_service,
            )
            from app.services.scan_service import get_scan_service

            scan_service = await get_scan_service()
            scan = await scan_service.get_scan(sid)
            if not scan:
                return {"error": f"Scan '{sid}' not found."}

            _, findings = await scan_service.finding_repo.list_by_scan(
                sid, limit=2000, include_dismissed=False
            )
            chain_service = get_scan_attack_chain_service()
            graph, stages = await chain_service.build_chain(
                {**scan, "_id": sid}, findings, language=language or "en"
            )
            graph_payload = graph.model_dump(by_alias=True)
            stages_payload = [s.model_dump(by_alias=True) for s in stages]

            system_prompt, user_prompt = build_scan_attack_chain_prompts(
                {**scan, "_id": sid},
                stages_payload,
                graph_payload,
                language=language,
                additional_context=additional_context,
            )

            output = {
                "scanId": sid,
                "graph": graph_payload,
                "stages": stages_payload,
                "systemPrompt": system_prompt,
                "userPrompt": user_prompt,
                "instructions": (
                    "The chain stages above are deterministic. Read systemPrompt and userPrompt, "
                    "produce a chained attacker narrative locally (≤350 words), then call "
                    "save_scan_attack_chain_analysis(scan_id, summary). Do NOT cite CVE/CAPEC IDs "
                    "absent from `stages` or `graph['nodes']`."
                ),
                "saveTool": "save_scan_attack_chain_analysis",
            }
            await log_tool_invocation(
                tool_name="prepare_scan_attack_chain_analysis", inputs=tool_inputs,
                result_count=len(stages_payload), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="prepare_scan_attack_chain_analysis", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return {"error": f"Prepare failed: {str(exc)[:200]}"}

    @mcp.tool()
    async def save_scan_attack_chain_analysis(
        scan_id: str,
        summary: str,
        language: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist a Cross-CVE Attack Chain narrative produced by the calling assistant.

        Use this after `prepare_scan_attack_chain_analysis`. Appends the narrative to the
        scan's `attack_chains[]` array and mirrors it on `attack_chain` (latest). Stamps a
        triggeredBy attribution like "Claude - MCP". Requires write scope.
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"scan_id": scan_id, "language": language, "client_name": client_name}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="save_scan_attack_chain_analysis", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return {"error": "Rate limit exceeded."}

        allowed, deny_reason = require_write_scope()
        if not allowed:
            await log_tool_invocation(
                tool_name="save_scan_attack_chain_analysis", inputs=tool_inputs,
                success=False, error=f"Write denied: {deny_reason}", started_at=started_at,
            )
            return {"error": f"Write access denied. {deny_reason}"}

        try:
            sid = (scan_id or "").strip()
            if not sid or len(sid) > 100:
                return {"error": "Invalid scan_id."}
            if not summary or not summary.strip():
                return {"error": "summary must not be empty."}
            if len(summary) > 200_000:
                return {"error": "summary too large (200k char limit)."}

            from app.mcp.tools.vulnerabilities import _mcp_triggered_by
            from app.services.ai_service import _append_attribution_footer, _normalize_language
            from app.services.scan_service import get_scan_service

            triggered_by = _mcp_triggered_by(client_name)
            stored_summary = _append_attribution_footer(summary.strip(), triggered_by)

            narrative = {
                "provider": "mcp-client",
                "language": _normalize_language(language),
                "summary": stored_summary,
                "generatedAt": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
                "triggeredBy": triggered_by,
            }
            scan_service = await get_scan_service()
            ok = await scan_service.save_attack_chain(sid, narrative)
            if not ok:
                return {"error": f"Scan '{sid}' not found or save failed."}

            await log_tool_invocation(
                tool_name="save_scan_attack_chain_analysis", inputs=tool_inputs,
                result_count=1, started_at=started_at,
            )
            return {
                "scanId": sid,
                "triggeredBy": triggered_by,
                "generatedAt": narrative["generatedAt"],
                "status": "saved",
            }

        except Exception as exc:
            await log_tool_invocation(
                tool_name="save_scan_attack_chain_analysis", inputs=tool_inputs,
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
        "packageType": finding.get("packageType") or finding.get("package_type"),
    }


def _serialize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Serialize a consolidated security alert (malicious-indicator finding) for MCP output."""
    targets = alert.get("targets") or []
    return {
        "title": alert.get("title"),
        "packageName": alert.get("package_name") or alert.get("packageName"),
        "packageVersion": alert.get("package_version") or alert.get("packageVersion"),
        "severity": alert.get("severity"),
        "category": alert.get("category"),
        "description": (alert.get("description") or "")[:500],
        "packagePath": alert.get("package_path") or alert.get("packagePath"),
        "targetCount": len(targets),
        "targets": [
            {"targetId": t.get("target_id"), "scanId": str(t.get("scan_id", "")) or None}
            for t in targets[:20]
        ],
    }


def _serialize_sbom_component(component: dict[str, Any]) -> dict[str, Any]:
    """Serialize an SBOM component for MCP output."""
    licenses = component.get("licenses") or []
    if not isinstance(licenses, list):
        licenses = [licenses] if licenses else []
    file_paths = component.get("file_paths") or component.get("filePaths") or []
    if not isinstance(file_paths, list):
        file_paths = []
    return {
        "name": component.get("name"),
        "version": component.get("version"),
        "type": component.get("type"),
        "purl": component.get("purl"),
        "cpe": component.get("cpe"),
        "supplier": component.get("supplier"),
        "licenses": licenses,
        "provenanceVerified": component.get("provenance_verified") or component.get("provenanceVerified"),
        "filePaths": file_paths[:5],
        "scanId": str(component.get("scan_id") or component.get("scanId") or "") or None,
        "targetId": component.get("target_id") or component.get("targetId"),
    }


def _serialize_history_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Serialize a scan history entry (from scan_repo.get_history) for MCP output."""
    summary = entry.get("summary") or {}
    if hasattr(summary, "model_dump"):
        summary = summary.model_dump()
    return {
        "scanId": str(entry.get("_id") or entry.get("scan_id") or ""),
        "startedAt": str(entry.get("started_at")) if entry.get("started_at") else None,
        "status": entry.get("status"),
        "summary": summary,
        "durationSeconds": entry.get("duration_seconds"),
        "commitSha": entry.get("commit_sha"),
    }


def _serialize_layer_analysis(scan_id: str, analysis: dict[str, Any] | None) -> dict[str, Any]:
    """Serialize a Dive layer-analysis document for MCP output."""
    if not analysis:
        return {"scanId": scan_id, "totalLayers": 0, "layers": []}
    raw_layers = analysis.get("layers") or []
    capped = raw_layers[:50]
    layers = [
        {
            "index": layer.get("index"),
            "command": (layer.get("command") or "")[:300],
            "size": layer.get("size") or layer.get("size_bytes"),
            "digest": layer.get("digest"),
            "addedFileCount": layer.get("added_file_count") or layer.get("addedFileCount"),
            "wastedSize": layer.get("wasted_size") or layer.get("wastedSize"),
        }
        for layer in capped
    ]
    return {
        "scanId": str(analysis.get("scan_id") or scan_id),
        "totalLayers": len(raw_layers),
        "returnedLayers": len(layers),
        "layers": layers,
    }


def _serialize_target(target: dict[str, Any]) -> dict[str, Any]:
    """Serialize a scan target for MCP output."""
    summary = target.get("latest_summary") or {}
    if hasattr(summary, "model_dump"):
        summary = summary.model_dump()
    return {
        "targetId": target.get("target_id") or target.get("_id"),
        "name": target.get("name"),
        "type": target.get("type"),
        "group": target.get("group"),
        "autoScan": target.get("auto_scan") or target.get("autoScan"),
        "scanners": target.get("scanners"),
        "lastScanAt": str(target.get("last_scan_at")) if target.get("last_scan_at") else None,
        "scanCount": target.get("scan_count") or target.get("scanCount"),
        "latestScanId": target.get("latest_scan_id") or target.get("latestScanId"),
        "latestSummary": summary,
        "hasRunningScan": target.get("has_running_scan") or target.get("hasRunningScan") or False,
    }
