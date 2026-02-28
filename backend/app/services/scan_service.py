from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from app.core.config import settings
from app.models.scan import (
    ScanDocument,
    ScanFindingDocument,
    ScanSbomComponentDocument,
    ScanSummary,
    ScanTargetDocument,
)
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.scan_sbom_repository import ScanSbomRepository
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services.audit_service import AuditService
from app.services.scan_parser import (
    parse_cyclonedx_sbom,
    parse_grype_json,
    parse_osv_json,
    parse_trivy_json,
)

log = structlog.get_logger()


class ScanService:
    def __init__(
        self,
        target_repo: ScanTargetRepository,
        scan_repo: ScanRepository,
        finding_repo: ScanFindingRepository,
        sbom_repo: ScanSbomRepository,
        audit_service: AuditService,
    ) -> None:
        self.target_repo = target_repo
        self.scan_repo = scan_repo
        self.finding_repo = finding_repo
        self.sbom_repo = sbom_repo
        self.audit_service = audit_service

    async def submit_scan(
        self,
        target: str,
        target_type: str,
        scanners: list[str] | None = None,
        source: str = "manual",
        commit_sha: str | None = None,
        branch: str | None = None,
        pipeline_url: str | None = None,
    ) -> dict[str, Any]:
        """Submit a scan request. Creates scan record and kicks off background processing.

        Returns immediately with scan_id + status=running so the caller doesn't block.
        """

        if scanners is None:
            scanners = [s.strip() for s in settings.sca_default_scanners.split(",") if s.strip()]

        # 1. Upsert scan target
        target_id = self._derive_target_id(target, target_type)
        target_name = self._derive_target_name(target)
        registry = self._extract_registry(target) if target_type == "container_image" else None
        repo_url = target if target_type == "source_repo" else None

        target_doc = ScanTargetDocument(
            target_id=target_id,
            type=target_type,
            name=target_name,
            registry=registry,
            repository_url=repo_url,
        )
        await self.target_repo.upsert(target_doc)

        # 2. Create scan record (status=running)
        started_at = datetime.now(tz=UTC)
        scan_doc = ScanDocument(
            target_id=target_id,
            scanners=scanners,
            status="running",
            source=source,
            image_ref=target if target_type == "container_image" else None,
            commit_sha=commit_sha,
            branch=branch,
            pipeline_url=pipeline_url,
            started_at=started_at,
        )
        scan_id = await self.scan_repo.insert(scan_doc)

        # 3. Fire off background task and return immediately
        asyncio.create_task(
            self._run_scan_background(
                scan_id=scan_id,
                target=target,
                target_id=target_id,
                target_type=target_type,
                scanners=scanners,
                source=source,
                started_at=started_at,
            )
        )

        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "status": "running",
            "findings_count": 0,
            "sbom_component_count": 0,
            "summary": ScanSummary().model_dump(),
            "error": None,
        }

    async def _run_scan_background(
        self,
        scan_id: str,
        target: str,
        target_id: str,
        target_type: str,
        scanners: list[str],
        source: str,
        started_at: datetime,
    ) -> None:
        """Execute scan in background. Each scanner runs independently and results are
        stored incrementally so the frontend can display partial results while other
        scanners are still running."""
        from app.services.scan_parser import _filter_and_merge_sbom

        all_findings: list[ScanFindingDocument] = []
        all_components: list[ScanSbomComponentDocument] = []
        errors: list[str] = []

        async def _run_single_scanner(scanner_name: str) -> None:
            """Run one scanner via the sidecar, parse & store results immediately."""
            try:
                results = await self._call_scanner_sidecar(target, target_type, [scanner_name])
            except Exception as exc:
                errors.append(f"{scanner_name}: {exc}")
                log.warning("scan_service.scanner_call_failed", scanner=scanner_name, error=str(exc))
                return

            for result in results:
                report = result.get("report", {})
                scanner_error = result.get("error")

                if scanner_error:
                    errors.append(f"{scanner_name}: {scanner_error}")
                    continue
                if not report:
                    continue

                fmt = result.get("format", "")
                findings: list[ScanFindingDocument] = []
                components: list[ScanSbomComponentDocument] = []

                try:
                    if fmt == "trivy-json":
                        findings, components, _ = parse_trivy_json(report, scan_id, target_id)
                    elif fmt == "grype-json":
                        findings, _ = parse_grype_json(report, scan_id, target_id)
                    elif fmt == "cyclonedx-json":
                        components, _ = parse_cyclonedx_sbom(report, scan_id, target_id)
                    elif fmt == "osv-json":
                        findings, _ = parse_osv_json(report, scan_id, target_id)
                    else:
                        log.warning("scan_service.unknown_format", scanner=scanner_name, format=fmt)
                        continue
                except Exception as exc:
                    log.warning("scan_service.parse_failed", scanner=scanner_name, error=str(exc))
                    errors.append(f"{scanner_name} parse error: {exc}")
                    continue

                # Store this scanner's results immediately so the frontend can see them
                if findings:
                    await self.finding_repo.bulk_insert(findings)
                    all_findings.extend(findings)
                if components:
                    await self.sbom_repo.bulk_insert(components)
                    all_components.extend(components)

                # Update running summary so polling sees incremental progress
                current_summary = self._compute_summary(all_findings)
                await self.scan_repo.update_status(
                    scan_id, "running",
                    summary=current_summary,
                    sbom_component_count=len(all_components),
                )

        # Run all scanners concurrently — each stores results as it finishes
        await asyncio.gather(*[_run_single_scanner(s) for s in scanners], return_exceptions=True)

        # CVE fallback: try to match findings without CVE against local vulnerability DB
        await self._match_cve_for_unmatched_findings(scan_id, all_findings)

        # Fix version correction: replace scanner-reported downgrade fixes with correct versions from vuln DB
        await self._fix_downgrade_fix_versions(scan_id, all_findings)

        # Final dedup pass: remove cross-scanner duplicates from DB
        # (findings dedup happens at display time via frontend merge; SBOM needs cleanup)
        # Recompute final summary after all scanners
        final_summary = self._compute_summary(all_findings)
        finished_at = datetime.now(tz=UTC)
        duration = (finished_at - started_at).total_seconds()
        error_text = "; ".join(errors) if errors else None
        status = "completed" if not errors or all_findings or all_components else "failed"

        await self.scan_repo.update_status(
            scan_id, status,
            finished_at=finished_at,
            duration_seconds=duration,
            summary=final_summary,
            sbom_component_count=len(all_components),
            error=error_text,
        )
        await self.target_repo.update_last_scan(target_id, finished_at)

        log.info(
            "scan_service.scan_completed",
            scan_id=scan_id,
            target=target,
            findings=len(all_findings),
            sbom_components=len(all_components),
            duration_seconds=round(duration, 2),
        )

        await self.audit_service.record_event(
            "sca-scan",
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            metadata={"target": target, "type": target_type, "scanners": scanners, "source": source},
            result={
                "scan_id": scan_id,
                "findings_count": len(all_findings),
                "sbom_component_count": len(all_components),
                "summary": final_summary.model_dump(),
            },
            error=error_text,
        )

    async def list_targets(
        self,
        type_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        total, items = await self.target_repo.list_targets(type_filter=type_filter, limit=limit, offset=offset)
        # Enrich with latest scan summary + scan ID + running status
        for item in items:
            target_id = item.get("target_id")
            if target_id:
                latest = await self.scan_repo.get_latest_by_target(target_id)
                if latest:
                    item["latest_summary"] = latest.get("summary")
                    item["latest_scan_id"] = str(latest.get("_id", ""))
                item["has_running_scan"] = await self.scan_repo.has_running_scan(target_id)
        return total, items

    async def get_target(self, target_id: str) -> dict[str, Any] | None:
        target = await self.target_repo.get(target_id)
        if target:
            latest = await self.scan_repo.get_latest_by_target(target_id)
            if latest:
                target["latest_summary"] = latest.get("summary")
                target["latest_scan_id"] = str(latest.get("_id", ""))
        return target

    async def delete_target(self, target_id: str) -> bool:
        """Delete a target and all associated scan data."""
        await self.finding_repo.delete_by_target(target_id)
        await self.sbom_repo.delete_by_target(target_id)
        await self.scan_repo.delete_by_target(target_id)
        return await self.target_repo.delete(target_id)

    async def list_scans(
        self,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        total, items = await self.scan_repo.list_all(
            target_id=target_id, status=status, limit=limit, offset=offset
        )
        # Enrich with target name
        for item in items:
            tid = item.get("target_id")
            if tid:
                target = await self.target_repo.get(tid)
                item["target_name"] = target.get("name") if target else tid
        return total, items

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        scan = await self.scan_repo.get(scan_id)
        if scan:
            tid = scan.get("target_id")
            if tid:
                target = await self.target_repo.get(tid)
                scan["target_name"] = target.get("name") if target else tid
        return scan

    async def get_scan_findings(
        self,
        scan_id: str,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        total, items = await self.finding_repo.list_by_scan(scan_id, severity=severity, limit=limit, offset=offset)

        # Lazy fix-version correction for scans completed before the correction pass was added.
        # Detect any findings with downgrade fix versions and correct them now.
        needs_correction = [
            item for item in items
            if item.get("fix_version") and item.get("package_version") and item.get("vulnerability_id")
            and self._is_downgrade(item.get("package_version", ""), item.get("fix_version", ""))
        ]
        if needs_correction:
            # Convert dicts to ScanFindingDocument-like objects for the correction method
            from app.models.scan import ScanFindingDocument
            docs = [
                ScanFindingDocument(
                    scan_id=str(item.get("scan_id", scan_id)),
                    target_id=str(item.get("target_id", "")),
                    scanner=item.get("scanner", ""),
                    package_name=item.get("package_name", ""),
                    package_version=item.get("package_version", ""),
                    vulnerability_id=item.get("vulnerability_id"),
                    fix_version=item.get("fix_version"),
                    package_type=item.get("package_type", ""),
                    severity=item.get("severity", "unknown"),
                )
                for item in needs_correction
            ]
            await self._fix_downgrade_fix_versions(scan_id, docs)
            # Re-fetch with corrected data
            total, items = await self.finding_repo.list_by_scan(scan_id, severity=severity, limit=limit, offset=offset)

        return total, items

    @staticmethod
    def _is_downgrade(package_version: str, fix_version: str) -> bool:
        """Return True if fix_version major is less than package_version major."""
        try:
            return int(fix_version.split(".")[0]) < int(package_version.split(".")[0])
        except (ValueError, IndexError):
            return False

    async def get_scan_sbom(
        self,
        scan_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        return await self.sbom_repo.list_by_scan(scan_id, search=search, limit=limit, offset=offset)

    async def find_by_cve(
        self, cve_id: str, limit: int = 50, offset: int = 0
    ) -> tuple[int, list[dict[str, Any]]]:
        return await self.finding_repo.find_by_cve(cve_id, limit=limit, offset=offset)

    async def get_target_history(self, target_id: str, limit: int = 30) -> list[dict[str, Any]]:
        return await self.scan_repo.get_history(target_id, limit=limit)

    async def compare_scans(
        self, scan_id_a: str, scan_id_b: str
    ) -> dict[str, Any]:
        """Compare two scans and return added/removed/unchanged findings."""
        scan_a = await self.scan_repo.get(scan_id_a)
        scan_b = await self.scan_repo.get(scan_id_b)
        if not scan_a or not scan_b:
            return {"error": "One or both scans not found"}

        _, findings_a_list = await self.finding_repo.list_by_scan(scan_id_a, limit=5000)
        _, findings_b_list = await self.finding_repo.list_by_scan(scan_id_b, limit=5000)

        def _finding_key(f: dict[str, Any]) -> str:
            vuln_id = f.get("vulnerability_id") or f.get("title") or str(f.get("_id", ""))
            return f"{vuln_id}:{f.get('package_name', '')}:{f.get('package_version', '')}"

        def _finding_summary(f: dict[str, Any]) -> dict[str, Any]:
            return {
                "vulnerability_id": f.get("vulnerability_id"),
                "package_name": f.get("package_name", ""),
                "package_version": f.get("package_version", ""),
                "severity": f.get("severity", "unknown"),
                "fix_version": f.get("fix_version"),
            }

        set_a = {_finding_key(f): f for f in findings_a_list}
        set_b = {_finding_key(f): f for f in findings_b_list}

        keys_a = set(set_a.keys())
        keys_b = set(set_b.keys())

        added = [_finding_summary(set_b[k]) for k in (keys_b - keys_a)]
        removed = [_finding_summary(set_a[k]) for k in (keys_a - keys_b)]
        unchanged_count = len(keys_a & keys_b)

        summary_a = scan_a.get("summary", {})
        summary_b = scan_b.get("summary", {})

        return {
            "scan_id_a": scan_id_a,
            "scan_id_b": scan_id_b,
            "summary_a": summary_a,
            "summary_b": summary_b,
            "added": added,
            "removed": removed,
            "unchanged_count": unchanged_count,
        }

    async def update_target_auto_scan(self, target_id: str, auto_scan: bool) -> bool:
        """Update auto_scan flag on a target."""
        return await self.target_repo.update_auto_scan(target_id, auto_scan)

    async def list_auto_scan_targets(self) -> list[dict[str, Any]]:
        """List all targets with auto_scan enabled."""
        return await self.target_repo.list_auto_scan_targets()

    # --- Private helpers ---

    async def _match_cve_for_unmatched_findings(
        self, scan_id: str, findings: list[ScanFindingDocument]
    ) -> None:
        """Try to match findings without CVE against the local vulnerability DB via OpenSearch."""
        from app.db.opensearch import async_search

        unmatched = [f for f in findings if not f.vulnerability_id]
        if not unmatched:
            return

        # Group by package name to avoid repeated searches
        seen_packages: dict[str, str | None] = {}
        matched_count = 0

        for finding in unmatched:
            pkg = finding.package_name.lower().strip()
            if not pkg:
                continue

            if pkg in seen_packages:
                cve_id = seen_packages[pkg]
            else:
                cve_id = await self._search_cve_by_package(pkg, async_search)
                seen_packages[pkg] = cve_id

            if cve_id:
                finding.vulnerability_id = cve_id
                finding.matched_from = "auto"
                matched_count += 1
                # Update in DB
                await self.finding_repo.update_vulnerability_id(
                    str(finding.scan_id), finding.package_name, finding.package_version,
                    cve_id, matched_from="auto",
                )

        if matched_count > 0:
            log.info("scan_service.cve_fallback_matched", scan_id=scan_id, matched=matched_count, total_unmatched=len(unmatched))

    async def _fix_downgrade_fix_versions(
        self, scan_id: str, findings: list[ScanFindingDocument]
    ) -> None:
        """
        For findings where the scanner-reported fix_version is a downgrade (fix major < pkg major),
        look up the vulnerability's productVersions / cpeConfigurations to find the correct fix.
        If no valid version is found, clear fix_version (fixState stays 'fixed').
        """
        from app.repositories.vulnerability_repository import VulnerabilityRepository

        # Collect unique (pkg_name, pkg_version, vuln_id) combos that need correction
        to_fix: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for f in findings:
            if not f.fix_version or not f.vulnerability_id or not f.package_version:
                continue
            try:
                pkg_major = int(f.package_version.split(".")[0])
                fix_major = int(f.fix_version.split(".")[0])
            except (ValueError, IndexError):
                continue
            if fix_major >= pkg_major:
                continue  # Not a downgrade
            key = (f.package_name, f.package_version)
            if key not in seen:
                seen.add(key)
                to_fix.append((f.package_name, f.package_version, f.vulnerability_id))

        if not to_fix:
            return

        vuln_repo = await VulnerabilityRepository.create()
        vuln_cache: dict[str, dict[str, Any]] = {}
        fixed_count = 0

        for pkg_name, pkg_version, vuln_id in to_fix:
            try:
                pkg_major = int(pkg_version.split(".")[0])
            except (ValueError, IndexError):
                continue

            if vuln_id not in vuln_cache:
                vuln_cache[vuln_id] = await vuln_repo.get_version_data(vuln_id)

            vdata = vuln_cache[vuln_id]
            # Prefer productVersions (range strings, more commonly populated)
            correct_fix = self._extract_fix_from_product_versions(
                vdata.get("productVersions", []), pkg_major
            )
            # Fall back to CPE configuration nodes
            if correct_fix is None:
                correct_fix = self._extract_fix_from_cpe(
                    vdata.get("cpeConfigurations", []), pkg_major
                )
            await self.finding_repo.update_fix_version(scan_id, pkg_name, pkg_version, correct_fix)
            fixed_count += 1

        if fixed_count > 0:
            log.info("scan_service.fix_version_corrected", scan_id=scan_id, corrected=fixed_count)

    @staticmethod
    def _extract_fix_from_product_versions(product_versions: list[str], pkg_major: int) -> str | None:
        """
        Parse productVersions range strings and find the upper bound for pkg_major.
        Handles formats:
          "0 <6.0.6"          -> fix = 6.0.6
          "7.0.0 <7.0.5"      -> fix = 7.0.5
          ">= 7.0.0, < 7.0.5" -> fix = 7.0.5
          "< 7.0.5"           -> fix = 7.0.5
          "7.0.0, <= 7.0.4"   -> fix = 7.0.4 (inclusive end — no bump for now)
        """
        import re
        best: str | None = None
        # Specificity: prefer ranges that also have a same-major start (most specific)
        best_specific = False

        for entry in product_versions:
            if not isinstance(entry, str):
                continue
            # Extract all version-like tokens preceded by optional operator
            tokens = re.findall(r"([<>]=?)\s*([\d]+\.[\d.]+)", entry)
            end_ver: str | None = None
            start_major: int | None = None
            for op, ver in tokens:
                try:
                    major = int(ver.split(".")[0])
                except (ValueError, IndexError):
                    continue
                if op in ("<", "<=") and major == pkg_major:
                    end_ver = ver
                elif op in (">", ">="):
                    start_major = major

            # Also handle bare "start <end" format (no operator on start, e.g. "0 <6.0.6")
            if end_ver is None:
                bare = re.match(r"^([\d.]+)\s+<\s*([\d]+\.[\d.]+)$", entry.strip())
                if bare:
                    try:
                        end_major = int(bare.group(2).split(".")[0])
                        if end_major == pkg_major:
                            end_ver = bare.group(2)
                            try:
                                start_major = int(bare.group(1).split(".")[0])
                            except (ValueError, IndexError):
                                pass
                    except (ValueError, IndexError):
                        pass

            if end_ver is None:
                continue

            is_specific = (start_major is not None and start_major == pkg_major)
            if best is None or (is_specific and not best_specific):
                best = end_ver
                best_specific = is_specific

        return best

    @staticmethod
    def _extract_fix_from_cpe(cpe_configurations: list[dict[str, Any]], pkg_major: int) -> str | None:
        """
        Walk CPE configuration nodes and find a versionEndExcluding / versionEndIncluding
        whose major version matches pkg_major. Returns the fix version or None.
        """
        def walk_nodes(nodes: list[dict[str, Any]]) -> str | None:
            for node in nodes:
                for match in node.get("matches", []):
                    for end_field in ("versionEndExcluding", "versionEndIncluding"):
                        end_ver = match.get(end_field)
                        if not end_ver:
                            continue
                        try:
                            if int(end_ver.split(".")[0]) == pkg_major:
                                return end_ver
                        except (ValueError, IndexError):
                            continue
                result = walk_nodes(node.get("nodes", []))
                if result:
                    return result
            return None

        return walk_nodes(cpe_configurations)

    @staticmethod
    async def _search_cve_by_package(package_name: str, async_search_fn: Any) -> str | None:
        """Search OpenSearch for a CVE matching a package name."""
        index = settings.opensearch_index
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "should": [
                        {"term": {"products": package_name}},
                        {"wildcard": {"products": {"value": f"*{package_name}*", "case_insensitive": True}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "_source": ["vuln_id"],
            "sort": [{"published": {"order": "desc"}}],
        }
        try:
            result = await async_search_fn(index, query)
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_source", {}).get("vuln_id")
        except Exception as exc:
            log.warning("scan_service.cve_search_failed", package=package_name, error=str(exc))
        return None

    async def _call_scanner_sidecar(
        self, target: str, target_type: str, scanners: list[str]
    ) -> list[dict[str, Any]]:
        """Call the scanner sidecar HTTP API."""
        url = f"{settings.sca_scanner_url}/scan"
        payload = {
            "target": target,
            "type": target_type,
            "scanners": scanners,
        }
        async with httpx.AsyncClient(timeout=settings.sca_scanner_timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("results", [])

    @staticmethod
    def _derive_target_id(target: str, target_type: str) -> str:
        """Derive a stable target ID from the target reference."""
        # For container images, strip the tag to group all tags of the same image
        if target_type == "container_image":
            # Remove tag/digest suffix: registry/repo:tag -> registry/repo
            parts = target.split("@")[0]  # Remove digest
            parts = parts.rsplit(":", 1)
            if len(parts) == 2 and "/" in parts[0]:
                return parts[0]  # Has tag, strip it
            return target  # No tag, use as-is
        return target

    @staticmethod
    def _derive_target_name(target: str) -> str:
        """Derive a human-readable name from the target reference."""
        # For URLs, use the path
        if "://" in target:
            parsed = urlparse(target)
            path = parsed.path.strip("/")
            return path.split("/")[-1] if "/" in path else path
        # For image refs, use the last path segment
        parts = target.split("@")[0].rsplit(":", 1)[0]
        if "/" in parts:
            return parts.split("/")[-1]
        return parts

    @staticmethod
    def _extract_registry(target: str) -> str | None:
        """Extract registry host from image reference."""
        parts = target.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
            return parts[0]
        return None

    @staticmethod
    def _deduplicate_findings(findings: list[ScanFindingDocument]) -> list[ScanFindingDocument]:
        """Remove duplicate findings (same CVE + package, keep first scanner's report)."""
        seen: set[str] = set()
        deduped: list[ScanFindingDocument] = []
        for f in findings:
            key = f"{f.vulnerability_id or ''}:{f.package_name}:{f.package_version}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    @staticmethod
    def _compute_summary(findings: list[ScanFindingDocument]) -> ScanSummary:
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0,
        }
        for f in findings:
            key = f.severity if f.severity in counts else "unknown"
            counts[key] += 1
        return ScanSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            negligible=counts["negligible"],
            unknown=counts["unknown"],
            total=len(findings),
        )


async def get_scan_service() -> ScanService:
    target_repo = await ScanTargetRepository.create()
    scan_repo = await ScanRepository.create()
    finding_repo = await ScanFindingRepository.create()
    sbom_repo = await ScanSbomRepository.create()
    log_repo = await IngestionLogRepository.create()
    audit_service = AuditService(log_repo)
    return ScanService(target_repo, scan_repo, finding_repo, sbom_repo, audit_service)
