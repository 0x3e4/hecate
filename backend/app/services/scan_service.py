from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import structlog
from bson import ObjectId

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
from app.repositories.scan_layer_repository import ScanLayerRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.scan_sbom_repository import ScanSbomRepository
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services.audit_service import AuditService
from app.services.notification_service import get_notification_service
from app.services.scan_parser import (
    parse_cyclonedx_sbom,
    parse_dockle_json,
    parse_dive_json,
    parse_grype_json,
    parse_hecate_json,
    parse_osv_json,
    parse_semgrep_json,
    parse_trivy_json,
    parse_trufflehog_json,
)

log = structlog.get_logger()

# Module-level dict to track running scan tasks across ScanService instances
_running_scan_tasks: dict[str, asyncio.Task] = {}

# Lazy-initialised semaphore to limit concurrent scans
_scan_semaphore: asyncio.Semaphore | None = None


def _get_scan_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = asyncio.Semaphore(settings.sca_max_concurrent_scans)
    return _scan_semaphore


class ScanService:
    def __init__(
        self,
        target_repo: ScanTargetRepository,
        scan_repo: ScanRepository,
        finding_repo: ScanFindingRepository,
        sbom_repo: ScanSbomRepository,
        layer_repo: ScanLayerRepository,
        audit_service: AuditService,
    ) -> None:
        self.target_repo = target_repo
        self.scan_repo = scan_repo
        self.finding_repo = finding_repo
        self.sbom_repo = sbom_repo
        self.layer_repo = layer_repo
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
        source_archive_base64: str | None = None,
        one_time: bool = False,
    ) -> dict[str, Any]:
        """Submit a scan request. Creates scan record and kicks off background processing.

        Returns immediately with scan_id + status=running so the caller doesn't block.
        """

        if scanners is None:
            scanners = ["trivy", "grype", "syft"]

        if source_archive_base64 and target_type != "source_repo":
            raise ValueError("source archive is only supported for source_repo scans")

        # 1. Upsert scan target (unless one-time scan)
        target_id = (
            f"one-time-upload:{uuid4().hex}"
            if one_time
            else self._derive_target_id(target, target_type)
        )
        target_name = self._derive_target_name(target)
        if not one_time:
            registry = self._extract_registry(target) if target_type == "container_image" else None
            repo_url = target if target_type == "source_repo" else None

            target_doc = ScanTargetDocument(
                target_id=target_id,
                type=target_type,
                name=target_name,
                registry=registry,
                repository_url=repo_url,
                scanners=scanners,
            )
            await self.target_repo.upsert(target_doc)

        # 2. Create scan record (status=pending — will transition to running when semaphore acquired)
        submitted_at = datetime.now(tz=UTC)
        scan_doc = ScanDocument(
            target_id=target_id,
            target_name=target_name,
            scanners=scanners,
            status="pending",
            source=source,
            image_ref=target if target_type == "container_image" else None,
            commit_sha=commit_sha,
            branch=branch,
            pipeline_url=pipeline_url,
            started_at=submitted_at,
        )
        scan_id = await self.scan_repo.insert(scan_doc)

        # 3. Fire off background task and return immediately
        task = asyncio.create_task(
            self._run_scan_background(
                scan_id=scan_id,
                target=target,
                target_id=target_id,
                target_type=target_type,
                scanners=scanners,
                source=source,
                submitted_at=submitted_at,
                source_archive_base64=source_archive_base64,
            )
        )
        _running_scan_tasks[scan_id] = task
        task.add_done_callback(lambda _t: _running_scan_tasks.pop(scan_id, None))

        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "status": "pending",
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
        submitted_at: datetime,
        source_archive_base64: str | None = None,
    ) -> None:
        """Execute scan in background with concurrency limiting.

        The scan waits in "pending" state until a semaphore slot opens, then
        transitions to "running" and calls the scanner sidecar.
        """
        from app.services.event_bus import publish_job_completed, publish_job_failed, publish_job_started

        sem = _get_scan_semaphore()
        try:
            async with sem:
                # Semaphore acquired — transition to running
                started_at = datetime.now(tz=UTC)
                await self.scan_repo.update_status(scan_id, "running")
                await self.scan_repo.update_fields(scan_id, {"started_at": started_at})
                publish_job_started(f"sca_scan_{scan_id}", started_at, target=target, scan_id=scan_id)

                # Wait for scanner sidecar to have sufficient resources
                await self._wait_for_scanner_resources(scan_id)

                await self._run_scan_background_inner(
                    scan_id, target, target_id, target_type, scanners, source, started_at, source_archive_base64,
                )
                finished_at = datetime.now(tz=UTC)
                publish_job_completed(f"sca_scan_{scan_id}", started_at, finished_at, scan_id=scan_id)
        except asyncio.CancelledError:
            log.info("scan_service.scan_cancelled", scan_id=scan_id, target=target)
            finished_at = datetime.now(tz=UTC)
            await self.scan_repo.update_status(scan_id, "cancelled", finished_at=finished_at,
                                               duration_seconds=(finished_at - submitted_at).total_seconds())
            await self.finding_repo.delete_by_scan(scan_id)
            await self.sbom_repo.delete_by_scan(scan_id)
            publish_job_failed(f"sca_scan_{scan_id}", submitted_at, finished_at, error="cancelled")
        except Exception as exc:
            log.exception("scan_service.scan_background_error", scan_id=scan_id, error=str(exc))
            finished_at = datetime.now(tz=UTC)
            publish_job_failed(f"sca_scan_{scan_id}", submitted_at, finished_at, error=str(exc))

    async def import_sbom(
        self,
        sbom_data: dict[str, Any],
        format: str | None = None,
        target_name: str | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        """Import an external SBOM file. Creates target + scan + components + matched findings."""
        from app.services.scan_parser import parse_cyclonedx_sbom, parse_spdx_sbom

        # Auto-detect format
        if not format:
            if sbom_data.get("bomFormat") == "CycloneDX":
                format = "cyclonedx-json"
            elif sbom_data.get("spdxVersion"):
                format = "spdx-json"
            else:
                raise ValueError("Cannot auto-detect SBOM format. Provide 'format' parameter.")

        # Derive target name from SBOM metadata if not given
        if not target_name:
            if format == "cyclonedx-json":
                meta = sbom_data.get("metadata", {})
                comp = meta.get("component", {}) if isinstance(meta, dict) else {}
                target_name = comp.get("name", "SBOM Import") if isinstance(comp, dict) else "SBOM Import"
            elif format == "spdx-json":
                target_name = sbom_data.get("name", "SBOM Import")
            else:
                target_name = "SBOM Import"

        # Create or reuse target
        if not target_id:
            target_id = f"sbom-import-{target_name.lower().replace(' ', '-')[:60]}"

        existing_target = await self.target_repo.get(target_id)
        if not existing_target:
            from app.models.scan import ScanTargetDocument
            target_doc = ScanTargetDocument(
                target_id=target_id,
                type="sbom-import",
                name=target_name,
                scanners=["sbom-import"],
                auto_scan=False,
            )
            await self.target_repo.upsert(target_doc)

        # Create scan record
        started_at = datetime.now(tz=UTC)
        from app.models.scan import ScanDocument, ScanSummary
        scan_doc = ScanDocument(
            target_id=target_id,
            target_name=target_name,
            scanners=["sbom-import"],
            status="completed",
            source="sbom-import",
            started_at=started_at,
            finished_at=started_at,
            duration_seconds=0,
        )
        scan_id_val = await self.scan_repo.insert(scan_doc)

        # Parse components
        if format == "cyclonedx-json":
            components, comp_count = parse_cyclonedx_sbom(sbom_data, scan_id_val, target_id)
        else:
            components, comp_count = parse_spdx_sbom(sbom_data, scan_id_val, target_id)

        # Store components
        if components:
            await self.sbom_repo.bulk_insert(components)

        # Match vulnerabilities for imported components
        all_findings: list[Any] = []
        try:
            findings = await self._match_vulnerabilities_for_components(scan_id_val, target_id, components)
            if findings:
                await self.finding_repo.bulk_insert(findings)
                all_findings = findings
        except Exception:
            log.warning("scan_service.import_sbom_match_failed", scan_id=scan_id_val, exc_info=True)

        # Compute summary
        summary = self._compute_summary(all_findings)

        # Evaluate license compliance
        lc_summary = None
        try:
            from app.repositories.license_policy_repository import LicensePolicyRepository
            from app.services.license_compliance_service import LicenseComplianceService

            lp_repo = await LicensePolicyRepository.create()
            lc_service = LicenseComplianceService(lp_repo, self.sbom_repo)
            lc_summary = await lc_service.compute_summary(scan_id_val)
        except Exception:
            pass

        # Update scan record
        from app.db.mongo import get_database
        db = await get_database()
        update_data: dict[str, Any] = {
            "summary": summary.model_dump(),
            "sbom_component_count": comp_count,
        }
        if lc_summary:
            update_data["license_compliance_summary"] = lc_summary
        await db[settings.mongo_scans_collection].update_one(
            {"_id": ObjectId(scan_id_val)},
            {"$set": update_data},
        )

        await self.target_repo.update_last_scan(target_id, started_at)

        return {
            "scan_id": scan_id_val,
            "target_id": target_id,
            "status": "completed",
            "findings_count": len(all_findings),
            "sbom_component_count": comp_count,
            "summary": summary,
        }

    async def _match_vulnerabilities_for_components(
        self,
        scan_id: str,
        target_id: str,
        components: list[Any],
    ) -> list[ScanFindingDocument]:
        """Search local vulnerability DB for CVEs matching SBOM components."""
        if not components:
            return []

        try:
            from app.db.opensearch import async_search
        except Exception:
            return []

        findings: list[ScanFindingDocument] = []
        cache: dict[str, str | None] = {}

        for comp in components:
            pkg_name = comp.name if hasattr(comp, "name") else comp.get("name", "")
            pkg_version = comp.version if hasattr(comp, "version") else comp.get("version", "")
            if not pkg_name:
                continue

            pkg_key = pkg_name.lower().strip()
            if pkg_key in cache:
                cve_id = cache[pkg_key]
            else:
                cve_id = await self._search_cve_by_package(pkg_name, async_search)
                cache[pkg_key] = cve_id

            if cve_id:
                findings.append(ScanFindingDocument(
                    scan_id=scan_id,
                    target_id=target_id,
                    vulnerability_id=cve_id,
                    matched_from="sbom-import",
                    scanner="sbom-import",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    package_type=comp.type if hasattr(comp, "type") else comp.get("type", ""),
                    severity="unknown",
                    title=f"Matched from local DB for {pkg_name}",
                ))

        return findings

    async def _run_scan_background_inner(
        self,
        scan_id: str,
        target: str,
        target_id: str,
        target_type: str,
        scanners: list[str],
        source: str,
        started_at: datetime,
        source_archive_base64: str | None = None,
    ) -> None:
        """Inner scan logic, separated to allow CancelledError handling in the wrapper."""
        from app.services.scan_parser import _filter_and_merge_sbom

        all_findings: list[ScanFindingDocument] = []
        all_components: list[ScanSbomComponentDocument] = []
        errors: list[str] = []
        scan_metadata: dict[str, Any] = {}

        async def _run_single_scanner(scanner_name: str) -> None:
            """Run one scanner via the sidecar, parse & store results immediately."""
            nonlocal scan_metadata
            try:
                results, metadata = await self._call_scanner_sidecar(
                    target=target,
                    target_type=target_type,
                    scanners=[scanner_name],
                    source_archive_base64=source_archive_base64,
                )
                if metadata and not scan_metadata:
                    scan_metadata = metadata
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
                    elif fmt == "hecate-json":
                        findings, components, _ = parse_hecate_json(report, scan_id, target_id)
                    elif fmt == "dockle-json":
                        findings, compliance_summary = parse_dockle_json(report, scan_id, target_id)
                        await self.scan_repo.update_fields(scan_id, {
                            "compliance_summary": compliance_summary,
                        })
                    elif fmt == "semgrep-json":
                        findings, _ = parse_semgrep_json(report, scan_id, target_id)
                    elif fmt == "trufflehog-json":
                        findings, _ = parse_trufflehog_json(report, scan_id, target_id)
                    elif fmt == "dive-json":
                        layer_doc = parse_dive_json(report, scan_id, target_id)
                        await self.layer_repo.insert(layer_doc)
                        await self.scan_repo.update_fields(scan_id, {
                            "layer_analysis_available": True,
                        })
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

        # Severity override: prefer local vuln DB severity over scanner-reported severity
        await self._override_severity_from_vuln_db(scan_id, all_findings)

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
        # Persist scanner-reported metadata (commit SHA, image digest)
        meta_update: dict[str, Any] = {"summary_version": 3, "severity_overridden": True}
        if scan_metadata.get("commit_sha"):
            meta_update["commit_sha"] = scan_metadata["commit_sha"]
        if scan_metadata.get("image_digest"):
            # Store full image ref with digest: image@sha256:...
            digest = scan_metadata["image_digest"]
            base_ref = target.split("@")[0].rsplit(":", 1)[0] if target_type == "container_image" else target
            meta_update["image_ref"] = f"{base_ref}@{digest}"
        try:
            from app.db.mongo import get_database
            db = await get_database()
            await db[settings.mongo_scans_collection].update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": meta_update},
            )
        except Exception:
            pass
        await self.target_repo.update_last_scan(target_id, finished_at)

        # Persist fingerprint for change detection on future auto-scans
        if scan_metadata.get("image_digest"):
            await self.target_repo.update_last_fingerprint(target_id, image_digest=scan_metadata["image_digest"])
        if scan_metadata.get("commit_sha"):
            await self.target_repo.update_last_fingerprint(target_id, commit_sha=scan_metadata["commit_sha"])

        # VEX carry-forward: copy VEX annotations from previous scan
        try:
            _, prev_scans = await self.scan_repo.list_by_target(target_id, limit=2)
            prev_scan_id = None
            for ps in prev_scans:
                ps_id = str(ps.get("_id", ""))
                if ps_id != scan_id and ps.get("status") == "completed":
                    prev_scan_id = ps_id
                    break
            if prev_scan_id:
                from app.services.vex_service import VexService
                vex_svc = VexService(self.finding_repo, self.scan_repo)
                carried = await vex_svc.carry_forward_vex(prev_scan_id, scan_id)
                if carried:
                    log.info("scan_service.vex_carried_forward", scan_id=scan_id, from_scan=prev_scan_id, count=carried)
                # Carry forward dismissal flags (independent from VEX annotations)
                carried_dismissed = await self.finding_repo.carry_forward_dismissed(prev_scan_id, scan_id)
                if carried_dismissed:
                    log.info("scan_service.dismissed_carried_forward", scan_id=scan_id, from_scan=prev_scan_id, count=carried_dismissed)
        except Exception:
            log.warning("scan_service.vex_carry_forward_failed", scan_id=scan_id, exc_info=True)

        # Evaluate license compliance if a default policy exists
        try:
            from app.repositories.license_policy_repository import LicensePolicyRepository
            from app.services.license_compliance_service import LicenseComplianceService

            lp_repo = await LicensePolicyRepository.create()
            lc_service = LicenseComplianceService(lp_repo, self.sbom_repo)
            lc_summary = await lc_service.compute_summary(scan_id)
            if lc_summary:
                from app.db.mongo import get_database as _get_db
                _db = await _get_db()
                await _db[settings.mongo_scans_collection].update_one(
                    {"_id": ObjectId(scan_id)},
                    {"$set": {"license_compliance_summary": lc_summary}},
                )
        except Exception:
            log.warning("scan_service.license_compliance_failed", scan_id=scan_id, exc_info=True)

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

        try:
            notifier = get_notification_service()

            # -- Classify findings by category --
            _SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
            _NON_VULN = {"malicious-indicator", "compliance-check", "sast-finding", "secret-finding"}
            vuln_findings = [f for f in all_findings if f.package_type not in _NON_VULN]
            alert_findings = [f for f in all_findings if f.package_type == "malicious-indicator"]
            sast_findings = [f for f in all_findings if f.package_type == "sast-finding"]
            secret_findings = [f for f in all_findings if f.package_type == "secret-finding"]
            compliance_findings = [f for f in all_findings if f.package_type == "compliance-check"]

            def _sev_counts(findings: list) -> dict[str, int]:
                c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for f in findings:
                    s = (f.severity or "").lower()
                    if s in c:
                        c[s] += 1
                return c

            # -- Top vulnerability findings (sorted by severity/CVSS, top 10) --
            top_sorted = sorted(
                vuln_findings,
                key=lambda f: (-_SEV_RANK.get(f.severity, 0), -(f.cvss_score or 0)),
            )[:10]
            top_findings = [
                {
                    "id": f.vulnerability_id or "N/A",
                    "severity": f.severity or "N/A",
                    "cvss": str(f.cvss_score) if f.cvss_score is not None else "N/A",
                    "package": f.package_name or "N/A",
                    "version": f.package_version or "N/A",
                    "fix": f.fix_version or "N/A",
                    "title": (f.title[:120] + "\u2026") if f.title and len(f.title) > 120 else (f.title or "N/A"),
                }
                for f in top_sorted
            ]

            # -- Top alert / SAST / secret findings (top 5 each) --
            _top = lambda lst: sorted(lst, key=lambda f: -_SEV_RANK.get(f.severity, 0))[:5]
            _trunc = lambda s, n=120: (s[:n] + "\u2026") if s and len(s) > n else (s or "N/A")

            top_alerts = [
                {"severity": f.severity or "N/A", "package": f.package_name or "N/A", "title": _trunc(f.title)}
                for f in _top(alert_findings)
            ]
            top_sast = [
                {"severity": f.severity or "N/A", "title": _trunc(f.title), "file": f.package_path or f.package_name or "N/A"}
                for f in _top(sast_findings)
            ]
            top_secrets = [
                {
                    "severity": f.severity or "N/A",
                    "detector": f.package_name or "N/A",
                    "file": f.package_path or "N/A",
                    "verified": "Yes" if f.severity == "critical" else "No",
                }
                for f in _top(secret_findings)
            ]

            # -- License info from SBOM components --
            license_set: set[str] = set()
            for c in all_components:
                if c.licenses:
                    license_set.update(c.licenses)

            # -- Fetch license compliance summary from scan document --
            lc_sum: dict[str, int] = {}
            try:
                from app.db.mongo import get_database as _get_db2
                _db2 = await _get_db2()
                scan_doc = await _db2[settings.mongo_scans_collection].find_one(
                    {"_id": ObjectId(scan_id)}, {"license_compliance_summary": 1}
                )
                if scan_doc and scan_doc.get("license_compliance_summary"):
                    lc_sum = scan_doc["license_compliance_summary"]
            except Exception:
                pass

            alerts_sev = _sev_counts(alert_findings)
            sast_sev = _sev_counts(sast_findings)
            compliance_sev = _sev_counts(compliance_findings)

            await notifier.notify_scan_completed(
                scan_id=scan_id,
                target=target,
                target_type=target_type,
                status=status,
                findings_count=len(vuln_findings),
                duration_seconds=round(duration, 2),
                summary={
                    "critical": final_summary.critical,
                    "high": final_summary.high,
                    "medium": final_summary.medium,
                    "low": final_summary.low,
                    "negligible": final_summary.negligible,
                    "unknown": final_summary.unknown,
                },
                scanners=scanners,
                source=source,
                branch=scan_metadata.get("branch"),
                commit_sha=scan_metadata.get("commit_sha"),
                image_ref=scan_metadata.get("image_digest"),
                error=error_text,
                sbom_component_count=len(all_components),
                top_findings=top_findings,
                alerts_summary={"total": len(alert_findings), **alerts_sev},
                sast_summary={"total": len(sast_findings), **sast_sev},
                secrets_summary={
                    "total": len(secret_findings),
                    "verified": sum(1 for f in secret_findings if f.severity == "critical"),
                    "unverified": sum(1 for f in secret_findings if f.severity != "critical"),
                },
                compliance_summary={"total": len(compliance_findings), **compliance_sev},
                license_summary=lc_sum,
                licenses=", ".join(sorted(license_set)[:20]) if license_set else None,
                top_alerts=top_alerts,
                top_sast=top_sast,
                top_secrets=top_secrets,
            )
        except Exception:
            pass

    async def _get_deduped_summary(self, scan: dict[str, Any]) -> dict[str, Any]:
        """Return the deduped summary for a scan, lazily correcting if needed."""
        if scan.get("summary_version") == 3:
            return scan.get("summary", {})
        # Recompute from findings with dedup
        scan_id = str(scan.get("_id", ""))
        _, findings = await self.finding_repo.list_by_scan(scan_id, limit=10000)
        nv = self._normalize_ver
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0,
        }
        # Exclude non-vulnerability findings from summary
        _excluded = ("malicious-indicator", "compliance-check", "sast-finding", "secret-finding")
        findings = [f for f in findings if f.get("package_type") not in _excluded]
        # First pass: keyed entries with CVE; collect no-CVE separately
        keyed: dict[str, str] = {}
        no_cve: list[dict[str, Any]] = []
        for f in findings:
            ver = nv(f.get("package_version", ""))
            vuln_id = f.get("vulnerability_id", "")
            if not vuln_id:
                no_cve.append(f)
                continue
            dedup_key = f"{vuln_id}:{f.get('package_name', '')}:{ver}"
            if dedup_key not in keyed:
                keyed[dedup_key] = f.get("severity", "unknown")

        # Build fix index for merging no-CVE findings
        fix_index: dict[str, str] = {}
        for f in findings:
            vuln_id = f.get("vulnerability_id", "")
            fix_ver = f.get("fix_version", "")
            if vuln_id and fix_ver:
                idx_key = f"{f.get('package_name', '')}:{nv(f.get('package_version', ''))}:{nv(fix_ver)}"
                if idx_key not in fix_index:
                    fix_index[idx_key] = f"{vuln_id}:{f.get('package_name', '')}:{nv(f.get('package_version', ''))}"

        for f in no_cve:
            ver = nv(f.get("package_version", ""))
            fix = nv(f.get("fix_version", "")) if f.get("fix_version") else ""
            if fix:
                idx_key = f"{f.get('package_name', '')}:{ver}:{fix}"
                if idx_key in fix_index:
                    continue
            dedup_key = f":{f.get('package_name', '')}:{ver}"
            if dedup_key not in keyed:
                keyed[dedup_key] = f.get("severity", "unknown")

        for sev in keyed.values():
            key = sev if sev in counts else "unknown"
            counts[key] += 1
        summary = {**counts, "total": len(keyed)}
        # Persist corrected summary so we don't recompute next time
        await self.scan_repo.update_status(
            scan_id, scan.get("status", "completed"),
            summary=ScanSummary(**summary),
        )
        try:
            from app.db.mongo import get_database
            db = await get_database()
            await db[settings.mongo_scans_collection].update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"summary_version": 3}},
            )
        except Exception:
            pass
        return summary

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
                    item["latest_summary"] = await self._get_deduped_summary(latest)
                    item["latest_scan_id"] = str(latest.get("_id", ""))
                item["has_running_scan"] = await self.scan_repo.has_running_scan(target_id)
                if item["has_running_scan"]:
                    result = await self.scan_repo.get_running_scan_id(target_id)
                    if result:
                        item["running_scan_id"], item["running_scan_status"] = result
        return total, items

    async def get_target(self, target_id: str) -> dict[str, Any] | None:
        target = await self.target_repo.get(target_id)
        if target:
            latest = await self.scan_repo.get_latest_by_target(target_id)
            if latest:
                target["latest_summary"] = await self._get_deduped_summary(latest)
                target["latest_scan_id"] = str(latest.get("_id", ""))
            target["has_running_scan"] = await self.scan_repo.has_running_scan(target_id)
            if target.get("has_running_scan"):
                result = await self.scan_repo.get_running_scan_id(target_id)
                if result:
                    target["running_scan_id"], target["running_scan_status"] = result
        return target

    async def delete_target(self, target_id: str) -> bool:
        """Delete a target and all associated scan data."""
        await self.finding_repo.delete_by_target(target_id)
        await self.sbom_repo.delete_by_target(target_id)
        await self.scan_repo.delete_by_target(target_id)
        return await self.target_repo.delete(target_id)

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a single scan and its associated findings and SBOM components."""
        # Look up the scan to find its target_id before deletion
        scan = await self.scan_repo.get(scan_id)
        target_id = scan.get("target_id") if scan else None

        await self.finding_repo.delete_by_scan(scan_id)
        await self.sbom_repo.delete_by_scan(scan_id)
        deleted = await self.scan_repo.delete(scan_id)

        # Decrement the target's scan count
        if deleted and target_id:
            await self.target_repo.decrement_scan_count(target_id)

        return deleted

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
        # Enrich with target name, repository_url + deduped summary
        for item in items:
            tid = item.get("target_id")
            if tid and (not item.get("target_name") or not item.get("repository_url")):
                target = await self.target_repo.get(tid)
                if target:
                    if not item.get("target_name"):
                        item["target_name"] = target.get("name") or tid
                    if not item.get("repository_url") and target.get("repository_url"):
                        item["repository_url"] = target["repository_url"]
            if item.get("status") == "completed":
                item["summary"] = await self._get_deduped_summary(item)
        return total, items

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        scan = await self.scan_repo.get(scan_id)
        if scan:
            tid = scan.get("target_id")
            if tid:
                target = await self.target_repo.get(tid)
                if target:
                    if not scan.get("target_name"):
                        scan["target_name"] = target.get("name") or tid
                    if not scan.get("repository_url") and target.get("repository_url"):
                        scan["repository_url"] = target["repository_url"]
            scan["summary"] = await self._get_deduped_summary(scan)
        return scan

    async def get_layer_analysis(self, scan_id: str) -> dict[str, Any] | None:
        """Get Dive layer analysis for a scan."""
        return await self.layer_repo.get_by_scan(scan_id)

    async def get_scan_findings(
        self,
        scan_id: str,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
        include_dismissed: bool = False,
    ) -> tuple[int, list[dict[str, Any]]]:
        # Lazy severity override for scans completed before the override was added
        await self._lazy_severity_override(scan_id)

        total, items = await self.finding_repo.list_by_scan(
            scan_id, severity=severity, limit=limit, offset=offset, include_dismissed=include_dismissed
        )

        # Lazy fix-version correction for scans completed before the correction pass was added.
        # Detect any findings with downgrade fix versions and correct them now.
        needs_correction = [
            item for item in items
            if item.get("fix_version") and item.get("package_version") and item.get("vulnerability_id")
            and self._is_downgrade(item.get("package_version", ""), item.get("fix_version", ""))
        ]
        if needs_correction:
            # Convert dicts to ScanFindingDocument-like objects for the correction method
            from app.models.scan import ScanFindingDocument as SFD
            docs = [
                SFD(
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
            total, items = await self.finding_repo.list_by_scan(
                scan_id, severity=severity, limit=limit, offset=offset, include_dismissed=include_dismissed
            )

        return total, items

    async def _lazy_severity_override(self, scan_id: str) -> None:
        """One-time severity override for existing scans that predate the override feature."""
        from app.db.mongo import get_database
        db = await get_database()
        scan_col = db[settings.mongo_scans_collection]
        scan_doc = await scan_col.find_one({"_id": ObjectId(scan_id)}, {"severity_overridden": 1})
        if not scan_doc or scan_doc.get("severity_overridden"):
            return
        # Fetch all findings for this scan, build ScanFindingDocument objects, run override
        _, all_items = await self.finding_repo.list_by_scan(scan_id, limit=10000)
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
                cvss_score=item.get("cvss_score"),
            )
            for item in all_items
        ]
        await self._override_severity_from_vuln_db(scan_id, docs)
        # Mark as done + invalidate summary cache
        await scan_col.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"severity_overridden": True, "summary_version": 0}},
        )

    @staticmethod
    def _is_downgrade(package_version: str, fix_version: str) -> bool:
        """Return True if fix_version major is less than package_version major."""
        try:
            return int(fix_version.split(".")[0]) < int(package_version.split(".")[0])
        except (ValueError, IndexError):
            return False

    async def get_global_findings(
        self,
        search: str | None = None,
        severity: str | None = None,
        target_id: str | None = None,
        sort_by: str = "cvss_score",
        sort_order: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Get consolidated findings from the latest completed scan of each target."""
        scan_ids = await self.scan_repo.get_latest_completed_scan_ids(target_id=target_id)
        if not scan_ids:
            return 0, []
        return await self.finding_repo.list_across_scans_consolidated(
            scan_ids, search=search, severity=severity,
            sort_by=sort_by, sort_order=sort_order, limit=limit, offset=offset,
        )

    async def get_latest_completed_scan_ids(
        self, target_id: str | None = None
    ) -> list[str]:
        """Get the latest completed scan ID for each target."""
        return await self.scan_repo.get_latest_completed_scan_ids(target_id=target_id)

    async def get_global_sbom(
        self,
        search: str | None = None,
        type_filter: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Get consolidated SBOM components from the latest completed scan of each target."""
        scan_ids = await self.scan_repo.get_latest_completed_scan_ids(target_id=target_id)
        if not scan_ids:
            return 0, []
        return await self.sbom_repo.list_across_scans_consolidated(
            scan_ids, search=search, type_filter=type_filter, limit=limit, offset=offset
        )

    async def get_scan_sbom(
        self,
        scan_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        return await self.sbom_repo.list_by_scan(scan_id, search=search, limit=limit, offset=offset)

    async def export_sbom(self, scan_id: str, fmt: str) -> tuple[dict[str, Any], str]:
        """Build SBOM document in the requested format. Returns (document, filename)."""
        from app.services.sbom_export import build_cyclonedx_json, build_spdx_json

        scan = await self.scan_repo.get(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        target = await self.target_repo.get(scan.get("target_id", ""))
        components = await self.sbom_repo.list_all_by_scan(scan_id)

        target_name = (target.get("name", "") if target else scan.get("target_name", "unknown"))
        safe_name = target_name.replace("/", "-").replace(":", "-").replace(" ", "-")
        date_str = datetime.now(tz=UTC).strftime("%Y%m%d")

        if fmt == "spdx-json":
            doc = build_spdx_json(scan, target, components)
            filename = f"{safe_name}-sbom-{date_str}.spdx.json"
        else:
            doc = build_cyclonedx_json(scan, target, components)
            filename = f"{safe_name}-sbom-{date_str}.cdx.json"

        return doc, filename

    async def find_by_cve(
        self, cve_id: str, limit: int = 50, offset: int = 0
    ) -> tuple[int, list[dict[str, Any]]]:
        return await self.finding_repo.find_by_cve(cve_id, limit=limit, offset=offset)

    async def get_target_history(self, target_id: str, limit: int = 30, since: datetime | None = None) -> list[dict[str, Any]]:
        return await self.scan_repo.get_history(target_id, limit=limit, since=since)

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

        raw_added = {k: set_b[k] for k in (keys_b - keys_a)}
        raw_removed = {k: set_a[k] for k in (keys_a - keys_b)}
        unchanged_count = len(keys_a & keys_b)

        # Detect "changed" findings: same package+version in both added and removed
        # but with a different vulnerability_id (e.g., CVE assigned after previous scan)
        def _pkg_key(f: dict[str, Any]) -> str:
            return f"{f.get('package_name', '')}:{f.get('package_version', '')}"

        added_by_pkg: dict[str, list[str]] = {}
        for k, f in raw_added.items():
            added_by_pkg.setdefault(_pkg_key(f), []).append(k)

        removed_by_pkg: dict[str, list[str]] = {}
        for k, f in raw_removed.items():
            removed_by_pkg.setdefault(_pkg_key(f), []).append(k)

        changed: list[dict[str, Any]] = []
        changed_added_keys: set[str] = set()
        changed_removed_keys: set[str] = set()

        for pkg in set(added_by_pkg) & set(removed_by_pkg):
            a_keys = removed_by_pkg[pkg]
            b_keys = added_by_pkg[pkg]
            pairs = min(len(a_keys), len(b_keys))
            for i in range(pairs):
                changed.append({
                    "before": _finding_summary(raw_removed[a_keys[i]]),
                    "after": _finding_summary(raw_added[b_keys[i]]),
                })
                changed_removed_keys.add(a_keys[i])
                changed_added_keys.add(b_keys[i])

        added = [_finding_summary(raw_added[k]) for k in raw_added if k not in changed_added_keys]
        removed = [_finding_summary(raw_removed[k]) for k in raw_removed if k not in changed_removed_keys]

        summary_a = scan_a.get("summary", {})
        summary_b = scan_b.get("summary", {})

        return {
            "scan_id_a": scan_id_a,
            "scan_id_b": scan_id_b,
            "summary_a": summary_a,
            "summary_b": summary_b,
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged_count": unchanged_count,
        }

    VALID_SCANNERS = {"trivy", "grype", "syft", "osv-scanner", "hecate", "dockle", "dive", "semgrep", "trufflehog"}

    async def update_target_auto_scan(self, target_id: str, auto_scan: bool) -> bool:
        """Update auto_scan flag on a target."""
        return await self.target_repo.update_auto_scan(target_id, auto_scan)

    async def update_target_scanners(self, target_id: str, scanners: list[str]) -> bool:
        """Update default scanners on a target."""
        if not scanners:
            raise ValueError("At least one scanner must be selected")
        invalid = set(scanners) - self.VALID_SCANNERS
        if invalid:
            raise ValueError(f"Invalid scanners: {', '.join(sorted(invalid))}")
        return await self.target_repo.update_scanners(target_id, scanners)

    async def list_auto_scan_targets(self) -> list[dict[str, Any]]:
        """List all targets with auto_scan enabled."""
        return await self.target_repo.list_auto_scan_targets()

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan. Returns True if cancelled."""
        task = _running_scan_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        # Task not tracked (e.g. server restarted) — just update status
        scan = await self.scan_repo.get(scan_id)
        if not scan or scan.get("status") not in ("running", "pending"):
            return False
        finished_at = datetime.now(tz=UTC)
        started = scan.get("started_at") or finished_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        await self.scan_repo.update_status(scan_id, "cancelled", finished_at=finished_at,
                                           duration_seconds=(finished_at - started).total_seconds())
        await self.finding_repo.delete_by_scan(scan_id)
        await self.sbom_repo.delete_by_scan(scan_id)
        return True

    async def get_scanner_stats(self) -> dict[str, Any]:
        """Fetch resource stats from the scanner sidecar."""
        try:
            url = f"{settings.sca_scanner_url}/stats"
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                # Convert snake_case to camelCase for frontend
                def _camel(s: str) -> str:
                    parts = s.split("_")
                    return parts[0] + "".join(p.capitalize() for p in parts[1:])
                return {_camel(k): v for k, v in data.items()}
        except Exception as exc:
            log.warning("scan_service.scanner_stats_failed", error=str(exc))
            return {"error": str(exc)}

    async def check_target_changed(self, target: str, target_type: str, target_doc: dict[str, Any]) -> bool:
        """Call scanner sidecar /check and compare with stored fingerprint.

        Returns True if changed.  When the /check call fails or cannot determine
        the current fingerprint, falls back to a staleness check: if the target
        was scanned within the current auto-scan interval and a stored
        fingerprint exists, treat as unchanged to avoid redundant scans.
        """
        data: dict[str, Any] = {}
        try:
            url = f"{settings.sca_scanner_url}/check"
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(url, json={"target": target, "type": target_type})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            log.warning("scan_service.change_check_failed", target=target, error=str(exc))

        # Extract current and previous fingerprints
        if target_type == "container_image":
            current = data.get("current_digest")
            previous = target_doc.get("last_image_digest")
        elif target_type == "source_repo":
            current = data.get("current_commit_sha")
            previous = target_doc.get("last_commit_sha")
        else:
            return True

        # Happy path: both fingerprints available — compare directly
        if current and previous:
            return current != previous

        # Valid current fingerprint but no previous → first scan needed
        if current and not previous:
            return True

        # Fallback: /check failed or returned None for current fingerprint.
        # If we have a stored fingerprint from a recent scan, skip the rescan.
        if previous and target_doc.get("last_scan_at"):
            from datetime import UTC, datetime, timedelta

            last_scan_at = target_doc["last_scan_at"]
            if isinstance(last_scan_at, str):
                last_scan_at = datetime.fromisoformat(last_scan_at)
            if not last_scan_at.tzinfo:
                last_scan_at = last_scan_at.replace(tzinfo=UTC)
            interval = timedelta(minutes=settings.sca_auto_scan_interval_minutes)
            if datetime.now(tz=UTC) - last_scan_at < interval:
                log.info(
                    "scan_service.change_check_fallback_unchanged",
                    target=target,
                    reason="recent_scan_with_fingerprint",
                )
                return False

        # No stored fingerprint or last scan too old → fail-open
        log.info("scan_service.change_check_fallback_changed", target=target)
        return True

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

    async def _override_severity_from_vuln_db(
        self, scan_id: str, findings: list[ScanFindingDocument]
    ) -> None:
        """Override scanner-reported severity with local vulnerability DB severity.

        The local DB (NVD/EUVD) is considered more accurate than scanner output.
        Also corrects CVE mappings using GHSA alias lookup when a scanner's
        reported CVE doesn't exist locally but its GHSA advisory does.
        """
        import re
        from app.db.mongo import get_database

        db = await get_database()
        vuln_col = db[settings.mongo_vulnerabilities_collection]

        # --- Phase 1: GHSA alias-based CVE correction ---
        ghsa_pattern = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)

        # Build map: finding index -> GHSA IDs extracted from data_source + urls
        finding_ghsa: dict[int, list[str]] = {}
        all_ghsa_ids: set[str] = set()
        for idx, f in enumerate(findings):
            ghsa_ids: list[str] = []
            for text in [f.data_source or ""] + (f.urls or []):
                for m in ghsa_pattern.finditer(text):
                    gid = m.group(0).upper()
                    if gid not in ghsa_ids:
                        ghsa_ids.append(gid)
            if ghsa_ids:
                finding_ghsa[idx] = ghsa_ids
                all_ghsa_ids.update(ghsa_ids)

        # Lookup GHSA -> CVE mapping from aliases
        ghsa_to_cve: dict[str, tuple[str, str | None, float | None]] = {}
        if all_ghsa_ids:
            cursor = vuln_col.find(
                {"aliases": {"$in": list(all_ghsa_ids)}},
                {"_id": 1, "aliases": 1, "cvss.severity": 1, "cvss.base_score": 1},
            )
            async for doc in cursor:
                cve_id = doc["_id"]
                cvss = doc.get("cvss", {})
                sev = cvss.get("severity")
                score = cvss.get("base_score")
                for alias in doc.get("aliases", []):
                    if isinstance(alias, str) and alias.upper() in all_ghsa_ids:
                        ghsa_to_cve[alias.upper()] = (
                            cve_id,
                            sev.lower() if isinstance(sev, str) else None,
                            score,
                        )

        # Correct findings where GHSA resolves to a different CVE than reported
        cve_corrected = 0
        for idx, ghsa_ids in finding_ghsa.items():
            f = findings[idx]
            for gid in ghsa_ids:
                if gid not in ghsa_to_cve:
                    continue
                real_cve, db_sev, db_score = ghsa_to_cve[gid]
                if f.vulnerability_id and f.vulnerability_id != real_cve:
                    # Check if the scanner-reported CVE's products match the finding's package
                    existing = await vuln_col.find_one(
                        {"_id": f.vulnerability_id}, {"_id": 1, "products": 1}
                    )
                    if existing:
                        existing_products = [p.lower() for p in (existing.get("products") or [])]
                        pkg_lower = f.package_name.lower()
                        # If the existing CVE's products contain the package name, it's likely correct
                        if pkg_lower in existing_products:
                            break
                        # Products don't match — check if GHSA-resolved CVE's products match better
                        ghsa_cve_doc = await vuln_col.find_one(
                            {"_id": real_cve}, {"_id": 1, "products": 1}
                        )
                        ghsa_products = [p.lower() for p in (ghsa_cve_doc.get("products") or [])] if ghsa_cve_doc else []
                        if pkg_lower not in ghsa_products:
                            # Neither matches well — keep scanner's original mapping
                            break
                    log.info(
                        "scan_service.ghsa_cve_correction",
                        scan_id=scan_id,
                        ghsa=gid,
                        old_cve=f.vulnerability_id,
                        new_cve=real_cve,
                        package=f.package_name,
                    )
                    old_vuln_id = f.vulnerability_id
                    f.vulnerability_id = real_cve
                    if db_sev:
                        f.severity = db_sev
                    if db_score is not None:
                        f.cvss_score = db_score
                    # Update in DB
                    await self.finding_repo.collection.update_many(
                        {"scan_id": scan_id, "vulnerability_id": old_vuln_id,
                         "package_name": f.package_name},
                        {"$set": {
                            "vulnerability_id": real_cve,
                            **({"severity": db_sev} if db_sev else {}),
                            **({"cvss_score": db_score} if db_score is not None else {}),
                        }},
                    )
                    cve_corrected += 1
                    break
        if cve_corrected:
            log.info("scan_service.ghsa_corrections", scan_id=scan_id, corrected=cve_corrected)

        # --- Phase 2: Severity override from local vuln DB ---
        cve_ids = {f.vulnerability_id for f in findings if f.vulnerability_id}
        if not cve_ids:
            return

        severity_map: dict[str, tuple[str, float | None]] = {}
        cursor = vuln_col.find(
            {"_id": {"$in": list(cve_ids)}},
            {"_id": 1, "cvss.severity": 1, "cvss.base_score": 1},
        )
        async for doc in cursor:
            cve_id = doc["_id"]
            cvss = doc.get("cvss", {})
            sev = cvss.get("severity")
            score = cvss.get("base_score")
            if sev and isinstance(sev, str):
                severity_map[cve_id] = (sev.lower(), score)

        if not severity_map:
            return

        updated_count = 0
        for f in findings:
            if not f.vulnerability_id or f.vulnerability_id not in severity_map:
                continue
            db_sev, db_score = severity_map[f.vulnerability_id]
            if db_sev and db_sev != f.severity:
                f.severity = db_sev
                if db_score is not None:
                    f.cvss_score = db_score
                updated_count += 1

        if updated_count > 0:
            for cve_id, (db_sev, db_score) in severity_map.items():
                update_fields: dict[str, Any] = {"severity": db_sev}
                if db_score is not None:
                    update_fields["cvss_score"] = db_score
                await self.finding_repo.collection.update_many(
                    {"scan_id": scan_id, "vulnerability_id": cve_id},
                    {"$set": update_fields},
                )
            log.info(
                "scan_service.severity_override",
                scan_id=scan_id,
                overridden=updated_count,
                total_with_cve=len(cve_ids),
            )

    async def _wait_for_scanner_resources(self, scan_id: str) -> None:
        """Poll scanner /stats until memory and disk are sufficient, or timeout."""
        min_mem = settings.sca_min_free_memory_mb * 1024 * 1024
        min_disk = settings.sca_min_free_disk_mb * 1024 * 1024
        max_wait = 600  # 10 minutes
        retry_interval = 30

        waited = 0
        while waited < max_wait:
            try:
                url = f"{settings.sca_scanner_url}/stats"
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    data = resp.json()

                mem_free = data.get("memory_limit_bytes", 0) - data.get("memory_used_bytes", 0)
                disk_free = data.get("tmp_disk_free_bytes", 0)
                active = data.get("active_scans", 0)

                if mem_free >= min_mem and disk_free >= min_disk:
                    return  # Resources OK

                # If no other scan is active, proceed anyway (run alone)
                if active == 0:
                    log.warning("scan_service.resource_low_but_solo", scan_id=scan_id,
                                mem_free_mb=mem_free // (1024 * 1024),
                                disk_free_mb=disk_free // (1024 * 1024))
                    return

                log.info("scan_service.waiting_for_resources", scan_id=scan_id,
                         mem_free_mb=mem_free // (1024 * 1024),
                         disk_free_mb=disk_free // (1024 * 1024),
                         active_scans=active, waited_seconds=waited)
            except Exception as exc:
                log.warning("scan_service.resource_check_failed", scan_id=scan_id, error=str(exc))
                return  # Fail-open

            await asyncio.sleep(retry_interval)
            waited += retry_interval

        log.warning("scan_service.resource_wait_timeout", scan_id=scan_id, waited_seconds=waited)

    async def _call_scanner_sidecar(
        self,
        target: str,
        target_type: str,
        scanners: list[str],
        source_archive_base64: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Call the scanner sidecar HTTP API. Returns (results, metadata)."""
        url = f"{settings.sca_scanner_url}/scan"
        payload = {
            "target": target,
            "type": target_type,
            "scanners": scanners,
        }
        if source_archive_base64:
            payload["sourceArchiveBase64"] = source_archive_base64
        async with httpx.AsyncClient(timeout=settings.sca_scanner_timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("results", []), data.get("metadata") or {}

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
    @staticmethod
    def _normalize_ver(v: str) -> str:
        if v.startswith("go"):
            return v[2:]
        if v.startswith("v"):
            return v[1:]
        return v

    @staticmethod
    def _compute_summary(findings: list[ScanFindingDocument]) -> ScanSummary:
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0,
        }
        nv = ScanService._normalize_ver
        # Exclude non-vulnerability findings from vulnerability summary
        _excluded = ("malicious-indicator", "compliance-check", "sast-finding", "secret-finding")
        vuln_findings = [f for f in findings if f.package_type not in _excluded]
        # First pass: collect all findings keyed by (vuln_id, pkg, ver)
        # Track no-CVE findings separately so we can merge them with CVE entries
        keyed: dict[str, str] = {}  # dedup_key -> severity
        no_cve: list[ScanFindingDocument] = []
        for f in vuln_findings:
            ver = nv(f.package_version)
            if not f.vulnerability_id:
                no_cve.append(f)
                continue
            dedup_key = f"{f.vulnerability_id}:{f.package_name}:{ver}"
            if dedup_key not in keyed:
                keyed[dedup_key] = f.severity

        # Second pass: merge no-CVE findings if same pkg+ver+fix exists with a CVE
        fix_index: dict[str, str] = {}  # "pkg:ver:fix" -> dedup_key (with CVE)
        for f in findings:
            if f.vulnerability_id and f.fix_version:
                idx_key = f"{f.package_name}:{nv(f.package_version)}:{nv(f.fix_version)}"
                if idx_key not in fix_index:
                    fix_index[idx_key] = f"{f.vulnerability_id}:{f.package_name}:{nv(f.package_version)}"

        for f in no_cve:
            ver = nv(f.package_version)
            fix = nv(f.fix_version) if f.fix_version else ""
            if fix:
                idx_key = f"{f.package_name}:{ver}:{fix}"
                if idx_key in fix_index:
                    continue  # merged into CVE entry
            dedup_key = f":{f.package_name}:{ver}"
            if dedup_key not in keyed:
                keyed[dedup_key] = f.severity

        for sev in keyed.values():
            key = sev if sev in counts else "unknown"
            counts[key] += 1
        total = len(keyed)
        return ScanSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            negligible=counts["negligible"],
            unknown=counts["unknown"],
            total=total,
        )


async def get_scan_service() -> ScanService:
    target_repo = await ScanTargetRepository.create()
    scan_repo = await ScanRepository.create()
    finding_repo = await ScanFindingRepository.create()
    sbom_repo = await ScanSbomRepository.create()
    layer_repo = await ScanLayerRepository.create()
    log_repo = await IngestionLogRepository.create()
    audit_service = AuditService(log_repo)
    return ScanService(target_repo, scan_repo, finding_repo, sbom_repo, layer_repo, audit_service)
