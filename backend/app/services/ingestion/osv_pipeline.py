from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.deps_dev_client import DepsDevClient
from app.services.ingestion.mal_enrichment import maybe_enrich_by_id
from app.services.ingestion.osv_client import OsvClient
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.normalizer import (
    build_document_from_osv,
    extract_osv_downstream_references,
    _extract_osv_package_info,
    _extract_osv_cvss,
)
from app.utils.strings import slugify

log = structlog.get_logger()

STATE_KEY = "osv"


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse an OSV ``modified`` field into an aware UTC datetime.

    OSV records store timestamps as RFC-3339 strings (``2026-04-23T05:38:28.588737Z``).
    Returns None for missing / unparseable values so the caller can use
    None-coalescing to keep ``max_processed_modified`` valid across
    records with bad timestamps.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Python's fromisoformat doesn't accept the trailing "Z" before 3.11;
        # we run on 3.13 but keep the swap for safety.
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


class OsvPipeline:
    """
    Pipeline for ingesting vulnerabilities from OSV.dev.

    Hybrid approach (mirrors GHSA pipeline):
    - Records with CVE alias: enrich existing CVE documents with OSV data.
    - Records without CVE alias (MAL-*, PYSEC-*, etc.): create new documents.
    """

    def __init__(
        self,
        *,
        client: OsvClient | None = None,
        deps_dev_client: DepsDevClient | None = None,
        initial_sync_concurrency: int | None = None,
        initial_sync_batch_size: int | None = None,
    ) -> None:
        self.client = client or OsvClient()
        # Long-lived deps.dev client so MAL-* enrichment during a sync reuses
        # one httpx.AsyncClient + one rate-limiter across all records.
        self.deps_dev_client = deps_dev_client or DepsDevClient()
        # Initial-sync concurrency knobs. Default to settings; tests override.
        # Incremental mode ignores both — see `sync()`.
        self._initial_concurrency = max(
            1, initial_sync_concurrency
            if initial_sync_concurrency is not None
            else settings.osv_initial_sync_concurrency,
        )
        self._initial_batch_size = max(
            self._initial_concurrency, initial_sync_batch_size
            if initial_sync_batch_size is not None
            else settings.osv_initial_sync_batch_size,
        )

    async def sync(
        self,
        *,
        limit: int | None = None,
        initial_sync: bool = False,
    ) -> dict[str, int]:
        """
        Sync vulnerabilities from OSV.dev API.

        Args:
            limit: Maximum number of records to process.
            initial_sync: If True, fetch all records (no modified_since filter).
        """
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        if initial_sync and effective_limit is not None:
            log.info(
                "osv_pipeline.initial_sync_unbounded",
                configured_limit=effective_limit,
            )
            effective_limit = None
        job_name = "osv_initial_sync" if initial_sync else "osv_sync"
        label = "OSV Initial Sync" if initial_sync else "OSV Sync"
        ctx = await tracker.start(
            job_name,
            limit=effective_limit,
            initial_sync=initial_sync,
            label=label,
        )

        created = 0
        enriched = 0
        unchanged = 0
        skipped = 0
        failures = 0

        timeout_minutes = settings.ingestion_running_timeout_minutes
        timeout_seconds = timeout_minutes * 60 if timeout_minutes and timeout_minutes > 0 else None
        timed_out = False

        processed_total = 0
        last_progress_log = datetime.now(tz=UTC)
        progress_interval = 500
        log_repo: IngestionLogRepository | None = None

        # Track the highest `modified` time of any record we successfully
        # processed in this run. On a partial completion (cap hit / timeout)
        # this becomes the cursor so the next run resumes from there. With
        # oldest-first iteration in `_iter_incremental`, this is monotonic
        # and no record is permanently lost. See the cursor-advancement
        # block at the end of this method for the full logic.
        max_processed_modified: datetime | None = None

        try:
            repository = await VulnerabilityRepository.create()
            asset_catalog = await AssetCatalogService.create()

            # Determine modified_since for incremental sync
            modified_since: datetime | None = None
            if not initial_sync:
                last_ts = await state_repo.get_timestamp(STATE_KEY)
                if last_ts:
                    modified_since = last_ts
                else:
                    log.warning(
                        "osv_pipeline.no_last_timestamp",
                        message="No previous sync timestamp found - fetching all records",
                    )

            log.info(
                "osv_pipeline.starting",
                initial_sync=initial_sync,
                modified_since=modified_since.isoformat() if modified_since else None,
                limit=effective_limit,
            )

            # Initial sync: dispatch records concurrently in fixed-size batches.
            # Incremental sync: keep concurrency=1 — the OSV REST limiter
            # (osv_rate_limit_seconds) makes parallelism marginal there and
            # incremental volume is small.
            concurrency = self._initial_concurrency if initial_sync else 1
            batch_size = self._initial_batch_size if initial_sync else 1
            semaphore = asyncio.Semaphore(concurrency)

            async def _process_one(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
                """Worker coroutine. Returns (status, record) or
                ("error", record) on exception. Caller folds into counters."""
                async with semaphore:
                    try:
                        status = await self._process_record(
                            record=record,
                            repository=repository,
                            asset_catalog=asset_catalog,
                            job_name=job_name,
                            job_label=label,
                        )
                        return (status, record)
                    except Exception as exc:  # noqa: BLE001 — fold into counters
                        osv_id = record.get("id", "unknown")
                        log.warning(
                            "osv_pipeline.process_failed",
                            osv_id=osv_id,
                            error=str(exc),
                        )
                        return ("error", record)

            async with asyncio.timeout(timeout_seconds):
                # `(record, vuln_id)` buffer; collisions on `vuln_id` within
                # one batch get deferred to the next batch so concurrent
                # writes never race on the same `_id`. Different OSV IDs can
                # resolve to the same `vuln_id` (e.g. a CVE entry and a
                # GHSA entry aliasing the same CVE), and `OsvClient`'s
                # `seen_ids` set only dedups by OSV ID.
                buffer: list[tuple[dict[str, Any], str]] = []
                iterator_done = False
                iter_obj = self.client.iter_all_vulnerabilities(
                    modified_since=modified_since,
                    max_records=effective_limit,
                ).__aiter__()

                while not iterator_done or buffer:
                    # Top up the buffer until we have at least batch_size
                    # records or the iterator is exhausted.
                    while not iterator_done and len(buffer) < batch_size:
                        try:
                            record = await iter_obj.__anext__()
                        except StopAsyncIteration:
                            iterator_done = True
                            break
                        vuln_id = self._resolve_vuln_id(record)
                        if vuln_id is None:
                            # Records we can't resolve (no `id`, withdrawn,
                            # etc.) are counted here without dispatching to
                            # a worker. `_process_record` would also have
                            # returned "skipped" for these.
                            skipped += 1
                            processed_total += 1
                            continue
                        buffer.append((record, vuln_id))

                    if not buffer:
                        break

                    # Pick records to dispatch this batch; collisions on
                    # `vuln_id` go back into the buffer for the next batch.
                    seen_in_batch: set[str] = set()
                    to_dispatch: list[dict[str, Any]] = []
                    next_buffer: list[tuple[dict[str, Any], str]] = []
                    for record, vid in buffer:
                        if vid in seen_in_batch:
                            next_buffer.append((record, vid))
                        else:
                            seen_in_batch.add(vid)
                            to_dispatch.append(record)
                    buffer = next_buffer

                    results = await asyncio.gather(
                        *(_process_one(r) for r in to_dispatch),
                    )

                    for status, record in results:
                        if status == "created":
                            created += 1
                        elif status == "enriched":
                            enriched += 1
                        elif status == "unchanged":
                            unchanged += 1
                        elif status == "skipped":
                            skipped += 1
                        elif status == "error":
                            failures += 1

                        # Track newest-of-processed `modified` time. We only
                        # consider records that actually went through the
                        # upsert path (created/enriched/unchanged), not
                        # skipped or failed ones — skipped records are by
                        # definition not "processed" and their timestamps
                        # shouldn't advance the cursor.
                        if status in ("created", "enriched", "unchanged"):
                            rec_modified = _parse_iso_timestamp(record.get("modified"))
                            if rec_modified is not None and (
                                max_processed_modified is None
                                or rec_modified > max_processed_modified
                            ):
                                max_processed_modified = rec_modified

                        processed_total += 1

                    # Progress reporting once per batch (was per-record).
                    now = datetime.now(tz=UTC)
                    if (
                        processed_total % progress_interval < batch_size
                        or (now - last_progress_log).total_seconds() >= 60
                    ):
                        progress_payload = {
                            "processed": processed_total,
                            "created": created,
                            "enriched": enriched,
                            "unchanged": unchanged,
                            "skipped": skipped,
                            "failures": failures,
                            "limit": effective_limit,
                        }
                        await state_repo.update_state(
                            f"job:{ctx.name}",
                            {
                                "status": "running",
                                "progress": progress_payload,
                                "last_progress_at": now,
                            },
                        )
                        if ctx.log_id is not None:
                            if log_repo is None:
                                log_repo = await IngestionLogRepository.create()
                            await log_repo.update_progress(ctx.log_id, progress_payload)
                        log.info("osv_pipeline.progress", **progress_payload)
                        last_progress_log = now

        except TimeoutError:
            timed_out = True
            log.warning(
                "osv_pipeline.timeout",
                timeout_seconds=timeout_seconds,
                created=created,
                enriched=enriched,
                failures=failures,
            )

        except Exception as exc:
            log.exception("osv_pipeline.sync_failed", error=str(exc))
            await tracker.fail(ctx, str(exc))
            raise

        # --- Cursor advancement ---
        #
        # The previous behaviour was to unconditionally `set_timestamp(now)`
        # after the loop. That's correct only when the loop fully drained the
        # iterator: every CSV change since `modified_since` was processed. On
        # a partial completion (record-count cap hit, or async timeout) the
        # `now` cursor causes the next sync's `since=now` filter to skip the
        # CSV rows we never got to — silently dropping records.
        #
        # Observed gap from this bug: ~9 % of upstream MAL-2026 records were
        # missing because every incremental sync since 2026-04-08 hit the
        # 5000-record cap and advanced the cursor past unprocessed entries.
        #
        # Rules:
        #
        # * Full completion (no timeout, didn't hit the cap):
        #   advance to `now` — this is "everything modified since last_run is
        #   in the DB".
        # * Incremental partial completion (cap or timeout):
        #   advance to `max_processed_modified`. With oldest-first CSV
        #   iteration in `_iter_incremental`, this is the newest of the rows
        #   we processed; the rows we didn't process are all newer (smaller
        #   number of records) and the next run picks them up via
        #   `since=max_processed_modified`.
        # * Initial sync partial completion (timeout):
        #   leave the cursor unchanged. The next run sees `last_ts is None`
        #   and re-runs initial mode, which is idempotent (upserts).
        # * Zero records processed (all skipped/failed):
        #   leave the cursor unchanged so the next run retries the same
        #   range; otherwise a transient outage on every record would
        #   silently advance past them.
        hit_cap = effective_limit is not None and processed_total >= effective_limit
        partial = hit_cap or timed_out

        if not partial:
            new_cursor: datetime | None = datetime.now(tz=UTC)
        elif initial_sync:
            # Don't advance — let the next run redo initial. The ZIP iterator
            # has no per-ecosystem progress state, so partial cursor would
            # silently drop all records older than max_processed_modified
            # in any ecosystem we hadn't fully completed.
            new_cursor = None
        elif max_processed_modified is not None:
            new_cursor = max_processed_modified
        else:
            new_cursor = None

        if new_cursor is not None:
            await state_repo.set_timestamp(STATE_KEY, new_cursor)

        result = {
            "created": created,
            "enriched": enriched,
            "unchanged": unchanged,
            "skipped": skipped,
            "failures": failures,
            "limit": effective_limit,
            "modified_since": modified_since.isoformat() if modified_since else None,
            "timed_out": timed_out,
            "hit_cap": hit_cap,
            "cursor_advanced_to": new_cursor.isoformat() if new_cursor else None,
        }
        await tracker.finish(ctx, **result)
        log.info("osv_pipeline.sync_complete", **result)
        return result

    async def _process_record(
        self,
        *,
        record: dict[str, Any],
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        job_name: str,
        job_label: str,
    ) -> str:
        """
        Process a single OSV record.
        Returns: 'created', 'enriched', 'unchanged', or 'skipped'
        """
        raw_osv_id = record.get("id")
        if not isinstance(raw_osv_id, str) or not raw_osv_id.strip():
            return "skipped"
        raw_osv_id = raw_osv_id.strip()  # original case — used for OSV URLs

        # Normalize GHSA/MAL/PYSEC prefixed IDs to uppercase to match
        # the convention used by the GHSA pipeline (prevents duplicates)
        _UPPER_PREFIXES = ("GHSA-", "MAL-", "PYSEC-")
        osv_id = raw_osv_id.upper() if raw_osv_id.upper().startswith(_UPPER_PREFIXES) else raw_osv_id

        # Skip withdrawn records
        if record.get("withdrawn") is not None:
            return "skipped"

        # Determine vuln_id from aliases
        aliases_raw = record.get("aliases") or []
        cve_id: str | None = None
        ghsa_alias: str | None = None
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if not isinstance(alias, str) or not alias.strip():
                    continue
                upper = alias.strip().upper()
                if upper.startswith("CVE-") and cve_id is None:
                    cve_id = upper
                elif upper.startswith("GHSA-") and ghsa_alias is None:
                    ghsa_alias = upper

        # Priority:
        #  - MAL-* records always keep MAL-* as the primary _id, so the rich
        #    OSSF/deps.dev description + version enrichment lives on the
        #    authoritative doc. Any existing GHSA / EUVD doc that aliases
        #    this MAL-* will be absorbed into the MAL-* doc by the repository
        #    layer (see `_absorb_aliased_docs`).
        #  - For everything else, prefer CVE > GHSA > OSV ID so a CVE doc
        #    collects the richer CVE-centric feeds.
        raw_id = osv_id.strip() if isinstance(osv_id, str) else ""
        is_mal = raw_id.upper().startswith("MAL-")
        has_cve = cve_id is not None
        if is_mal:
            vuln_id = raw_id.upper()
        elif has_cve:
            vuln_id = cve_id
        elif ghsa_alias:
            vuln_id = ghsa_alias
        else:
            vuln_id = osv_id

        # Extract package info
        vendors, products, product_versions, product_version_map, impacted_products = _extract_osv_package_info(record)

        # Extract CVSS
        cvss, cvss_metrics = _extract_osv_cvss(record)

        # Extract references
        references: list[str] = []
        refs_raw = record.get("references") or []
        if isinstance(refs_raw, list):
            for ref in refs_raw:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if isinstance(url, str) and url.strip():
                        references.append(url.strip())
                elif isinstance(ref, str):
                    references.append(ref)

        # Add downstream distro reference URLs (Debian, Ubuntu)
        for downstream_url in extract_osv_downstream_references(record, vuln_id):
            if downstream_url not in references:
                references.append(downstream_url)

        # Extract CWEs
        cwes: list[str] = []
        db_specific = record.get("database_specific") or {}
        cwe_ids = db_specific.get("cwe_ids") or []
        if isinstance(cwe_ids, list):
            for cwe_id_str in cwe_ids:
                if isinstance(cwe_id_str, str) and cwe_id_str.strip():
                    cwes.append(cwe_id_str.strip())

        # Build aliases list (case-insensitive dedup)
        aliases: list[str] = [osv_id]
        seen_upper: set[str] = {osv_id.upper()}
        if has_cve:
            aliases.append(cve_id)
            seen_upper.add(cve_id.upper())
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if isinstance(alias, str) and alias.strip():
                    normed = alias.strip().upper() if alias.strip().upper().startswith(("GHSA-", "MAL-", "PYSEC-", "CVE-")) else alias.strip()
                    if normed.upper() not in seen_upper:
                        seen_upper.add(normed.upper())
                        aliases.append(normed)

        # Record assets
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=[],
                cpe_configurations=None,
            )
        except Exception as exc:
            log.warning("osv_pipeline.asset_catalog_failed", osv_id=osv_id, error=str(exc))
            catalog_result = None

        change_context = {
            "job_name": job_name,
            "job_label": job_label,
            "metadata": {
                "trigger": "automated",
                "provider": "OSV",
            },
        }

        # Build document as fallback for creation mode
        build_result = build_document_from_osv(record, ingested_at=datetime.now(tz=UTC))
        if build_result is None:
            if not has_cve:
                return "skipped"
            document = None
        else:
            document = build_result[0]

        result = await repository.upsert_from_osv(
            vuln_id=vuln_id,
            osv_id=osv_id,
            document=document,
            vendors=vendors,
            products=products,
            product_versions=product_versions,
            vendor_slugs=catalog_result.vendor_slugs if catalog_result else [slugify(v) or v.lower() for v in vendors],
            product_slugs=catalog_result.product_slugs if catalog_result else [slugify(p) or p.lower() for p in products],
            product_version_ids=catalog_result.version_ids if catalog_result else [],
            impacted_products=impacted_products,
            references=references,
            aliases=aliases,
            cwes=cwes,
            cvss=cvss,
            cvss_metrics=cvss_metrics,
            summary=record.get("summary"),
            osv_raw=record,
            change_context=change_context,
        )

        # Fill in published versions for MAL-*/GHSA-* records — OSSF publishes
        # MAL-* with `introduced: "0"` (all versions) and deps.dev gives us
        # the actual short list. We run enrichment on every upsert outcome
        # (inserted / updated / unchanged) because a doc with broad ranges
        # that OSV didn't touch on this pass still needs enrichment; the
        # helper is idempotent and bails early when ranges are already
        # specific, so the "unchanged" case is cheap (one Mongo read per
        # record + at most N deps.dev calls when targets exist).
        if vuln_id.upper().startswith(("MAL-", "GHSA-")):
            try:
                await maybe_enrich_by_id(vuln_id, client=self.deps_dev_client)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "osv_pipeline.enrichment_failed",
                    vuln_id=vuln_id,
                    error=str(exc),
                )

        if result == "inserted":
            log.debug("osv_pipeline.created", vuln_id=vuln_id, osv_id=osv_id)
            return "created"
        elif result == "updated":
            log.debug("osv_pipeline.enriched", vuln_id=vuln_id, osv_id=osv_id)
            return "enriched"
        else:
            return "unchanged"

    async def close(self) -> None:
        await self.client.close()
        await self.deps_dev_client.close()

    @staticmethod
    def _resolve_vuln_id(record: dict[str, Any]) -> str | None:
        """Compute the canonical ``vuln_id`` for an OSV record.

        Mirrors the same priority order as ``_process_record`` (MAL > CVE >
        GHSA > raw OSV ID) so the producer can deduplicate concurrent
        writes by ``vuln_id`` before dispatching workers. Returns None
        when the record should be skipped (no ID, withdrawn).

        Kept cheap — pure string manipulation on the aliases array. Runs
        once per record in the producer loop; ``_process_record`` re-runs
        the same logic, but the cost is negligible vs. the I/O work it
        guards.
        """
        raw_osv_id = record.get("id")
        if not isinstance(raw_osv_id, str) or not raw_osv_id.strip():
            return None
        raw_osv_id = raw_osv_id.strip()
        if record.get("withdrawn") is not None:
            return None

        upper_prefixes = ("GHSA-", "MAL-", "PYSEC-")
        osv_id = (
            raw_osv_id.upper()
            if raw_osv_id.upper().startswith(upper_prefixes)
            else raw_osv_id
        )

        cve_id: str | None = None
        ghsa_alias: str | None = None
        aliases_raw = record.get("aliases") or []
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if not isinstance(alias, str) or not alias.strip():
                    continue
                upper = alias.strip().upper()
                if upper.startswith("CVE-") and cve_id is None:
                    cve_id = upper
                elif upper.startswith("GHSA-") and ghsa_alias is None:
                    ghsa_alias = upper

        if osv_id.upper().startswith("MAL-"):
            return osv_id.upper()
        if cve_id is not None:
            return cve_id
        if ghsa_alias is not None:
            return ghsa_alias
        return osv_id

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.osv_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit
