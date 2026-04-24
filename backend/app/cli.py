from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.services.ingestion.circl_pipeline import CirclPipeline
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.ghsa_pipeline import GhsaPipeline
from app.services.ingestion.osv_pipeline import OsvPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.ingestion.kev_pipeline import KevPipeline
from app.services.capec_service import get_capec_service
from app.services.cwe_service import get_cwe_service


def _parse_iso8601(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:  # noqa: TRY003 - providing CLI feedback
        raise argparse.ArgumentTypeError(f"Invalid ISO timestamp: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Hecate backend management CLI.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="ingest",
        choices=["ingest", "sync-euvd", "sync-cpe", "sync-nvd", "sync-kev", "sync-cwe", "sync-capec", "sync-circl", "sync-ghsa", "sync-osv", "enrich-mal", "purge-malware", "reindex-opensearch"],
        help="Command to execute (ingest, sync-euvd, sync-cpe, sync-nvd, sync-kev, sync-cwe, sync-capec, sync-circl, sync-ghsa, sync-osv, enrich-mal, purge-malware, reindex-opensearch).",
    )
    parser.add_argument(
        "--since",
        type=_parse_iso8601,
        help="ISO timestamp to fetch vulnerabilities modified since (e.g. 2024-01-01T00:00:00Z).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of vulnerabilities to ingest (useful for testing).",
    )
    parser.add_argument(
        "--initial",
        action="store_true",
        help="Force an initial/full sync (supported for ingest, sync-euvd, sync-cpe, sync-nvd, sync-cwe, and sync-capec).",
    )
    parser.add_argument(
        "--ecosystem",
        type=str,
        help="Ecosystem filter for purge-malware (e.g. 'vscode', 'npm'). Matches both MAL-* vulnerability docs and malware_intel entries.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually delete — just print counts.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        result = asyncio.run(
            run_ingestion(
                modified_since=args.since,
                limit=args.limit,
                initial_sync=args.initial,
            )
        )
        print(f"Ingestion finished: {result}")
    elif args.command == "sync-euvd":
        result = asyncio.run(
            run_ingestion(
                modified_since=args.since,
                limit=args.limit,
                initial_sync=args.initial,
            )
        )
        print(f"EUVD sync finished: {result}")
    elif args.command == "sync-cpe":
        if args.since:
            parser.error("The --since option is not supported for sync-cpe.")
        result = asyncio.run(run_cpe_sync_once(limit=args.limit, initial_sync=args.initial))
        print(f"CPE sync finished: {result}")
    elif args.command == "sync-nvd":
        if args.limit is not None:
            parser.error("The --limit option is not supported for sync-nvd.")
        if args.initial and args.since:
            parser.error("Use either --initial or --since for sync-nvd, not both.")
        result = asyncio.run(
            run_nvd_sync_once(
                initial_sync=args.initial,
                modified_since=args.since,
            )
        )
        print(f"NVD sync finished: {result}")
    elif args.command == "sync-kev":
        if args.limit is not None:
            parser.error("The --limit option is not supported for sync-kev.")
        if args.since:
            parser.error("The --since option is not supported for sync-kev.")
        result = asyncio.run(run_kev_sync_once(initial_sync=args.initial))
        print(f"KEV sync finished: {result}")
    elif args.command == "sync-cwe":
        if args.limit is not None:
            parser.error("The --limit option is not supported for sync-cwe.")
        if args.since:
            parser.error("The --since option is not supported for sync-cwe.")
        result = asyncio.run(run_cwe_sync_once(initial_sync=args.initial))
        print(f"CWE sync finished: {result}")
    elif args.command == "sync-capec":
        if args.limit is not None:
            parser.error("The --limit option is not supported for sync-capec.")
        if args.since:
            parser.error("The --since option is not supported for sync-capec.")
        result = asyncio.run(run_capec_sync_once(initial_sync=args.initial))
        print(f"CAPEC sync finished: {result}")
    elif args.command == "sync-circl":
        if args.since:
            parser.error("The --since option is not supported for sync-circl.")
        if args.initial:
            parser.error("The --initial option is not supported for sync-circl (enrichment only).")
        result = asyncio.run(run_circl_sync_once(limit=args.limit))
        print(f"CIRCL sync finished: {result}")
    elif args.command == "sync-ghsa":
        if args.since:
            parser.error("The --since option is not supported for sync-ghsa.")
        # For initial sync without explicit --limit, use 0 (no limit)
        effective_limit = args.limit if args.limit is not None else (0 if args.initial else None)
        result = asyncio.run(run_ghsa_sync_once(limit=effective_limit, initial_sync=args.initial))
        print(f"GHSA sync finished: {result}")
    elif args.command == "sync-osv":
        if args.since:
            parser.error("The --since option is not supported for sync-osv.")
        effective_limit = args.limit if args.limit is not None else (0 if args.initial else None)
        result = asyncio.run(run_osv_sync_once(limit=effective_limit, initial_sync=args.initial))
        print(f"OSV sync finished: {result}")
    elif args.command == "enrich-mal":
        if args.since:
            parser.error("The --since option is not supported for enrich-mal.")
        if args.initial:
            parser.error("The --initial option is not supported for enrich-mal.")
        result = asyncio.run(run_mal_enrichment_once(limit=args.limit))
        print(f"MAL enrichment finished: {result}")
    elif args.command == "purge-malware":
        if not args.ecosystem:
            parser.error("The --ecosystem argument is required for purge-malware.")
        if args.since or args.initial or args.limit:
            parser.error("purge-malware only accepts --ecosystem and --dry-run.")
        result = asyncio.run(
            run_malware_purge_once(ecosystem=args.ecosystem, dry_run=args.dry_run)
        )
        print(f"Malware purge finished: {result}")
    elif args.command == "reindex-opensearch":
        if args.limit is not None:
            parser.error("The --limit option is not supported for reindex-opensearch.")
        if args.since:
            parser.error("The --since option is not supported for reindex-opensearch.")
        result = asyncio.run(run_opensearch_reindex())
        print(f"OpenSearch reindex finished: {result}")
    else:
        parser.error(f"Unsupported command: {args.command}")


async def run_cpe_sync_once(limit: int | None = None, *, initial_sync: bool = False) -> dict[str, int]:
    pipeline = CPEPipeline()
    try:
        return await pipeline.sync(limit=limit, initial_sync=initial_sync)
    finally:
        await pipeline.close()


async def run_nvd_sync_once(
    *,
    initial_sync: bool = False,
    modified_since: datetime | None = None,
) -> dict[str, Any]:
    pipeline = NVDPipeline()
    return await pipeline.sync(initial_sync=initial_sync, modified_since=modified_since)


async def run_kev_sync_once(*, initial_sync: bool = False) -> dict[str, Any]:
    pipeline = KevPipeline()
    return await pipeline.sync(initial_sync=initial_sync)


async def run_circl_sync_once(limit: int | None = None) -> dict[str, int]:
    """Run CIRCL enrichment sync once from CLI."""
    pipeline = CirclPipeline()
    try:
        return await pipeline.sync(limit=limit)
    finally:
        await pipeline.close()


async def run_ghsa_sync_once(
    limit: int | None = None,
    *,
    initial_sync: bool = False,
) -> dict[str, int]:
    """Run GHSA sync once from CLI."""
    pipeline = GhsaPipeline()
    try:
        return await pipeline.sync(limit=limit, initial_sync=initial_sync)
    finally:
        await pipeline.close()


async def run_mal_enrichment_once(limit: int | None = None) -> dict[str, int]:
    """Backfill deps.dev version data onto existing MAL-* vulnerability docs.

    Walks the vulnerabilities collection for `_id` matching `^MAL-` that still
    carry broad `introduced: "0"` ranges and rewrites `impactedProducts` with
    actual published versions. Rate-limited by the deps.dev client. Meant to
    be run once after deploy (`--limit` optional to bound the API-call budget
    — default is no cap, runs until exhausted).

    Wrapped in `JobTracker` so the run surfaces in the audit log (`job:
    mal_enrichment_backfill`) and the System → Data → Sync Status view.
    """
    from app.db.mongo import get_database
    from app.repositories.ingestion_state_repository import IngestionStateRepository
    from app.services.ingestion.deps_dev_client import DepsDevClient
    from app.services.ingestion.job_tracker import JobTracker
    from app.services.ingestion.mal_enrichment import enrich_mal_document

    database = await get_database()
    collection = database[settings.mongo_vulnerabilities_collection]

    state_repo = await IngestionStateRepository.create()
    tracker = JobTracker(state_repo)
    ctx = await tracker.start(
        "mal_enrichment_backfill",
        limit=limit,
        label="MAL-* deps.dev Enrichment",
    )

    client = DepsDevClient()
    stats = {"scanned": 0, "patched": 0, "unchanged": 0, "failed": 0}
    try:
        cursor = collection.find({"_id": {"$regex": "^MAL-"}})
        if limit:
            cursor = cursor.limit(limit)
        async for doc in cursor:
            stats["scanned"] += 1
            try:
                patched = await enrich_mal_document(doc, client=client)
            except Exception as exc:  # noqa: BLE001
                stats["failed"] += 1
                print(f"  ! {doc.get('_id')}: {exc}", flush=True)
                continue
            if patched > 0:
                stats["patched"] += 1
                print(f"  + {doc.get('_id')}: patched {patched} product(s)", flush=True)
            else:
                stats["unchanged"] += 1
            if stats["scanned"] % 100 == 0:
                print(f"  … {stats['scanned']} scanned · {stats['patched']} patched", flush=True)
    except Exception as exc:
        await tracker.fail(ctx, str(exc))
        raise
    finally:
        await client.close()

    await tracker.finish(ctx, **stats)
    return stats


async def run_malware_purge_once(*, ecosystem: str, dry_run: bool = False) -> dict[str, int]:
    """Delete every malware entry for a given ecosystem.

    Targets two collections:
    - `malware_intel` — dynamic blocklist entries (exact ecosystem match).
    - `vulnerabilities` — MAL-* documents whose `impactedProducts[].vendor.name`
      matches the ecosystem (case-insensitive, with OSV naming variants like
      'VSCode' / 'VSCode:https://open-vsx.org' folded in).

    Intended for one-off cleanups when an ecosystem produces too many false
    positives or the user wants to re-evaluate. Reversible via the next
    scheduled OSV sync, which will re-ingest upstream records.
    """
    from app.db.mongo import get_database

    eco_lower = ecosystem.strip().lower()
    if not eco_lower:
        return {"intel_deleted": 0, "vuln_deleted": 0}

    # OSV stores `vendor.name` with upstream casing (e.g. "VSCode"). Build a
    # small set of variants so a single --ecosystem vscode catches all of them.
    variants = {eco_lower}
    if eco_lower == "vscode":
        variants.update({"vscode", "vscode:https://open-vsx.org"})
    # case-insensitive regex, anchored so 'npm' doesn't match 'nuget-npm'
    variant_regex = "|".join(f"^{_regex_escape(v)}$" for v in variants)

    database = await get_database()
    intel = database[settings.mongo_malware_intel_collection]
    vulns = database[settings.mongo_vulnerabilities_collection]

    intel_query = {"ecosystem": {"$in": list(variants)}}
    vuln_query = {
        "_id": {"$regex": "^MAL-"},
        "$or": [
            {"impactedProducts.vendor.name": {"$regex": variant_regex, "$options": "i"}},
            {"impacted_products.vendor.name": {"$regex": variant_regex, "$options": "i"}},
        ],
    }

    if dry_run:
        intel_n = await intel.count_documents(intel_query)
        vuln_n = await vulns.count_documents(vuln_query)
        print(f"  [dry-run] would delete {intel_n} malware_intel + {vuln_n} vulnerabilities rows")
        return {"intel_deleted": intel_n, "vuln_deleted": vuln_n}

    intel_result = await intel.delete_many(intel_query)
    vuln_result = await vulns.delete_many(vuln_query)
    return {
        "intel_deleted": intel_result.deleted_count,
        "vuln_deleted": vuln_result.deleted_count,
    }


def _regex_escape(s: str) -> str:
    import re
    return re.escape(s)


async def run_osv_sync_once(
    limit: int | None = None,
    *,
    initial_sync: bool = False,
) -> dict[str, int]:
    """Run OSV sync once from CLI."""
    pipeline = OsvPipeline()
    try:
        return await pipeline.sync(limit=limit, initial_sync=initial_sync)
    finally:
        await pipeline.close()


async def run_capec_sync_once(*, initial_sync: bool = False) -> dict[str, Any]:
    """Run CAPEC sync once from CLI."""
    capec_service = get_capec_service()
    try:
        capec_service.clear_cache()

        stats = await capec_service.sync_all_capecs()

        deleted = 0
        if stats["fetched"] > 0:
            deleted = await capec_service.clear_old_entries()
            print(f"Deleted {deleted} old CAPEC entries from MongoDB")
        else:
            print("Warning: No new CAPEC data fetched, skipping deletion of old entries")

        return {
            "fetched": stats["fetched"],
            "inserted": stats["inserted"],
            "updated": stats["updated"],
            "unchanged": stats["unchanged"],
            "failed": stats["failed"],
            "deleted_old": deleted,
        }
    finally:
        await capec_service.close()


async def run_cwe_sync_once(*, initial_sync: bool = False) -> dict[str, Any]:
    """Run CWE sync once from CLI."""
    cwe_service = get_cwe_service()
    try:
        # Clear in-memory cache
        cwe_service.clear_cache()

        # Sync ALL CWEs from MITRE API
        stats = await cwe_service.sync_all_cwes()

        # Only delete old entries if sync was successful (fetched > 0)
        deleted = 0
        if stats["fetched"] > 0:
            # Delete old MongoDB entries (older than 7 days)
            deleted = await cwe_service.clear_old_entries()
            print(f"Deleted {deleted} old CWE entries from MongoDB")
        else:
            print("Warning: No new CWE data fetched, skipping deletion of old entries")

        return {
            "fetched": stats["fetched"],
            "inserted": stats["inserted"],
            "updated": stats["updated"],
            "unchanged": stats["unchanged"],
            "failed": stats["failed"],
            "deleted_old": deleted,
        }
    finally:
        await cwe_service.close()


async def run_opensearch_reindex() -> dict[str, Any]:
    """Reindex all vulnerabilities from MongoDB to OpenSearch using bulk operations."""
    from app.repositories.vulnerability_repository import VulnerabilityRepository
    from app.repositories.ingestion_state_repository import IngestionStateRepository
    from app.models.vulnerability import VulnerabilityDocument
    from app.db.opensearch import get_client, ensure_vulnerability_index
    from app.core.config import settings
    from app.services.ingestion.job_tracker import JobTracker
    from opensearchpy.helpers import bulk
    import structlog

    log = structlog.get_logger()

    # Initialize job tracking
    state_repo = await IngestionStateRepository.create()
    tracker = JobTracker(state_repo)
    job_ctx = await tracker.start("Reindex OpenSearch")

    try:
        # Ensure index exists with proper mapping
        ensure_vulnerability_index(settings.opensearch_index)
        log.info("opensearch.reindex_started", index=settings.opensearch_index)

        repo = await VulnerabilityRepository.create()
        total = await repo.collection.count_documents({})
        log.info("opensearch.reindex_total", total=total)
        print(f"Reindexing {total} vulnerabilities to OpenSearch...")

        client = get_client()
        indexed = 0
        failed = 0
        bulk_batch: list[dict[str, Any]] = []
        bulk_size = 500

        async for doc in repo.collection.find({}).batch_size(bulk_size):
            try:
                # Remove MongoDB internal fields
                doc.pop("_id", None)
                doc.pop("change_history", None)

                # Validate and convert to VulnerabilityDocument
                vuln = VulnerabilityDocument.model_validate(doc)
                os_doc = vuln.opensearch_document()
                os_doc["_index"] = settings.opensearch_index
                os_doc["_id"] = vuln.vuln_id
                bulk_batch.append(os_doc)

            except Exception as exc:
                failed += 1
                vuln_id = doc.get("vuln_id", "unknown")
                if failed <= 10:
                    print(f"Failed to prepare {vuln_id}: {str(exc)[:100]}")

            if len(bulk_batch) >= bulk_size:
                try:
                    success, errors = bulk(client, bulk_batch, raise_on_error=False, refresh=False)
                    indexed += success
                    if errors:
                        failed += len(errors)
                except Exception as exc:
                    log.warning("opensearch.bulk_failed", error=str(exc))
                    failed += len(bulk_batch)
                bulk_batch = []

                progress_pct = (indexed / total * 100) if total > 0 else 0
                print(f"Progress: {indexed}/{total} ({progress_pct:.1f}%) - failed: {failed}")

        # Flush remaining batch
        if bulk_batch:
            try:
                success, errors = bulk(client, bulk_batch, raise_on_error=False, refresh=False)
                indexed += success
                if errors:
                    failed += len(errors)
            except Exception as exc:
                log.warning("opensearch.bulk_failed", error=str(exc))
                failed += len(bulk_batch)

        # Refresh the index once at the end
        try:
            client.indices.refresh(index=settings.opensearch_index)
        except Exception:
            pass

        log.info("opensearch.reindex_completed", indexed=indexed, failed=failed, total=total)
        print(f"\nReindex complete: {indexed} indexed, {failed} failed out of {total} total")

        result = {
            "indexed": indexed,
            "failed": failed,
            "total": total,
        }

        # Mark job as successful
        await tracker.finish(job_ctx, **result)
        return result

    except Exception as exc:
        # Mark job as failed
        await tracker.fail(job_ctx, error=str(exc))
        raise


if __name__ == "__main__":
    main()
