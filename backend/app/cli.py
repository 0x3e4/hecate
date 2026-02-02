from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
from typing import Any

from app.services.ingestion.circl_pipeline import CirclPipeline
from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.ingestion.kev_pipeline import KevPipeline
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
        choices=["ingest", "sync-euvd", "sync-cpe", "sync-nvd", "sync-kev", "sync-cwe", "sync-circl", "reindex-opensearch"],
        help="Command to execute (ingest, sync-euvd, sync-cpe, sync-nvd, sync-kev, sync-cwe, sync-circl, reindex-opensearch).",
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
        help="Force an initial/full sync (supported for ingest, sync-euvd, sync-cpe, sync-nvd, and sync-cwe).",
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
    elif args.command == "sync-circl":
        if args.since:
            parser.error("The --since option is not supported for sync-circl.")
        if args.initial:
            parser.error("The --initial option is not supported for sync-circl (enrichment only).")
        result = asyncio.run(run_circl_sync_once(limit=args.limit))
        print(f"CIRCL sync finished: {result}")
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
    """Reindex all vulnerabilities from MongoDB to OpenSearch."""
    from app.repositories.vulnerability_repository import VulnerabilityRepository
    from app.repositories.ingestion_state_repository import IngestionStateRepository
    from app.models.vulnerability import VulnerabilityDocument
    from app.db.opensearch import async_index_document, ensure_vulnerability_index
    from app.core.config import settings
    from app.services.ingestion.job_tracker import JobTracker
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

        indexed = 0
        failed = 0
        batch_size = 100

        async for doc in repo.collection.find({}).batch_size(batch_size):
            try:
                # Remove MongoDB internal fields
                doc.pop("_id", None)
                doc.pop("change_history", None)

                # Validate and convert to VulnerabilityDocument
                vuln = VulnerabilityDocument.model_validate(doc)

                # Index to OpenSearch with all enriched fields
                await async_index_document(
                    index=settings.opensearch_index,
                    document_id=vuln.vuln_id,
                    document=vuln.opensearch_document(),
                )
                indexed += 1

                if indexed % 100 == 0:
                    progress_pct = (indexed / total * 100) if total > 0 else 0
                    print(f"Progress: {indexed}/{total} ({progress_pct:.1f}%) - failed: {failed}")
                    log.info("opensearch.reindex_progress", indexed=indexed, total=total, failed=failed)

            except Exception as exc:
                failed += 1
                vuln_id = doc.get("vuln_id", "unknown")
                log.warning("opensearch.reindex_failed", vuln_id=vuln_id, error=str(exc))
                if failed <= 10:  # Only print first 10 errors
                    print(f"Failed to index {vuln_id}: {str(exc)[:100]}")

        log.info("opensearch.reindex_completed", indexed=indexed, failed=failed, total=total)
        print(f"\nReindex complete: {indexed} indexed, {failed} failed out of {total} total")

        result = {
            "indexed": indexed,
            "failed": failed,
            "total": total,
        }

        # Mark job as successful
        await tracker.succeed(job_ctx, result=result)
        return result

    except Exception as exc:
        # Mark job as failed
        await tracker.fail(job_ctx, error=str(exc))
        raise


if __name__ == "__main__":
    main()
