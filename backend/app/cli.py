from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
from typing import Any

from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.euvd_pipeline import run_ingestion
from app.services.ingestion.nvd_pipeline import NVDPipeline
from app.services.ingestion.kev_pipeline import KevPipeline


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
        choices=["ingest", "sync-euvd", "sync-cpe", "sync-nvd", "sync-kev"],
        help="Command to execute (ingest, sync-euvd, sync-cpe, sync-nvd, sync-kev).",
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
        help="Force an initial/full sync (supported for ingest, sync-euvd, sync-cpe, and sync-nvd).",
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


if __name__ == "__main__":
    main()
