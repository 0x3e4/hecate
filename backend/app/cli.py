from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

from app.services.ingestion.cpe_pipeline import CPEPipeline
from app.services.ingestion.pipeline import run_ingestion


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
        choices=["ingest", "sync-cpe"],
        help="Command to execute (ingest, sync-cpe).",
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
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        result = asyncio.run(run_ingestion(modified_since=args.since, limit=args.limit))
        print(f"Ingestion finished: {result}")
    elif args.command == "sync-cpe":
        if args.since:
            parser.error("The --since option is not supported for sync-cpe.")
        result = asyncio.run(run_cpe_sync_once(limit=args.limit))
        print(f"CPE sync finished: {result}")
    else:
        parser.error(f"Unsupported command: {args.command}")


async def run_cpe_sync_once(limit: int | None = None) -> dict[str, int]:
    pipeline = CPEPipeline()
    try:
        return await pipeline.sync(limit=limit)
    finally:
        await pipeline.close()


if __name__ == "__main__":
    main()
