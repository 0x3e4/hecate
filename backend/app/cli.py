from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

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
        help="Command to execute (only 'ingest' supported).",
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

    if args.command != "ingest":
        parser.error("Only the 'ingest' command is currently supported.")

    result = asyncio.run(run_ingestion(modified_since=args.since, limit=args.limit))
    print(f"Ingestion finished: {result}")


if __name__ == "__main__":
    main()
