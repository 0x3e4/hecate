"""Runs Hecate's own analyzers on one directory, in a process of their own.

They parse files from the repository being scanned. A hostile lockfile can pin a
CPU in a regex, which holds the GIL, or exhaust memory, and neither can be
cancelled from a thread. As a child process the work is killed on timeout and
takes nothing else down: ``/check``, ``/stats`` and other scans keep running.

Prints one JSON object on stdout. An analyzer that fails is reported in
``errors``; the other one still runs, so a file that breaks the SBOM parsers
cannot switch off malware detection.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

from app.hecate_analyzer import run_analysis
from app.malware_detector import run_detection


def analyze(source_dir: str) -> dict[str, Any]:
    result: dict[str, Any] = {"sbom": {}, "findings": [], "errors": []}
    try:
        result["sbom"] = run_analysis(source_dir)
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"SBOM analysis failed: {exc!r}")
    try:
        result["findings"] = run_detection(source_dir)
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"Malware detection failed: {exc!r}")
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.analyze_cli <source_dir>", file=sys.stderr)
        return 2
    # stdout carries the result, so anything logged has to stay off it.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    json.dump(analyze(argv[1]), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
