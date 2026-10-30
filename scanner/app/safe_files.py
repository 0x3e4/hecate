"""Reading files from the repository being scanned.

The tree under a scan directory is attacker-controlled. A symlink can point at
``/dev/zero`` or at a file outside the checkout, and a lockfile can be any size,
so nothing in it is read without checking what it is first.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_PARSED_FILE_BYTES = int(os.environ.get("HECATE_MAX_PARSED_FILE_BYTES", str(32 * 1024 * 1024)))


def read_text_limited(path: Path) -> str:
    """Read a regular file of a bounded size, or raise ``OSError``.

    ``OSError`` is what every parser already treats as "skip this file".
    ``lstat`` on purpose: a symlink is refused rather than followed.
    """
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"Not a regular file: {path.name}")
    if info.st_size > MAX_PARSED_FILE_BYTES:
        raise OSError(f"File too large to parse: {path.name}")
    return path.read_text(errors="replace")
