"""Reading files from the repository being scanned.

The tree under a scan directory is attacker-controlled. A symlink can point at
``/dev/zero`` or at a file outside the checkout, and a lockfile can be any size,
so nothing in it is read without checking what it is first.
"""
from __future__ import annotations

import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.parsers import expat

MAX_PARSED_FILE_BYTES = int(os.environ.get("HECATE_MAX_PARSED_FILE_BYTES", str(32 * 1024 * 1024)))


def _checked(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"Not a regular file: {path.name}")
    if info.st_size > MAX_PARSED_FILE_BYTES:
        raise OSError(f"File too large to parse: {path.name}")


def parse_xml_limited(path: Path) -> ET.ElementTree:
    """Parse a manifest such as ``pom.xml`` like ``ET.parse``, under the same rules.

    Raises ``OSError`` for anything a parser should skip: a symlink, an oversized
    file, or a DTD, which no manifest needs and which is how an entity bomb gets in.
    """
    _checked(path)
    data = path.read_bytes()

    def refuse(*_args: object) -> None:
        raise OSError(f"DTD in {path.name}")

    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from exc
    return ET.ElementTree(ET.fromstring(data))


def read_text_limited(path: Path) -> str:
    """Read a regular file of a bounded size, or raise ``OSError``.

    ``OSError`` is what every parser already treats as "skip this file".
    ``lstat`` on purpose: a symlink is refused rather than followed.
    """
    _checked(path)
    return path.read_text(errors="replace")
