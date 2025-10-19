from __future__ import annotations

import hashlib
import re
from typing import Iterable

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, *, max_length: int = 120) -> str:
    normalized = _SLUG_RE.sub("-", value.lower()).strip("-")
    if not normalized:
        normalized = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return normalized[:max_length]


def normalize_key(value: str) -> str:
    return _TOKEN_RE.sub("", value.lower())


def build_search_tokens(parts: Iterable[str]) -> list[str]:
    tokens: set[str] = set()
    for part in parts:
        if not part:
            continue
        cleaned = _TOKEN_RE.sub(" ", part.lower())
        for token in cleaned.split():
            if token:
                tokens.add(token)
    return sorted(tokens)
