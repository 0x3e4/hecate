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


# Hard cap on a user-supplied free-text substring search. Bounds the work any
# single scan can do and keeps a pathological input cheap.
MAX_SEARCH_TERM_LENGTH = 200


def contains_regex(
    value: str, *, options: str = "i", max_length: int = MAX_SEARCH_TERM_LENGTH
) -> dict[str, str]:
    """Build a MongoDB ``$regex`` clause matching *value* as a LITERAL substring.

    ``re.escape`` neutralises every regex metacharacter so the compiled pattern
    can only ever be a literal — removing the ReDoS / regex-injection class at
    the unauthenticated search endpoints that feed user input into ``$regex`` —
    and ``max_length`` bounds the literal. Use this instead of
    ``{"$regex": user_value, "$options": "i"}``.
    """
    literal = re.escape((value or "")[:max_length])
    return {"$regex": literal, "$options": options}


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
