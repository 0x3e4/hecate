"""Input sanitization and rate limiting for MCP tool handlers."""

from __future__ import annotations

import re
import time

import structlog

log = structlog.get_logger()

# Characters that have special meaning in Lucene / OpenSearch query_string syntax.
# Stripping them prevents injection when user input is used as a search_term
# (which flows into multi_match, not query_string, but we sanitise defensively).
_LUCENE_SPECIAL = re.compile(r'[{}\[\]\\^~!:"/()]')


def sanitize_search_input(text: str) -> str:
    """Strip Lucene/OpenSearch query syntax operators from free-text input."""
    cleaned = _LUCENE_SPECIAL.sub(" ", text)
    # Collapse whitespace
    return " ".join(cleaned.split()).strip()


class _TokenBucket:
    """Simple token bucket for rate limiting."""

    __slots__ = ("_capacity", "_tokens", "_last_refill", "_refill_rate")

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._refill_rate = capacity / 60.0  # tokens per second

    def try_consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Per-client token bucket rate limiter."""

    def __init__(self, max_per_minute: int) -> None:
        self._max_per_minute = max_per_minute
        self._buckets: dict[str, _TokenBucket] = {}
        self._last_eviction = time.monotonic()

    def check(self, client_id: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        self._maybe_evict()
        bucket = self._buckets.get(client_id)
        if bucket is None:
            bucket = _TokenBucket(self._max_per_minute)
            self._buckets[client_id] = bucket
        return bucket.try_consume()

    def _maybe_evict(self) -> None:
        """Remove stale buckets every 10 minutes to prevent memory growth."""
        now = time.monotonic()
        if now - self._last_eviction < 600:
            return
        self._last_eviction = now
        stale = [
            cid
            for cid, bucket in self._buckets.items()
            if now - bucket._last_refill > 600
        ]
        for cid in stale:
            del self._buckets[cid]
        if stale:
            log.debug("mcp.rate_limiter.evicted_stale_buckets", count=len(stale))
