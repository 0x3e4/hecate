"""In-memory per-client throttle + lockout for the shared-secret auth endpoints.

The ``SYSTEM_PASSWORD`` / ``AI_ANALYSIS_PASSWORD`` probe endpoints
(``POST /status/system-auth``, ``/status/ai-auth``) and the write gates return a
fast boolean, so a weak secret could otherwise be brute-forced online at full
request rate. This adds a sliding-window failure counter per (scope, client): N
failures inside the window trigger a lockout window during which further
attempts get 429 without ever touching the secret comparison. A success clears
the counter.

In-memory and single-process — consistent with the app's other in-memory state
(EventBus, caches, scheduler). Pair with TLS + network ACLs as documented in
docs/security-access-control.md; this is defence in depth, not user auth.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

# Defaults chosen to be invisible to a legitimate operator (who fat-fingers a
# password a couple of times) but to cap an attacker at ~10 tries/minute.
_MAX_ATTEMPTS = 10
_WINDOW_SECONDS = 60.0
_LOCKOUT_SECONDS = 300.0


class AuthThrottle:
    def __init__(
        self,
        *,
        max_attempts: int = _MAX_ATTEMPTS,
        window_seconds: float = _WINDOW_SECONDS,
        lockout_seconds: float = _LOCKOUT_SECONDS,
    ) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    def remaining_lockout(self, key: str) -> float | None:
        """Return remaining lockout seconds if *key* is locked, else ``None``."""
        until = self._locked_until.get(key)
        if until is None:
            return None
        remaining = until - self._now()
        if remaining > 0:
            return remaining
        # Lockout elapsed — reset so the client gets a fresh window.
        self._locked_until.pop(key, None)
        self._fails.pop(key, None)
        return None

    def record_failure(self, key: str) -> None:
        now = self._now()
        attempts = self._fails[key]
        attempts.append(now)
        while attempts and now - attempts[0] > self._window:
            attempts.popleft()
        if len(attempts) >= self._max:
            self._locked_until[key] = now + self._lockout
            attempts.clear()

    def record_success(self, key: str) -> None:
        self._fails.pop(key, None)
        self._locked_until.pop(key, None)


_throttle = AuthThrottle()


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Honours the left-most X-Forwarded-For hop when a
    reverse proxy sets it, else the direct peer. Best-effort by design — the
    throttle is defence in depth, not an authorization boundary."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def enforce_auth_throttle(request: Request, scope: str) -> str:
    """Raise 429 if the (scope, client) is locked out; otherwise return the key
    the caller passes to :func:`record_auth_result`."""
    key = f"{scope}:{_client_ip(request)}"
    remaining = _throttle.remaining_lockout(key)
    if remaining is not None:
        retry_after = int(remaining) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    return key


def record_auth_result(key: str, ok: bool) -> None:
    if ok:
        _throttle.record_success(key)
    else:
        _throttle.record_failure(key)
