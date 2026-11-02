"""In-memory per-client throttle + lockout for the shared-secret auth endpoints.

The ``SYSTEM_PASSWORD`` / ``AI_ANALYSIS_PASSWORD`` probe endpoints
(``POST /status/system-auth``, ``/status/ai-auth``) and the write gates return a
fast boolean, so a weak secret could otherwise be brute-forced online at full
request rate. This adds a sliding-window failure counter per (secret, client): N
failures inside the window trigger a lockout window during which further
attempts get 429 without ever touching the secret comparison. A success clears
the counter.

The counter belongs to the secret, not to the route. The system password is
compared on the unlock endpoint, the write gate and every target route; with a
counter per route, one client got ten guesses on each.

In-memory and single-process — consistent with the app's other in-memory state
(EventBus, caches, scheduler). Pair with TLS + network ACLs as documented in
docs/security-access-control.md; this is defence in depth, not user auth.
"""
from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.utils.request import get_security_client_ip

# Defaults chosen to be invisible to a legitimate operator (who fat-fingers a
# password a couple of times) but to cap an attacker at ~10 tries/minute.
_MAX_ATTEMPTS = 10
_WINDOW_SECONDS = 60.0
_LOCKOUT_SECONDS = 300.0
# Every distinct client adds an entry; past this many, entries with no recent
# failure and no running lockout are dropped.
_MAX_TRACKED_CLIENTS = 10_000

SYSTEM_SECRET = "secret:system"
AI_SECRET = "secret:ai"
API_KEY_SECRET = "secret:api-key"


class AuthThrottle:
    def __init__(
        self,
        *,
        max_attempts: int = _MAX_ATTEMPTS,
        window_seconds: float = _WINDOW_SECONDS,
        lockout_seconds: float = _LOCKOUT_SECONDS,
        max_tracked: int = _MAX_TRACKED_CLIENTS,
    ) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._max_tracked = max_tracked
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
        if len(self._fails) + len(self._locked_until) > self._max_tracked:
            self._prune(now)

    def _prune(self, now: float) -> None:
        """Forget clients whose failures have aged out and who are not locked."""
        for key in [k for k, until in self._locked_until.items() if until <= now]:
            self._locked_until.pop(key, None)
        for key in [k for k, attempts in self._fails.items() if not attempts or now - attempts[-1] > self._window]:
            if key not in self._locked_until:
                self._fails.pop(key, None)

    def record_success(self, key: str) -> None:
        self._fails.pop(key, None)
        self._locked_until.pop(key, None)


_throttle = AuthThrottle()


def _client_ip(request: Request) -> str:
    """Client IP used as the per-client throttle key.

    Uses :func:`get_security_client_ip` so a client cannot rotate the lockout
    key (and thereby bypass the brute-force limit) by spoofing
    ``X-Forwarded-For``: the forwarded header is only trusted when the direct
    peer is a configured trusted proxy, and then the proxy-observed (right-most)
    hop is used. Falls back to ``"unknown"`` when no peer is available."""
    return client_key(get_security_client_ip(request) or "unknown")


def client_key(ip: str) -> str:
    """An IPv6 client is its /64: one host usually holds the whole prefix, and
    counting single addresses let it take a fresh one for every batch of guesses."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(ipaddress.ip_network(f"{address}/64", strict=False))


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
