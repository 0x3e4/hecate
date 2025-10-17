from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator


class AsyncRateLimiter:
    """
    Ensures a minimum interval between acquired slots.
    Useful for APIs that enforce a maximum requests per second.
    """

    def __init__(self, min_interval_seconds: float) -> None:
        self._min_interval = max(min_interval_seconds, 0.0)
        self._lock = asyncio.Lock()
        self._last_acquired: float = 0.0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_acquired
            remaining = self._min_interval - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)

            self._last_acquired = time.monotonic()

        try:
            yield
        finally:
            # nothing to cleanup post-request; future slots use updated timestamp
            pass
