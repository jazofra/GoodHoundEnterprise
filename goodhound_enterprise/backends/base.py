from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol


class QueryError(RuntimeError):
    """The backend rejected or failed a query (not retried)."""


class RetryableQueryError(QueryError):
    """The backend failed a query but says a retry may succeed (e.g. Hunter's ``query_timed_out``)."""


class CypherExecutor(Protocol):
    """Runs one read-only Cypher query and returns the raw (JSON-like) result."""

    name: str

    async def run(self, query: str) -> Any: ...

    async def aclose(self) -> None: ...


class RateLimiter:
    """Spaces request starts at least ``1/rate`` seconds apart."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)
