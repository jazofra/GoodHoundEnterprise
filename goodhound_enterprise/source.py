"""High-level graph questions answered with small, Hunter-compliant Cypher queries."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from typing import Any

from . import cypher
from .backends.base import CypherExecutor, QueryError, RateLimiter
from .config import Settings
from .graph import AttackPath, Graph, Node, best_path, parse_graph

log = logging.getLogger(__name__)


class CypherGraphSource:
    def __init__(self, executor: CypherExecutor, settings: Settings, *, retries: int = 3) -> None:
        self.executor = executor
        self.settings = settings
        self.retries = retries
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._limiter = RateLimiter(settings.rate_limit)
        self.queries_sent = 0

    async def query(self, query: str) -> Graph:
        cypher.assert_hunter_safe(query, self.settings.max_hops)
        async with self._sem:
            for attempt in range(1, self.retries + 1):
                await self._limiter.wait()
                self.queries_sent += 1
                try:
                    raw: Any = await self.executor.run(query)
                    return parse_graph(raw, self.settings.target_label)
                except QueryError:
                    raise
                except Exception as exc:  # transport hiccup, 429, timeout...
                    if attempt == self.retries:
                        raise
                    backoff = 2**attempt
                    log.warning("Query failed (%s); retrying in %ss", exc, backoff)
                    await asyncio.sleep(backoff)
        raise AssertionError("unreachable")

    async def scalar(self, query: str, key: str) -> int:
        graph = await self.query(query)
        value = graph.literal(key)
        if value is None:
            # BHE answers 404 / empty for "no rows"; a count of nothing is 0.
            return 0
        if isinstance(value, list) and value:
            value = value[0]
        return int(value)

    # ------------------------------------------------------------------

    async def count_enabled_users(self) -> int:
        return await self.scalar(cypher.count_enabled_users(self.settings), "total")

    async def domains(self) -> list[Node]:
        graph = await self.query(cypher.list_domains())
        return sorted(graph.nodes.values(), key=lambda n: n.name)

    async def iter_start_pages(self, start_label: str) -> AsyncIterator[list[Node]]:
        after: str | None = None
        while True:
            graph = await self.query(cypher.list_start_nodes(self.settings, start_label, after))
            page = sorted(
                (n for n in graph.nodes.values() if n.objectid and not n.tier_zero),
                key=lambda n: n.objectid,
            )
            if not page:
                return
            yield page
            if len(graph.nodes) < self.settings.page_size:
                return
            after = page[-1].objectid

    async def shortest_path(self, start: Node, start_label: str, max_hops: int | None = None) -> AttackPath | None:
        query = cypher.shortest_paths_from(self.settings, start_label, start.objectid, max_hops)
        graph = await self.query(query)
        return best_path(graph, start.objectid, self.settings.cost, allowed_edges=self.settings.traversable_edges)

    async def first_hops(self, user: Node) -> list[tuple[str, Node]]:
        graph = await self.query(cypher.first_hops(self.settings, user.objectid))
        start = graph.by_objectid(user.objectid)
        if start is None:
            return []
        return sorted(
            ((e.kind, graph.nodes[e.target]) for e in graph.edges if e.source == start.id and e.target in graph.nodes),
            key=lambda kv: (kv[0], kv[1].objectid),
        )

    async def member_count(self, group: Node) -> int:
        return await self.scalar(cypher.member_count(self.settings, group.objectid), "members")

    async def unique_members(self, group_objectids: Sequence[str]) -> int | None:
        """Distinct enabled non-Tier Zero users in any of the groups (None if it cannot be computed)."""
        if not group_objectids:
            return 0
        try:
            return await self.scalar(cypher.unique_members(self.settings, group_objectids), "users")
        except QueryError as exc:
            log.warning("Could not compute distinct users across groups: %s", exc)
            return None
