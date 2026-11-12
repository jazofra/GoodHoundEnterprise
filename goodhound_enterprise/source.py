"""High-level graph questions answered with small, Hunter-compliant Cypher queries."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from typing import Any

from . import cypher
from .backends.base import CypherExecutor, QueryError, RateLimiter, RetryableQueryError
from .checkpoint import Checkpoint
from .config import HUNTER_MAX_LIMIT, OPENGRAPH_EDGE_PROBABILITY, Settings
from .graph import Edge, Graph, Node, parse_graph, reaches_path_limit
from .risk import cyberark_platform_key

log = logging.getLogger(__name__)


class CypherGraphSource:
    def __init__(
        self,
        executor: CypherExecutor,
        settings: Settings,
        *,
        retries: int = 3,
        checkpoint: Checkpoint | None = None,
    ) -> None:
        self.executor = executor
        self.settings = settings
        self.retries = retries
        #: Answers of an interrupted run (see checkpoint.py). Set to None for live-only queries.
        self.checkpoint = checkpoint
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._limiter = RateLimiter(settings.rate_limit)
        self.queries_sent = 0
        self._all_shortest_unsupported = False
        self.single_path_fallbacks: list[str] = []
        #: Start nodes whose result may have been cut off at Hunter's row limit.
        self.possibly_truncated: list[str] = []

    async def throttle(self) -> None:
        """Wait for a slot under the shared rate limit (for calls that do not go through ``query``)."""
        await self._limiter.wait()

    async def query(self, query: str, *, retries: int | None = None) -> Graph:
        retries = retries or self.retries
        cypher.assert_hunter_safe(query, self.settings.max_hops)
        if self.checkpoint is not None:
            stored = self.checkpoint.get(query)
            if stored is not Checkpoint.MISSING:
                return parse_graph(stored, self.settings.target_label, self.settings.target_objectid)
        for attempt in range(1, retries + 1):
            async with self._sem:
                await self._limiter.wait()
                self.queries_sent += 1
                try:
                    raw: Any = await self.executor.run(query)
                except RetryableQueryError as exc:
                    if attempt == retries:
                        raise
                    problem = str(exc)[:200]
                except QueryError:
                    raise
                except Exception as exc:  # transport hiccup, 429, timeout...
                    if attempt == retries:
                        raise
                    problem = str(exc)[:200]
                else:
                    graph = parse_graph(raw, self.settings.target_label, self.settings.target_objectid)
                    if self.checkpoint is not None:
                        self.checkpoint.put(query, raw)
                    return graph
            # Back off outside the semaphore: a waiting retry must not hold up other queries.
            backoff = 2**attempt
            log.warning("Query failed (%s); retrying in %ss", problem, backoff)
            await asyncio.sleep(backoff)
        raise AssertionError("unreachable")

    async def scalar(self, query: str, key: str) -> int:
        graph = await self.query(query)
        value = graph.literal(key)
        if isinstance(value, list) and value:
            value = value[0]
        # count() always returns a row, so a missing value means the result was not understood.
        # Treating it as 0 would silently produce wrong percentages and risk scores.
        try:
            return int(value)
        except (TypeError, ValueError):
            raise QueryError(f"Expected a number named {key!r} but got {graph.literals!r}\nQuery: {query}") from None

    # ------------------------------------------------------------------

    async def count_enabled_users(self) -> int:
        return await self.scalar(cypher.count_enabled_users(self.settings), "total")

    async def enable_opengraph(self) -> dict[str, list[str]]:
        """Add the traversable relationship kinds of the configured OpenGraph extensions.

        Hunter's capability catalog is authoritative (it also knows kinds this tool has
        no defaults for). Other backends fall back to the built-in tables. Unknown kinds
        must never reach a query: Hunter rejects the whole query.
        """
        prefixes = [p.rstrip("_") for p in self.settings.opengraph if p]
        if not prefixes:
            return {}
        catalog_fn = getattr(self.executor, "relationship_catalog", None)
        catalog = await catalog_fn() if catalog_fn else None
        if catalog is None:
            catalog = {k: True for k in OPENGRAPH_EDGE_PROBABILITY}
        enabled: dict[str, list[str]] = {}
        for prefix in prefixes:
            kinds = sorted(k for k, traversable in catalog.items() if traversable and k.startswith(f"{prefix}_"))
            if not kinds:
                log.warning("No traversable %s_* relationship kinds on this tenant; ignoring it", prefix)
                continue
            enabled[prefix] = self.settings.add_edges(kinds)
        return enabled

    async def dual_control_platforms(self) -> set[tuple[str, str]]:
        """(platformId, instance) of CyberArk platforms that require dual-control approval."""
        found: set[tuple[str, str]] = set()
        after: str | None = None
        while True:
            graph = await self.query(cypher.list_nodes("CyberArk_Platform", after))
            page = sorted((n for n in graph.nodes.values() if n.objectid), key=lambda n: n.objectid)
            for node in page:
                if node.properties.get("requireDualControlPasswordAccessApproval") is True:
                    key = cyberark_platform_key(node.properties.get("platformId"), node.objectid)
                    if key:
                        found.add(key)
            if len(graph.nodes) < HUNTER_MAX_LIMIT or not page:
                return found
            after = page[-1].objectid

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

    async def shortest_paths(self, start: Node, start_label: str, max_hops: int | None = None) -> Graph:
        """Union of the shortest paths from ``start`` to the reachable Tier Zero nodes.

        Prefers ``allShortestPaths`` (every equally short alternative, which the reach
        probability needs) and falls back to ``shortestPath`` (one path per target): for good
        if the backend rejects it, or for this start node only if it times out.
        """
        if self.settings.all_shortest_paths and not self._all_shortest_unsupported:
            query = cypher.all_shortest_paths_from(self.settings, start_label, start.objectid, max_hops)
            try:
                # A timed-out allShortestPaths rarely succeeds on retry; shortestPath is cheaper.
                graph = await self.query(query, retries=1)
                if reaches_path_limit(graph, start.objectid, self.settings.paths_per_start):
                    self.possibly_truncated.append(start.objectid)
                return graph
            except RetryableQueryError as exc:
                self._single_path_fallback(start, exc)
            except QueryError as exc:
                self._all_shortest_unsupported = True
                log.warning("allShortestPaths rejected (%s); falling back to shortestPath", str(exc)[:200])
            except Exception as exc:  # client-side timeout or transport error
                self._single_path_fallback(start, exc)
        graph = await self.query(cypher.shortest_paths_from(self.settings, start_label, start.objectid, max_hops))
        if reaches_path_limit(graph, start.objectid, self.settings.paths_per_start):
            self.possibly_truncated.append(start.objectid)
        return graph

    def _single_path_fallback(self, start: Node, exc: BaseException) -> None:
        self.single_path_fallbacks.append(start.objectid)
        log.warning(
            "allShortestPaths failed for %s (%s); using shortestPath for this start node",
            start.name or start.objectid,
            str(exc)[:120],
        )

    async def first_hops(self, user: Node) -> list[tuple[Edge, Node]]:
        graph = await self.query(cypher.first_hops(self.settings, user.objectid))
        start = graph.by_objectid(user.objectid)
        if start is None:
            return []
        hops = sorted(
            ((e, graph.nodes[e.target]) for e in graph.edges if e.source == start.id and e.target in graph.nodes),
            key=lambda kv: (kv[0].kind, kv[1].objectid),
        )
        if len(hops) >= HUNTER_MAX_LIMIT:  # one row per relationship: the rest was cut off
            self.possibly_truncated.append(user.objectid)
        return hops

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
