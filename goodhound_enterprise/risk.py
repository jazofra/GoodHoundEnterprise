"""Probabilistic attack-path risk.

Every relationship gets a success probability (``Settings.probability``). From
there:

* **Path probability** = product of its hops' probabilities. Hops therefore
  matter: every attacker action multiplies the chance of success by something
  below 1, while structural hops (``MemberOf``, ``Contains``) cost nothing.
* **Reach probability** of a start node = chance that *at least one* of the
  visible attack paths works, treating each relationship as an independent
  coin flip. Alternative paths raise it; a choke point shared by every path
  caps it. It is computed exactly (inclusion-exclusion over the paths) when
  there are few paths, and with a seeded Monte Carlo estimate otherwise.
* **Exposure** = expected share of the enabled non-Tier Zero users whose
  compromise leads to Tier Zero. Each user counts once, at the best reach
  probability among the start groups they belong to, using distinct-user
  counts from BloodHound (no double counting of nested or overlapping groups).

Only relationships the backend returned are visible: Hunter returns shortest
paths (at most 10 hops), so longer alternatives are not counted and reach
probabilities are lower bounds in that sense.
"""

from __future__ import annotations

import heapq
import math
import random
import zlib
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from .config import Settings
from .graph import AttackPath, Edge, Graph, Hop, Node

EdgeKey = tuple[str, str, str]  # (source objectid, kind, target objectid)


@dataclass(frozen=True)
class GEdge:
    src: str  # objectid
    dst: str  # objectid
    kind: str
    p: float
    cost: int
    last_seen: str | None = None

    @property
    def key(self) -> EdgeKey:
        return (self.src, self.kind, self.dst)


@dataclass(frozen=True)
class Reach:
    probability: float
    paths: int  # distinct simple paths seen (capped at exact_path_limit + 1)
    exact: bool


class AttackGraph:
    """Attack paths visible from one start node, keyed by objectid, with per-edge probabilities."""

    def __init__(self, start: Node, nodes: Mapping[str, Node], edges: Iterable[GEdge]) -> None:
        self.start = start
        self.nodes = dict(nodes)
        self.edges = list(edges)
        self.out: dict[str, list[int]] = {}
        for i, e in enumerate(self.edges):
            self.out.setdefault(e.src, []).append(i)
        for ids in self.out.values():
            ids.sort(key=lambda i: (self.edges[i].dst, self.edges[i].kind))
        self.terminals = {oid for oid, n in self.nodes.items() if n.tier_zero and oid != start.objectid}
        self._paths: list[int] | None = None  # bitmasks over edge indices
        self._paths_overflow = False

    # ------------------------------------------------------------------ construction

    @classmethod
    def from_edges(cls, start: Node, nodes: Mapping[str, Node], edges: Iterable[GEdge]) -> AttackGraph | None:
        """Keep only edges on some route from ``start`` to a Tier Zero node (Tier Zero is terminal)."""
        if start.tier_zero:
            return None
        unique: dict[EdgeKey, GEdge] = {}
        for e in edges:
            if e.p > 0 and e.src in nodes and e.dst in nodes:
                unique.setdefault(e.key, e)
        out: dict[str, list[GEdge]] = {}
        for e in unique.values():
            out.setdefault(e.src, []).append(e)
        reached, stack, kept = {start.objectid}, [start.objectid], []
        while stack:
            oid = stack.pop()
            if oid != start.objectid and nodes[oid].tier_zero:
                continue
            for e in out.get(oid, ()):
                kept.append(e)
                if e.dst not in reached:
                    reached.add(e.dst)
                    stack.append(e.dst)
        incoming: dict[str, list[GEdge]] = {}
        for e in kept:
            incoming.setdefault(e.dst, []).append(e)
        useful = {oid for oid in reached if oid != start.objectid and nodes[oid].tier_zero}
        if not useful:
            return None
        stack = list(useful)
        while stack:
            for e in incoming.get(stack.pop(), ()):
                if e.src not in useful:
                    useful.add(e.src)
                    stack.append(e.src)
        edges_kept = [e for e in kept if e.src in useful and e.dst in useful]
        return cls(start, {oid: nodes[oid] for oid in useful}, edges_kept)

    @classmethod
    def from_graph(
        cls,
        graph: Graph,
        start_objectid: str,
        prob: Callable[[Edge, Node], float],
        cost: Callable[[str, str], int],
        allowed: Iterable[str],
    ) -> AttackGraph | None:
        start = graph.by_objectid(start_objectid)
        if start is None:
            return None
        allowed_set = set(allowed)
        nodes = {n.objectid: n for n in graph.nodes.values() if n.objectid}
        edges = []
        for e in graph.edges:
            src, dst = graph.nodes.get(e.source), graph.nodes.get(e.target)
            if src is None or dst is None or not src.objectid or not dst.objectid or e.kind not in allowed_set:
                continue
            edges.append(GEdge(src.objectid, dst.objectid, e.kind, prob(e, dst), cost(e.kind, dst.kind), e.last_seen))
        return cls.from_edges(start, nodes, edges)

    def sub(self, objectid: str) -> AttackGraph | None:
        node = self.nodes.get(objectid)
        return None if node is None else AttackGraph.from_edges(node, self.nodes, self.edges)

    @property
    def keys(self) -> set[EdgeKey]:
        return {e.key for e in self.edges}

    # ------------------------------------------------------------------ paths

    def best_path(self, objective: str = "probability") -> AttackPath:
        """Most likely path ("probability") or GoodHound's fewest hops then lowest cost ("hops")."""

        def weight(nlp: float, hops: int, cost: int) -> tuple:
            return (round(nlp, 12), hops, cost) if objective == "probability" else (hops, cost, round(nlp, 12))

        start = self.start.objectid
        best: dict[str, tuple] = {start: weight(0.0, 0, 0)}
        parent: dict[str, int] = {}
        heap: list[tuple] = [(*best[start], start, 0.0, 0, 0)]
        while heap:
            *w, oid, nlp, hops, cost = heapq.heappop(heap)
            if tuple(w) != best.get(oid):
                continue
            if oid in self.terminals:
                return self._rebuild(oid, parent)
            for i in self.out.get(oid, ()):
                e = self.edges[i]
                cand = (nlp - math.log(e.p), hops + 1, cost + e.cost)
                cw = weight(*cand)
                if e.dst not in best or cw < best[e.dst]:
                    best[e.dst] = cw
                    parent[e.dst] = i
                    heapq.heappush(heap, (*cw, e.dst, *cand))
        raise ValueError("attack graph has no path to Tier Zero")  # from_edges guarantees one

    def _rebuild(self, end: str, parent: dict[str, int]) -> AttackPath:
        hops: list[Hop] = []
        cost, oid = 0, end
        while oid != self.start.objectid:
            e = self.edges[parent[oid]]
            hops.append(Hop(self.nodes[e.src], e.kind, self.nodes[e.dst], e.p, e.last_seen))
            cost += e.cost
            oid = e.src
        hops.reverse()
        return AttackPath(self.start, tuple(hops), cost)

    def _enumerate(self, cap: int) -> None:
        paths: list[int] = []
        stack: list[tuple[str, int, frozenset[str]]] = [(self.start.objectid, 0, frozenset({self.start.objectid}))]
        while stack:
            oid, mask, seen = stack.pop()
            for i in reversed(self.out.get(oid, ())):
                e = self.edges[i]
                if e.dst in seen:
                    continue
                m = mask | (1 << i)
                if e.dst in self.terminals:
                    paths.append(m)
                    if len(paths) > cap:
                        self._paths, self._paths_overflow = paths, True
                        return
                else:
                    stack.append((e.dst, m, seen | {e.dst}))
        self._paths, self._paths_overflow = paths, False

    def reach(self, settings: Settings, exclude: Iterable[EdgeKey] = ()) -> Reach:
        """Probability that at least one visible path to Tier Zero works."""
        if self._paths is None:
            self._enumerate(settings.exact_path_limit)
        assert self._paths is not None
        exclude_keys = set(exclude)
        excluded = {i for i, e in enumerate(self.edges) if e.key in exclude_keys}
        excluded_mask = sum(1 << i for i in excluded)
        if not self._paths_overflow:
            paths = [m for m in self._paths if not m & excluded_mask]
            probs = [e.p for e in self.edges]
            return Reach(_union_probability(paths, probs), len(paths), True)
        seed = zlib.crc32(self.start.objectid.encode())
        return Reach(self._monte_carlo(excluded, settings.monte_carlo_samples, seed), len(self._paths), False)

    def _monte_carlo(self, excluded: set[int], samples: int, seed: int) -> float:
        rng = random.Random(seed)  # same seed -> same draws: removal deltas use common random numbers
        probs = [0.0 if i in excluded else e.p for i, e in enumerate(self.edges)]
        hits = 0
        for _ in range(samples):
            draws = [rng.random() for _ in probs]
            stack, seen = [self.start.objectid], {self.start.objectid}
            while stack:
                oid = stack.pop()
                if oid in self.terminals:
                    hits += 1
                    break
                for i in self.out.get(oid, ()):
                    if draws[i] < probs[i] and self.edges[i].dst not in seen:
                        seen.add(self.edges[i].dst)
                        stack.append(self.edges[i].dst)
        return hits / samples if samples else 0.0


def _union_probability(paths: list[int], probs: list[float]) -> float:
    """P(at least one path has all its edges present), exact, by inclusion-exclusion."""
    total = 0.0

    def rec(start: int, mask: int, prob: float, size: int) -> None:
        nonlocal total
        for i in range(start, len(paths)):
            added, p = paths[i] & ~mask, prob
            while added:
                low = added & -added
                p *= probs[low.bit_length() - 1]
                added ^= low
            total += p if size % 2 == 0 else -p
            rec(i + 1, mask | paths[i], p, size + 1)

    rec(0, 0, 1.0, 0)
    return max(0.0, min(1.0, total))


# --------------------------------------------------------------------------
# Context and exposure
# --------------------------------------------------------------------------


class RiskContext:
    """Settings + the analysis time, turned into the functions the model needs."""

    def __init__(self, settings: Settings, now: datetime) -> None:
        self.settings = settings
        self.now = now

    @property
    def objective(self) -> str:
        return "probability" if self.settings.risk_model == "probability" else "hops"

    def edge_probability(self, edge: Edge, target: Node) -> float:
        return self.settings.probability(edge.kind, target.kind, edge.last_seen, self.now)

    def build(self, graph: Graph, start_objectid: str) -> AttackGraph | None:
        return AttackGraph.from_graph(
            graph, start_objectid, self.edge_probability, self.settings.cost, self.settings.traversable_edges
        )


CountUsers = Callable[[frozenset[str]], Awaitable[int | None]]


async def distinct_exposure(
    group_reach: Mapping[str, float],
    user_reach: Mapping[str, float],
    total_users: int,
    count_users: CountUsers,
    max_levels: int,
) -> tuple[float | None, bool]:
    """Expected % of users whose compromise reaches Tier Zero (each user once, at their best group).

    Uses E = sum over levels L of |users with best probability >= L| x (L - next level), with one
    distinct-user count per level. Returns (exposure %, is_estimate); None when counting failed.
    Direct user start nodes are added on top of the group counts (they may overlap: estimate).
    """
    if total_users <= 0:
        return 0.0, False
    values = [p for p in (*group_reach.values(), *user_reach.values()) if p > 0]
    if not values:
        return 0.0, False
    levels = sorted({round(p, 4) for p in values}, reverse=True)
    estimate = bool(user_reach)

    def q(p: float) -> float:
        return round(p, 4)

    if len(levels) > max_levels:  # coarsen down to a grid: a lower bound
        grid = 1.0 / max_levels
        q = lambda p: round(math.floor(round(p, 4) / grid) * grid, 4)  # noqa: E731
        levels = sorted({q(p) for p in values if q(p) > 0}, reverse=True)
        estimate = True
    acc = 0.0
    for i, level in enumerate(levels):
        groups = frozenset(g for g, p in group_reach.items() if q(p) >= level)
        n = await count_users(groups) if groups else 0
        if n is None:
            return None, True
        n += sum(1 for p in user_reach.values() if q(p) >= level)
        nxt = levels[i + 1] if i + 1 < len(levels) else 0.0
        acc += min(n, total_users) * (level - nxt)
    return 100.0 * acc / total_users, estimate
