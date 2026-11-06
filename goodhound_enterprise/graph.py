"""Parse BloodHound "unified graph" results and pick paths locally.

BloodHound Enterprise's Cypher endpoint (and, presumably, Hunter's Cypher tool,
whose exact output schema is not yet published) returns a merged graph rather
than one row per path::

    {"data": {"nodes": {"<id>": {"label": ..., "kind": ..., "kinds": [...],
                                  "objectId": ..., "isTierZero": ..., "properties": {...}}},
              "edges": [{"source": "<id>", "target": "<id>", "kind": ...}],
              "literals": [{"key": "total", "value": 42}]}}

``parse_graph`` is deliberately tolerant about where that object sits inside a
tool result, and about a few alternative spellings, so that small differences
in Hunter's envelope do not break the pipeline.
"""

from __future__ import annotations

import hashlib
import heapq
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Node:
    id: str
    objectid: str
    name: str
    kind: str
    kinds: tuple[str, ...] = ()
    tier_zero: bool = False
    properties: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def display(self) -> str:
        return self.name or self.objectid or self.id


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str
    last_seen: str | None = field(default=None, compare=False, hash=False)
    properties: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    literals: list[tuple[str, Any]] = field(default_factory=list)

    def by_objectid(self, objectid: str) -> Node | None:
        for node in self.nodes.values():
            if node.objectid == objectid:
                return node
        return None

    def literal(self, key: str | None = None) -> Any:
        """Value of the literal named ``key`` (or the first literal if ``key`` is None)."""
        for k, v in self.literals:
            if key is None or k == key:
                return v
        if key is not None and len(self.literals) == 1:
            return self.literals[0][1]
        return None

    def merge(self, other: Graph) -> None:
        self.nodes.update(other.nodes)
        seen = set(self.edges)
        self.edges.extend(e for e in other.edges if e not in seen)
        self.literals.extend(other.literals)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

_GRAPH_KEYS = ("nodes", "edges", "literals")


def _find_payload(obj: Any, depth: int = 0) -> Mapping[str, Any] | None:
    if depth > 6:
        return None
    if isinstance(obj, str):
        try:
            return _find_payload(json.loads(obj), depth + 1)
        except (ValueError, TypeError):
            return None
    if isinstance(obj, Mapping):
        if any(k in obj for k in _GRAPH_KEYS):
            return obj
        for key in ("data", "result", "results", "graph", "structuredContent", "structured_content"):
            if key in obj:
                found = _find_payload(obj[key], depth + 1)
                if found is not None:
                    return found
        for value in obj.values():
            if isinstance(value, (Mapping, list)) or (isinstance(value, str) and value.lstrip()[:1] in ("{", "[")):
                found = _find_payload(value, depth + 1)
                if found is not None:
                    return found
    if isinstance(obj, list):
        for item in obj:
            found = _find_payload(item, depth + 1)
            if found is not None:
                return found
    return None


def _node_from(raw_id: str, raw: Mapping[str, Any], target_label: str) -> Node:
    props = raw.get("properties") or {}
    kinds = tuple(raw.get("kinds") or ([raw["kind"]] if raw.get("kind") else []))
    kind = raw.get("kind") or next((k for k in kinds if k != "Base" and not k.startswith("Tag_")), "") or ""
    system_tags = str(props.get("system_tags") or "")
    tier_zero = bool(
        raw.get("isTierZero")
        or target_label in kinds
        or (target_label == "Tag_Tier_Zero" and "admin_tier_0" in system_tags)
    )
    objectid = raw.get("objectId") or raw.get("objectid") or props.get("objectid") or ""
    name = raw.get("label") or raw.get("name") or props.get("name") or ""
    return Node(
        id=str(raw.get("id", raw_id)),
        objectid=str(objectid),
        name=str(name),
        kind=str(kind),
        kinds=kinds,
        tier_zero=tier_zero,
        properties=props,
    )


def _literals_from(raw: Any) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(raw, Mapping):
        return [(str(k), v) for k, v in raw.items()]
    for item in raw or []:
        if isinstance(item, Mapping) and "key" in item:
            out.append((str(item["key"]), item.get("value")))
        elif isinstance(item, Mapping):
            out.extend((str(k), v) for k, v in item.items())
    return out


def parse_graph(result: Any, target_label: str = "Tag_Tier_Zero") -> Graph:
    """Convert a Cypher result (any supported envelope) into a ``Graph``."""
    payload = _find_payload(result)
    graph = Graph()
    if payload is None:
        return graph
    raw_nodes = payload.get("nodes") or {}
    if isinstance(raw_nodes, Mapping):
        items: Iterable[tuple[str, Any]] = raw_nodes.items()
    else:
        items = ((str(n.get("id", i)), n) for i, n in enumerate(raw_nodes))
    for raw_id, raw in items:
        node = _node_from(str(raw_id), raw, target_label)
        graph.nodes[str(raw_id)] = node
    for raw in payload.get("edges") or []:
        source = raw.get("source", raw.get("start", raw.get("from")))
        target = raw.get("target", raw.get("end", raw.get("to")))
        kind = raw.get("kind") or raw.get("label") or raw.get("type")
        if source is None or target is None or not kind:
            continue
        graph.edges.append(Edge(str(source), str(target), str(kind), raw.get("lastSeen"), raw.get("properties") or {}))
    graph.literals = _literals_from(payload.get("literals"))
    return graph


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Hop:
    source: Node
    kind: str
    target: Node


@dataclass(frozen=True)
class AttackPath:
    start: Node
    hops: tuple[Hop, ...]
    cost: int

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def target(self) -> Node:
        return self.hops[-1].target

    @property
    def nodes(self) -> list[Node]:
        return [self.start, *(h.target for h in self.hops)]

    @property
    def text(self) -> str:
        parts = [self.start.display]
        for hop in self.hops:
            parts.append(f" - {hop.kind} -> {hop.target.display}")
        return "".join(parts)

    @property
    def uid(self) -> str:
        """Stable id: object ids and edge kinds, so renames do not create 'new' paths."""
        key = "|".join([self.start.objectid, *(f"{h.kind}|{h.target.objectid}" for h in self.hops)])
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def suffix(self, index: int, cost_fn: Callable[[str, str], int]) -> AttackPath:
        hops = self.hops[index:]
        return AttackPath(hops[0].source, hops, sum(cost_fn(h.kind, h.target.kind) for h in hops))


def best_path(
    graph: Graph,
    start: Node | str,
    cost_fn: Callable[[str, str], int],
    allowed_edges: Iterable[str] | None = None,
) -> AttackPath | None:
    """Fewest hops, then lowest cost, from ``start`` to the first Tier Zero node.

    Tier Zero nodes are terminal: once an attacker reaches Tier Zero the path
    is complete, so the search never expands through them.
    """
    if isinstance(start, Node):
        start_node = graph.nodes.get(start.id) or graph.by_objectid(start.objectid)
    else:
        start_node = graph.by_objectid(start)
    if start_node is None or start_node.tier_zero:
        return None
    allowed = set(allowed_edges) if allowed_edges is not None else None
    adjacency: dict[str, list[Edge]] = {}
    for edge in graph.edges:
        if allowed is None or edge.kind in allowed:
            adjacency.setdefault(edge.source, []).append(edge)

    # Dijkstra on the lexicographic weight (hops, cost).
    best: dict[str, tuple[int, int]] = {start_node.id: (0, 0)}
    parent: dict[str, Edge] = {}
    heap: list[tuple[int, int, str]] = [(0, 0, start_node.id)]
    while heap:
        hops, cost, node_id = heapq.heappop(heap)
        if best.get(node_id) != (hops, cost):
            continue
        node = graph.nodes.get(node_id)
        if node is None:
            continue
        if node.tier_zero:
            return _rebuild(graph, start_node, node_id, parent, cost)
        for edge in sorted(adjacency.get(node_id, ()), key=lambda e: (e.target, e.kind)):
            target = graph.nodes.get(edge.target)
            if target is None:
                continue
            candidate = (hops + 1, cost + cost_fn(edge.kind, target.kind))
            if candidate < best.get(edge.target, (10**9, 10**9)):
                best[edge.target] = candidate
                parent[edge.target] = edge
                heapq.heappush(heap, (*candidate, edge.target))
    return None


def _rebuild(graph: Graph, start: Node, end_id: str, parent: dict[str, Edge], cost: int) -> AttackPath:
    hops: list[Hop] = []
    current = end_id
    while current != start.id:
        edge = parent[current]
        hops.append(Hop(graph.nodes[edge.source], edge.kind, graph.nodes[edge.target]))
        current = edge.source
    hops.reverse()
    return AttackPath(start, tuple(hops), cost)
