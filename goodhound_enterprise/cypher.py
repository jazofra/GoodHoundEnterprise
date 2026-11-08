"""Cypher builders that stay inside Hunter MCP's documented guard-rails.

Hunter's Cypher fallback (per the SpecterOps docs) must:

* end with a literal ``LIMIT`` between 1 and 100,
* bound every variable-length traversal to at most 10 hops,
* not mutate the graph,
* not use collection-producing result functions (e.g. ``collect()``).

GoodHound's original queries break all four rules (unbounded ``shortestPath``,
``SET r.cost``, APOC path combination, unbounded result sets), so the analysis
is decomposed into many small, bounded queries and the aggregation happens on
the client.  ``assert_hunter_safe`` double-checks every query before it is sent.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from .config import HUNTER_MAX_HOPS, HUNTER_MAX_LIMIT, Settings


class UnsafeQueryError(ValueError):
    """Raised when a generated query would be rejected by Hunter."""


def literal(value: str) -> str:
    """Quote a string as a Cypher single-quoted literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _label(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise UnsafeQueryError(f"Invalid label or relationship kind: {name!r}")
    return name


def rel_types(kinds: Iterable[str]) -> str:
    kinds = list(kinds)
    if not kinds:
        raise UnsafeQueryError("At least one relationship kind is required")
    return "|".join(_label(k) for k in kinds)


def _domain_clause(var: str, settings: Settings) -> str:
    return f" AND {var}.domainsid = {literal(settings.domain_sid)}" if settings.domain_sid else ""


# --------------------------------------------------------------------------
# Query builders
# --------------------------------------------------------------------------


def count_enabled_users(settings: Settings) -> str:
    tz = _label(settings.target_label)
    return (
        f"MATCH (u:User) WHERE u.enabled = true AND NOT u:{tz}{_domain_clause('u', settings)} "
        "RETURN count(u) AS total LIMIT 1"
    )


def list_start_nodes(settings: Settings, start_label: str, after: str | None) -> str:
    """One keyset-paginated page of non-Tier Zero start nodes, ordered by objectid."""
    tz = _label(settings.target_label)
    label = _label(start_label)
    where = [f"NOT s:{tz}"]
    if start_label == "User":
        where.append("s.enabled = true")
    if after is not None:
        where.append(f"s.objectid > {literal(after)}")
    if settings.domain_sid:
        where.append(f"s.domainsid = {literal(settings.domain_sid)}")
    return f"MATCH (s:{label}) WHERE {' AND '.join(where)} RETURN s ORDER BY s.objectid ASC LIMIT {settings.page_size}"


def shortest_paths_from(settings: Settings, start_label: str, objectid: str, max_hops: int | None = None) -> str:
    """Shortest paths from one start node to every reachable Tier Zero node.

    Returning up to ``paths_per_start`` paths (one per target) lets the client
    choose the cheapest among the shortest, which is what GoodHound's
    ``min(cost)`` did.
    """
    tz = _label(settings.target_label)
    rels = rel_types(settings.traversable_edges)
    hops = max_hops or settings.max_hops
    return (
        f"MATCH p=shortestPath((s:{_label(start_label)} {{objectid: {literal(objectid)}}})"
        f"-[:{rels}*1..{hops}]->(t:{tz})) "
        f"RETURN p LIMIT {settings.paths_per_start}"
    )


def all_shortest_paths_from(settings: Settings, start_label: str, objectid: str, max_hops: int | None = None) -> str:
    """Every shortest path (not one per target) from a start node to Tier Zero."""
    tz = _label(settings.target_label)
    rels = rel_types(settings.traversable_edges)
    return (
        f"MATCH p=allShortestPaths((s:{_label(start_label)} {{objectid: {literal(objectid)}}})"
        f"-[:{rels}*1..{max_hops or settings.max_hops}]->(t:{tz})) "
        f"RETURN p LIMIT {settings.paths_per_start}"
    )


def first_hops(settings: Settings, user_objectid: str) -> str:
    """A user's outbound attack edges other than group membership."""
    rels = rel_types(e for e in settings.traversable_edges if e != "MemberOf")
    return f"MATCH p=(s:User {{objectid: {literal(user_objectid)}}})-[:{rels}]->(m) RETURN p LIMIT {HUNTER_MAX_LIMIT}"


def member_count(settings: Settings, group_objectid: str) -> str:
    tz = _label(settings.target_label)
    return (
        f"MATCH (u:User)-[:MemberOf*1..{settings.max_hops}]->(g:Group {{objectid: {literal(group_objectid)}}}) "
        f"WHERE u.enabled = true AND NOT u:{tz}{_domain_clause('u', settings)} "
        "RETURN count(DISTINCT u) AS members LIMIT 1"
    )


def unique_members(settings: Settings, group_objectids: Sequence[str]) -> str:
    tz = _label(settings.target_label)
    ids = ", ".join(literal(i) for i in group_objectids)
    return (
        f"MATCH (u:User)-[:MemberOf*1..{settings.max_hops}]->(g:Group) "
        f"WHERE g.objectid IN [{ids}] AND u.enabled = true AND NOT u:{tz}{_domain_clause('u', settings)} "
        "RETURN count(DISTINCT u) AS users LIMIT 1"
    )


def node_by_objectid(objectid: str) -> str:
    return f"MATCH (n {{objectid: {literal(objectid)}}}) RETURN n LIMIT 1"


def inbound(objectid: str, kinds: Iterable[str], limit: int = HUNTER_MAX_LIMIT) -> str:
    """One-hop relationships of the given kinds that point *at* an object."""
    return f"MATCH p=(a)-[:{rel_types(kinds)}]->(n {{objectid: {literal(objectid)}}}) RETURN p LIMIT {limit}"


def outbound(objectid: str, kinds: Iterable[str], limit: int = HUNTER_MAX_LIMIT) -> str:
    """One-hop relationships of the given kinds that start *from* an object."""
    return f"MATCH p=(n {{objectid: {literal(objectid)}}})-[:{rel_types(kinds)}]->(b) RETURN p LIMIT {limit}"


def list_domains() -> str:
    return f"MATCH (d:Domain) RETURN d LIMIT {HUNTER_MAX_LIMIT}"


def view_path(hops: Sequence[tuple[str, str, str]]) -> str:
    """Query that renders exactly one path in BloodHound Explore (or via Hunter).

    ``hops`` is a sequence of (source objectid, edge kind, target objectid).
    """
    if not hops:
        raise ValueError("empty path")
    parts = [f"(n0 {{objectid: {literal(hops[0][0])}}})"]
    for i, (_, kind, target) in enumerate(hops, start=1):
        parts.append(f"-[:{_label(kind)}]->(n{i} {{objectid: {literal(target)}}})")
    return f"MATCH p={''.join(parts)} RETURN p LIMIT 1"


# --------------------------------------------------------------------------
# Guard-rail check
# --------------------------------------------------------------------------

_LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\s*;?\s*$", re.IGNORECASE)
_VARLEN_RE = re.compile(r"\*\s*(\d*)\s*(\.\.)?\s*(\d*)\s*\]")
_WRITE_RE = re.compile(r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD\s+CSV|CALL)\b", re.IGNORECASE)
_COLLECT_RE = re.compile(r"\bcollect\s*\(", re.IGNORECASE)


def assert_hunter_safe(query: str, max_hops: int = HUNTER_MAX_HOPS) -> None:
    """Raise ``UnsafeQueryError`` if ``query`` breaks a documented Hunter rule.

    String literals are blanked first so object names cannot trigger false
    positives.
    """
    stripped = re.sub(r"'(?:\\.|[^'\\])*'", "''", query)
    m = _LIMIT_RE.search(stripped)
    if not m or not 1 <= int(m.group(1)) <= HUNTER_MAX_LIMIT:
        raise UnsafeQueryError(f"Query must end with LIMIT 1..{HUNTER_MAX_LIMIT}: {query}")
    for vm in _VARLEN_RE.finditer(stripped):
        lo, dots, hi = vm.groups()
        upper = hi if dots else lo
        if not upper or int(upper) > max_hops:
            raise UnsafeQueryError(f"Variable-length traversal must be bounded to <= {max_hops} hops: {query}")
    if _WRITE_RE.search(stripped):
        raise UnsafeQueryError(f"Query must be read-only: {query}")
    if _COLLECT_RE.search(stripped):
        raise UnsafeQueryError(f"collect() is not allowed by Hunter: {query}")
