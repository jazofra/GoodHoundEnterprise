"""The only door agents have into BloodHound.

Every tool an agent can call is defined here and executed by *this process*
through the same ``CypherGraphSource`` the deterministic engine uses. So:

* there is one Hunter connection (one OAuth approval) for the whole fleet,
* one rate limiter, so a fleet cannot exceed Hunter's per-IP limit,
* every query passes ``assert_hunter_safe`` (read-only, bounded),
* every call is written to an audit log,
* results are trimmed before they reach a model, which bounds token spend.

Graph content is attacker-influenced (anyone who can edit an AD object controls
its name and description), so results are returned as JSON data and the agent
prompts tell the models never to follow instructions found inside them.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .. import cypher
from ..analysis import AnalysisResult
from ..backends.base import QueryError
from ..graph import Graph, Node
from ..risk import RiskContext
from ..source import CypherGraphSource

MAX_RESULT_CHARS = 12_000
MAX_LIST_ITEMS = 40
_PROP_LIMIT = 300

Handler = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass
class Tool:
    name: str
    description: str
    properties: dict[str, Any]
    handler: Handler

    def param(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "strict": True,
            "input_schema": {
                "type": "object",
                "properties": self.properties,
                "required": list(self.properties),
                "additionalProperties": False,
            },
        }


@dataclass
class AuditEntry:
    agent: str
    tool: str
    arguments: dict[str, Any]
    ok: bool
    ms: int
    error: str | None = None


def _str(desc: str) -> dict[str, str]:
    return {"type": "string", "description": desc}


def _compact_props(props: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in sorted(props.items()):
        if isinstance(value, str):
            out[key] = value if len(value) <= _PROP_LIMIT else value[:_PROP_LIMIT] + "…"
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = value[:10]
    return out


def node_json(node: Node, *, full: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": node.display,
        "objectid": node.objectid,
        "kind": node.kind,
        "tier_zero": node.tier_zero,
    }
    if full:
        data["properties"] = _compact_props(dict(node.properties))
    elif node.properties.get("enabled") is not None:
        data["enabled"] = node.properties.get("enabled")
    return data


def _edges_json(graph: Graph, *, around: str, direction: str) -> list[dict[str, Any]]:
    rows = []
    for e in graph.edges:
        if (direction == "in" and e.target != around) or (direction == "out" and e.source != around):
            continue
        other = graph.nodes.get(e.source if direction == "in" else e.target)
        if other is None:
            continue
        rows.append({"relationship": e.kind, "last_seen": e.last_seen, **node_json(other)})
    rows.sort(key=lambda r: (r["relationship"], r["name"]))
    return rows


@dataclass
class Gateway:
    source: CypherGraphSource
    result: AnalysisResult
    hunter: Any = None  # HunterExecutor when the backend is Hunter (typed-tool passthrough)
    audit: list[AuditEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.tools: dict[str, Tool] = {t.name: t for t in self._build_tools()}

    # ------------------------------------------------------------------ plumbing

    def tool_params(self) -> list[dict[str, Any]]:
        return [t.param() for t in self.tools.values()]

    async def call(self, agent: str, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run one tool call. Returns (JSON text, is_error)."""
        started = time.monotonic()
        tool = self.tools.get(name)
        try:
            if tool is None:
                raise QueryError(f"Unknown tool {name!r}")
            payload = await tool.handler(dict(arguments or {}))
            text = json.dumps(payload, default=str)
            if len(text) > MAX_RESULT_CHARS:
                text = text[:MAX_RESULT_CHARS] + '..." [truncated: narrow the request]'
            self.audit.append(AuditEntry(agent, name, arguments, True, int((time.monotonic() - started) * 1000)))
            return text, False
        except Exception as exc:
            # Whatever went wrong (rejected query, dropped session, bad arguments), the agent gets
            # an error result it can react to; one failed call must not take the fleet down.
            self.audit.append(
                AuditEntry(agent, name, arguments, False, int((time.monotonic() - started) * 1000), str(exc)[:300])
            )
            return json.dumps({"error": (str(exc) or type(exc).__name__)[:1000]}), True

    async def _query(self, query: str) -> Graph:
        return await self.source.query(query)

    async def _node(self, objectid: str) -> Node:
        graph = await self._query(cypher.node_by_objectid(objectid))
        node = graph.by_objectid(objectid)
        if node is None:
            raise QueryError(f"No object with objectid {objectid!r}")
        return node

    # ------------------------------------------------------------------ tools

    def _build_tools(self) -> list[Tool]:
        settings = self.source.settings
        # Same dual-control platforms as the analysis, so the agents' numbers match the report's.
        ctx = RiskContext(settings, self.result.generated_at, self.result.dual_control_keys)
        attack_edges = [e for e in settings.traversable_edges if e != "MemberOf"]
        oid = _str("objectid (SID or GUID) exactly as given in the task or a previous tool result")

        async def get_object(args: dict[str, Any]) -> Any:
            return node_json(await self._node(args["objectid"]), full=True)

        async def relationship_exists(args: dict[str, Any]) -> Any:
            q = cypher.view_path([(args["source_objectid"], args["kind"], args["target_objectid"])])
            graph = await self._query(q)
            edge = next((e for e in graph.edges if e.kind == args["kind"]), None)
            return {"exists": edge is not None, "last_seen": edge.last_seen if edge else None, "query": q}

        async def inbound_control(args: dict[str, Any]) -> Any:
            graph = await self._query(cypher.inbound(args["objectid"], attack_edges))
            target = graph.by_objectid(args["objectid"])
            rows = _edges_json(graph, around=target.id, direction="in") if target else []
            return {"controllers": rows[:MAX_LIST_ITEMS], "total_returned": len(rows)}

        async def group_members(args: dict[str, Any]) -> Any:
            group = await self._node(args["objectid"])
            graph = await self._query(cypher.inbound(args["objectid"], ["MemberOf"]))
            target = graph.by_objectid(args["objectid"])
            rows = _edges_json(graph, around=target.id, direction="in") if target else []
            nested_users = await self.source.member_count(group) if group.kind == "Group" else None
            return {
                "group": node_json(group),
                "direct_members_sample": rows[:MAX_LIST_ITEMS],
                "direct_members_returned": len(rows),
                "enabled_non_tier_zero_users_including_nested": nested_users,
            }

        async def outbound_rights(args: dict[str, Any]) -> Any:
            graph = await self._query(cypher.outbound(args["objectid"], self.source.settings.traversable_edges))
            start = graph.by_objectid(args["objectid"])
            rows = _edges_json(graph, around=start.id, direction="out") if start else []
            return {"relationships": rows[:MAX_LIST_ITEMS], "total_returned": len(rows)}

        async def paths_using_link(args: dict[str, Any]) -> Any:
            key = (args["source_objectid"], args["kind"], args["target_objectid"])
            rows = [
                {
                    "start": r.path.start.display,
                    "start_objectid": r.path.start.objectid,
                    "users": r.members,
                    "risk": r.risk,
                    "reach_probability": round(r.reach, 4),
                    "reach_without_this_link": round(r.graph.reach(settings, exclude=[key]).probability, 4)
                    if r.graph is not None
                    else None,
                    "most_likely_path": r.path.text,
                }
                for r in self.result.all_paths
                if (r.graph is not None and key in r.graph.keys)
                or any((h.source.objectid, h.kind, h.target.objectid) == key for h in r.path.hops)
            ]
            return {"start_nodes": rows[:MAX_LIST_ITEMS], "count": len(rows)}

        async def path_without_link(args: dict[str, Any]) -> Any:
            start = await self._node(args["start_objectid"])
            try:
                graph = await self._query(cypher.all_shortest_paths_from(settings, start.kind, start.objectid))
                searched = "all shortest paths"
            except QueryError:  # the backend may not support allShortestPaths
                graph = await self._query(cypher.shortest_paths_from(settings, start.kind, start.objectid))
                searched = "one shortest path per Tier Zero target"
            removed = (args["source_objectid"], args["kind"], args["target_objectid"])
            before = ctx.build(graph, start.objectid)
            reach_before = before.reach(settings).probability if before else 0.0

            def keep(edge) -> bool:
                src, dst = graph.nodes.get(edge.source), graph.nodes.get(edge.target)
                return not (src and dst and (src.objectid, edge.kind, dst.objectid) == removed)

            graph.edges = [e for e in graph.edges if keep(e)]
            after = ctx.build(graph, start.objectid)
            path = after.best_path(ctx.objective) if after else None
            return {
                "reach_probability_before": round(reach_before, 4),
                "reach_probability_after": round(after.reach(settings).probability, 4) if after else 0.0,
                "remaining_most_likely_path": path.text if path else None,
                "remaining_path_probability": round(path.probability, 4) if path else None,
                "hops": path.length if path else None,
                "searched": searched,
                "note": "Only paths of the minimal hop length are searched; a longer remaining path would not show.",
            }

        async def run_cypher(args: dict[str, Any]) -> Any:
            graph = await self._query(args["query"])
            return {
                "nodes": [node_json(n) for n in list(graph.nodes.values())[:MAX_LIST_ITEMS]],
                "edges": [
                    {
                        "source": graph.nodes[e.source].display if e.source in graph.nodes else e.source,
                        "kind": e.kind,
                        "target": graph.nodes[e.target].display if e.target in graph.nodes else e.target,
                    }
                    for e in graph.edges[:MAX_LIST_ITEMS]
                ],
                "literals": graph.literals[:MAX_LIST_ITEMS],
                "total_nodes": len(graph.nodes),
                "total_edges": len(graph.edges),
            }

        async def list_bloodhound_tools(args: dict[str, Any]) -> Any:
            if self.hunter is None:
                return {"tools": [], "note": "Typed Hunter tools are only available with the hunter backend."}
            tools = self.hunter.tools or await self.hunter.list_tools()
            return {
                "tools": [
                    {
                        "name": t.name,
                        "description": (t.description or "")[:300],
                        "arguments": list((t.input_schema or {}).get("properties") or {}),
                    }
                    for t in tools
                    if t.name != self.hunter.tool_name
                ]
            }

        async def call_bloodhound_tool(args: dict[str, Any]) -> Any:
            if self.hunter is None:
                raise QueryError("Typed Hunter tools are only available with the hunter backend.")
            name = args["tool"]
            if name == self.hunter.tool_name:
                raise QueryError("Use run_cypher for Cypher; it applies the read-only guard-rails.")
            arguments = json.loads(args["arguments_json"] or "{}")
            if not isinstance(arguments, dict):
                raise ValueError("arguments_json must be a JSON object")
            await self.source.throttle()  # typed tools share Hunter's rate limit with the queries
            result = await self.hunter.call_tool(name, arguments)
            from ..backends.hunter import _result_payload

            payload = _result_payload(result)
            if result.is_error:
                raise QueryError(f"{name} failed: {json.dumps(payload)[:500]}")
            return payload

        edge = {
            "source_objectid": oid,
            "kind": _str("relationship kind, e.g. HasSession, AdminTo, MemberOf"),
            "target_objectid": oid,
        }
        return [
            Tool(
                "get_object",
                "Properties of one AD object (name, kind, Tier Zero flag, description, enabled, timestamps...).",
                {"objectid": oid},
                get_object,
            ),
            Tool(
                "relationship_exists",
                "Check, right now, whether one relationship still exists in BloodHound and when it was last seen.",
                edge,
                relationship_exists,
            ),
            Tool(
                "inbound_control",
                "Who holds attack rights (ACLs, admin, sessions, delegation, ...) over an "
                "object. Useful to find owners or other ways to the same object.",
                {"objectid": oid},
                inbound_control,
            ),
            Tool(
                "group_members",
                "Direct members of a group (sample) and the count of enabled non-Tier Zero "
                "users including nested membership.",
                {"objectid": oid},
                group_members,
            ),
            Tool(
                "outbound_rights",
                "Attack relationships an object holds over other objects.",
                {"objectid": oid},
                outbound_rights,
            ),
            Tool(
                "paths_using_link",
                "Which analysed start nodes depend on a relationship: their users, risk, and reach probability "
                "now and without this relationship (from this run's results, no query).",
                edge,
                paths_using_link,
            ),
            Tool(
                "path_without_link",
                "Re-run the shortest-path search from a start object without one relationship: reach "
                "probability before and after, and the most likely path that would remain after fixing it.",
                {"start_objectid": oid, **edge},
                path_without_link,
            ),
            Tool(
                "run_cypher",
                "Run one read-only BloodHound Cypher query. It must end with LIMIT 1-100, bound "
                "variable-length patterns to at most 10 hops, and not write. Tier Zero is the label "
                "Tag_Tier_Zero. Prefer the other tools.",
                {"query": _str("the Cypher query")},
                run_cypher,
            ),
            Tool(
                "list_bloodhound_tools",
                "List BloodHound Enterprise's own typed tools (findings, remediation "
                "guidance, ...) available through Hunter.",
                {},
                list_bloodhound_tools,
            ),
            Tool(
                "call_bloodhound_tool",
                "Call one of BloodHound Enterprise's typed Hunter tools (read-only). Use list_bloodhound_tools first.",
                {"tool": _str("tool name"), "arguments_json": _str("the tool's arguments as a JSON object")},
                call_bloodhound_tool,
            ),
        ]
