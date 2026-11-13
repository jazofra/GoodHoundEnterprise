"""A small synthetic AD environment that answers the queries in ``cypher.py``.

It is *not* a Cypher engine: it recognises the handful of query shapes this
tool generates and answers them in BloodHound's unified-graph format.  It lets
you try the tool without a tenant, and the test-suite uses it (also behind a
fake Hunter MCP server) to exercise the whole pipeline end to end.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .base import QueryError

DOMAIN = "CONTOSO.LOCAL"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
TZ = "Tag_Tier_Zero"


@dataclass
class DemoNode:
    id: int
    objectid: str
    name: str
    kind: str
    tier_zero: bool = False
    enabled: bool = True
    description: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class DemoGraph:
    nodes: dict[int, DemoNode] = field(default_factory=dict)
    by_oid: dict[str, DemoNode] = field(default_factory=dict)
    out: dict[int, list[tuple[str, int]]] = field(default_factory=dict)
    inbound: dict[int, list[tuple[str, int]]] = field(default_factory=dict)

    def add(
        self,
        rid: str,
        name: str,
        kind: str,
        *,
        tier_zero: bool = False,
        enabled: bool = True,
        properties: dict[str, Any] | None = None,
    ) -> DemoNode:
        opengraph = "_" in kind  # OpenGraph kinds (CyberArk_Account, ...) keep their own ids and names
        oid = rid if rid.startswith("S-1-5-21") or kind == "Domain" or opengraph else f"{DOMAIN_SID}-{rid}"
        # BloodHound names users/groups NAME@DOMAIN; computers and domains are FQDNs already.
        display = name if kind in ("Domain", "Computer") or opengraph else f"{name}@{DOMAIN}"
        node = DemoNode(len(self.nodes) + 1, oid, display, kind, tier_zero, enabled, properties=dict(properties or {}))
        self.nodes[node.id] = node
        self.by_oid[oid] = node
        return node

    def link(self, src: DemoNode, kind: str, dst: DemoNode) -> None:
        self.out.setdefault(src.id, []).append((kind, dst.id))
        self.inbound.setdefault(dst.id, []).append((kind, src.id))


def build_demo_graph(users: int = 400) -> DemoGraph:
    g = DemoGraph()
    domain = g.add(DOMAIN_SID, DOMAIN, "Domain", tier_zero=True)
    da = g.add("512", "DOMAIN ADMINS", "Group", tier_zero=True)
    g.add("519", "ENTERPRISE ADMINS", "Group", tier_zero=True)
    dcs = g.add("516", "DOMAIN CONTROLLERS", "Group", tier_zero=True)
    dc01 = g.add("1000", "DC01.CONTOSO.LOCAL", "Computer", tier_zero=True)
    g.add("500", "ADMINISTRATOR", "User", tier_zero=True)
    adm_jsmith = g.add("1105", "ADM.JSMITH", "User", tier_zero=True)
    adm_klee = g.add("1106", "ADM.KLEE", "User", tier_zero=True)
    for admin in (adm_jsmith, adm_klee):
        g.link(admin, "MemberOf", da)
    g.link(dc01, "MemberOf", dcs)
    g.link(da, "GenericAll", domain)

    domain_users = g.add("513", "DOMAIN USERS", "Group")
    groups = {
        name: g.add(rid, name, "Group")
        for rid, name in [
            ("1201", "HELPDESK"),
            ("1202", "IT SUPPORT"),
            ("1203", "SERVER ADMINS"),
            ("1204", "SQL ADMINS"),
            ("1205", "DEVELOPERS"),
            ("1206", "CONTRACTORS"),
            ("1207", "FINANCE"),
            ("1208", "MARKETING"),
            ("1209", "WORKSTATION ADMINS"),
        ]
    }
    computers = {
        name: g.add(rid, name, "Computer")
        for rid, name in [
            ("1301", "WS-ADMIN01.CONTOSO.LOCAL"),
            ("1302", "SQL01.CONTOSO.LOCAL"),
            ("1303", "APP01.CONTOSO.LOCAL"),
            ("1304", "FS01.CONTOSO.LOCAL"),
        ]
    }
    svc_sql = g.add("1401", "SVC_SQL", "User")
    descriptions = {
        "APP01.CONTOSO.LOCAL": (
            "Line-of-business app server (owner: Apps team). Domain Users granted RDP for the legacy client."
        ),
        "SQL01.CONTOSO.LOCAL": "SQL Server 2019 - finance DB (owner: DBA team)",
        "WS-ADMIN01.CONTOSO.LOCAL": "Shared IT admin workstation (owner: IT Operations)",
        "SQL ADMINS": "DBA team - local admins on SQL servers",
        "DEVELOPERS": "All developers incl. contractors",
        "ADM.JSMITH": "Domain admin account of J. Smith (IT Operations)",
        "ADM.KLEE": "Domain admin account of K. Lee (Apps team)",
    }
    for node in g.nodes.values():
        node.description = descriptions.get(node.name.split("@")[0], "")

    # Regular users, spread across departments; a few are disabled.
    plan = [
        ("HELPDESK", 30),
        ("IT SUPPORT", 12),
        ("DEVELOPERS", 45),
        ("CONTRACTORS", 25),
        ("FINANCE", 40),
        ("MARKETING", 35),
    ]
    rid = 2000
    for i in range(users):
        rid += 1
        user = g.add(str(rid), f"USER{i + 1:04d}", "User", enabled=(i % 27 != 5))
        g.link(user, "MemberOf", domain_users)
        offset = 0
        for group_name, size in plan:
            if offset <= i < offset + size:
                g.link(user, "MemberOf", groups[group_name])
            offset += size
    for admin in (adm_jsmith, adm_klee, svc_sql):
        g.link(admin, "MemberOf", domain_users)

    # The attack surface.
    g.link(domain_users, "CanRDP", computers["APP01.CONTOSO.LOCAL"])
    g.link(computers["APP01.CONTOSO.LOCAL"], "HasSession", adm_klee)
    g.link(groups["HELPDESK"], "MemberOf", groups["IT SUPPORT"])
    g.link(groups["IT SUPPORT"], "MemberOf", groups["WORKSTATION ADMINS"])
    g.link(groups["IT SUPPORT"], "MemberOf", groups["SERVER ADMINS"])
    g.link(groups["WORKSTATION ADMINS"], "AdminTo", computers["WS-ADMIN01.CONTOSO.LOCAL"])
    g.link(computers["WS-ADMIN01.CONTOSO.LOCAL"], "HasSession", adm_jsmith)
    g.link(groups["SERVER ADMINS"], "AdminTo", computers["SQL01.CONTOSO.LOCAL"])
    g.link(groups["SERVER ADMINS"], "AdminTo", computers["FS01.CONTOSO.LOCAL"])
    g.link(groups["CONTRACTORS"], "MemberOf", groups["DEVELOPERS"])
    g.link(groups["DEVELOPERS"], "GenericWrite", groups["SQL ADMINS"])
    g.link(svc_sql, "MemberOf", groups["SQL ADMINS"])
    g.link(groups["SQL ADMINS"], "AdminTo", computers["SQL01.CONTOSO.LOCAL"])
    g.link(computers["SQL01.CONTOSO.LOCAL"], "HasSession", adm_jsmith)
    g.link(groups["FINANCE"], "ADCSESC1", domain)
    first_user = g.by_oid[f"{DOMAIN_SID}-2007"]
    g.link(first_user, "ForceChangePassword", svc_sql)

    # CyberArk (OpenGraph): only traversed with opengraph = ["CyberArk"].
    pam_operators = g.add("1210", "PAM OPERATORS", "Group")
    g.add(
        "CAPLATFORM-WINDOMAINDUAL-DEMO",
        "WINDOWS DOMAIN DUAL CONTROL",
        "CyberArk_Platform",
        properties={"platformId": "WinDomainDual", "requireDualControlPasswordAccessApproval": True},
    )
    g.add(
        "CAPLATFORM-WINDOMAIN-DEMO",
        "WINDOWS DOMAIN ACCOUNT",
        "CyberArk_Platform",
        properties={"platformId": "WinDomain", "requireDualControlPasswordAccessApproval": False},
    )
    ca_marketing = g.add("CAGROUP-PAM_MARKETING-DEMO", "PAM_MARKETING", "CyberArk_Group")
    ca_operators = g.add("CAGROUP-PAM_OPERATORS-DEMO", "PAM_OPERATORS", "CyberArk_Group")
    safe = g.add("CASAFE-T0_ADMINS-DEMO", "T0_ADMINS", "CyberArk_Safe")
    dual_account = g.add(
        "CAACCOUNT-1_1-DEMO", "ADM.KLEE", "CyberArk_Account", properties={"platformId": "WinDomainDual"}
    )
    plain_account = g.add(
        "CAACCOUNT-1_2-DEMO", "ADM.JSMITH", "CyberArk_Account", properties={"platformId": "WinDomain"}
    )
    g.link(groups["MARKETING"], "CyberArk_SyncsToGroup", ca_marketing)
    g.link(ca_marketing, "CyberArk_HasAccessTo", dual_account)
    g.link(dual_account, "CyberArk_SyncsToADUser", adm_klee)
    g.link(pam_operators, "CyberArk_SyncsToGroup", ca_operators)
    g.link(ca_operators, "CyberArk_HasAccessTo", safe)
    g.link(safe, "CyberArk_Contains", plain_account)
    g.link(plain_account, "CyberArk_SyncsToADUser", adm_jsmith)
    return g


# --------------------------------------------------------------------------


def _node_json(n: DemoNode) -> dict[str, Any]:
    kinds = [n.kind, "Base"] + ([TZ] if n.tier_zero else [])
    return {
        "label": n.name,
        "kind": n.kind,
        "kinds": kinds,
        "objectId": n.objectid,
        "isTierZero": n.tier_zero,
        "properties": {
            "name": n.name,
            "objectid": n.objectid,
            "enabled": n.enabled,
            "domainsid": DOMAIN_SID,
            "description": n.description,
            **n.properties,
        },
    }


def _graph(
    nodes: Sequence[DemoNode], edges: Sequence[tuple[int, str, int]] = (), literals: Sequence[tuple[str, Any]] = ()
) -> dict[str, Any]:
    return {
        "data": {
            "nodes": {str(n.id): _node_json(n) for n in nodes},
            "edges": [
                {"source": str(s), "target": str(t), "kind": k, "label": k, "lastSeen": "2026-11-05T22:00:00Z"}
                for s, k, t in edges
            ],
            "literals": [{"key": k, "value": v} for k, v in literals],
        }
    }


_LIMIT = re.compile(r"LIMIT (\d+)\s*$")
# Target: a label (Tier Zero) or one object by objectid (--target-objectid).
_TARGET = r"->\((?:t:(\w+)|t \{objectid: '([^']+)'\})\)\)"
_ALL_SHORTEST = re.compile(r"allShortestPaths\(\(s:(\w+) \{objectid: '([^']+)'\}\)-\[:([\w|]+)\*1\.\.(\d+)\]" + _TARGET)
_SHORTEST = re.compile(r"shortestPath\(\(s:(\w+) \{objectid: '([^']+)'\}\)-\[:([\w|]+)\*1\.\.(\d+)\]" + _TARGET)
# Stitching: shortest paths from one node to the non-Tier Zero groups around it.
_TO_GROUPS = re.compile(
    r"(allShortestPaths|shortestPath)\(\(s:(\w+) \{objectid: '([^']+)'\}\)-\[:([\w|]+)\*1\.\.(\d+)\]->\(w:Group\)\)"
)

_NODE = re.compile(r"MATCH \(n \{objectid: '([^']+)'\}\) RETURN n")
_VIEW_HOP = re.compile(r"-\[:(\w+)\]->\(n\d+ \{objectid: '([^']+)'\}\)")
_INBOUND = re.compile(r"MATCH p=\(a\)-\[:([\w|]+)\]->\(n \{objectid: '([^']+)'\}\)")
_OUTBOUND = re.compile(r"MATCH p=\(n \{objectid: '([^']+)'\}\)-\[:([\w|]+)\]->\(b\)")
_FIRST_HOPS = re.compile(r"MATCH p=\(s:User \{objectid: '([^']+)'\}\)-\[:([\w|]+)\]->\(m\)")


class DemoExecutor:
    name = "demo"

    def __init__(self, graph: DemoGraph | None = None) -> None:
        self.g = graph or build_demo_graph()
        self.log: list[str] = []

    def _target_test(self, target_oid: str | None):
        if target_oid is None:
            return lambda nid: self.g.nodes[nid].tier_zero
        target = self.g.by_oid.get(target_oid)
        return lambda nid: target is not None and nid == target.id

    def _members(self, group_ids: set[int], max_hops: int) -> set[int]:
        seen, users = set(group_ids), set()
        frontier = deque((gid, 0) for gid in group_ids)
        while frontier:
            gid, depth = frontier.popleft()
            if depth >= max_hops:
                continue
            for kind, src in self.g.inbound.get(gid, ()):
                if kind != "MemberOf" or src in seen:
                    continue
                seen.add(src)
                node = self.g.nodes[src]
                if node.kind == "User":
                    if node.enabled and not node.tier_zero:
                        users.add(src)
                elif node.kind == "Group":
                    frontier.append((src, depth + 1))
        return users

    async def run(self, query: str) -> Any:
        self.log.append(query)
        limit_match = _LIMIT.search(query)
        limit = int(limit_match.group(1)) if limit_match else 1000
        g = self.g

        if "RETURN count(u) AS total" in query:
            total = sum(1 for n in g.nodes.values() if n.kind == "User" and n.enabled and not n.tier_zero)
            return _graph([], literals=[("total", total)])

        if query.startswith("MATCH (d:Domain)"):
            return _graph([n for n in g.nodes.values() if n.kind == "Domain"][:limit])

        if m := re.match(r"MATCH \(s:(\w+)\) WHERE", query):
            label = m.group(1)
            after = re.search(r"s\.objectid > '([^']+)'", query)
            nodes = sorted(
                (
                    n
                    for n in g.nodes.values()
                    if n.kind == label
                    and not n.tier_zero
                    and (label != "User" or n.enabled)
                    and (after is None or n.objectid > after.group(1))
                ),
                key=lambda n: n.objectid,
            )
            return _graph(nodes[:limit])

        if m := re.match(r"MATCH \(n:(\w+)\)(?: WHERE n\.objectid > '([^']+)')? RETURN n ORDER BY", query):
            label, after_oid = m.groups()
            nodes = sorted(
                (n for n in g.nodes.values() if n.kind == label and (after_oid is None or n.objectid > after_oid)),
                key=lambda n: n.objectid,
            )
            return _graph(nodes[:limit])

        if m := _NODE.match(query):
            node = g.by_oid.get(m.group(1))
            return _graph([node] if node else [])

        if query.startswith("MATCH p=(n0 {objectid: "):
            hops = _VIEW_HOP.findall(query)
            first_match = re.match(r"MATCH p=\(n0 \{objectid: '([^']+)'\}\)", query)
            first = g.by_oid.get(first_match.group(1)) if first_match else None
            if first is None:
                return _graph([])
            hop_nodes, hop_edges, at = [first], [], first
            for kind, oid in hops:
                nxt_node = g.by_oid.get(oid)
                if nxt_node is None or (kind, nxt_node.id) not in g.out.get(at.id, []):
                    return _graph([])
                hop_nodes.append(nxt_node)
                hop_edges.append((at.id, kind, nxt_node.id))
                at = nxt_node
            return _graph(hop_nodes, hop_edges)

        if m := _INBOUND.match(query):
            rels, oid = m.groups()
            node = g.by_oid.get(oid)
            if node is None:
                return _graph([])
            allowed = set(rels.split("|"))
            edges = [(src, k, node.id) for k, src in g.inbound.get(node.id, ()) if k in allowed][:limit]
            return _graph([node, *(g.nodes[s] for s, _, _ in edges)], edges)

        if m := _OUTBOUND.match(query):
            oid, rels = m.groups()
            node = g.by_oid.get(oid)
            if node is None:
                return _graph([])
            allowed = set(rels.split("|"))
            edges = [(node.id, k, dst) for k, dst in g.out.get(node.id, ()) if k in allowed][:limit]
            return _graph([node, *(g.nodes[d] for _, _, d in edges)], edges)

        if m := _FIRST_HOPS.match(query):
            oid, rels = m.groups()
            start = g.by_oid.get(oid)
            if start is None:
                return _graph([])
            allowed = set(rels.split("|"))
            edges = [(start.id, kind, dst) for kind, dst in g.out.get(start.id, ()) if kind in allowed][:limit]
            return _graph([start, *(g.nodes[d] for _, _, d in edges)], edges)

        if m := _TO_GROUPS.search(query):
            fn, label, oid, rels, max_hops = m.groups()
            start = g.by_oid.get(oid)
            if start is None or start.kind != label:
                return _graph([])
            allowed, depth = set(rels.split("|")), {start.id: 0}
            way: dict[int, list[tuple[int, str]]] = {}
            frontier = [start.id]
            while frontier and depth[frontier[0]] < int(max_hops):
                nxt_frontier = []
                for cur in frontier:
                    for kind, nxt in g.out.get(cur, ()):
                        if kind not in allowed:
                            continue
                        if nxt not in depth:
                            depth[nxt] = depth[cur] + 1
                            nxt_frontier.append(nxt)
                        if depth[nxt] == depth[cur] + 1:
                            way.setdefault(nxt, []).append((cur, kind))
                frontier = nxt_frontier
            if fn == "shortestPath":  # one path per group
                way = {n: p[:1] for n, p in way.items()}
            group_nodes = {start.id: start}
            group_edges = set()
            groups = sorted(
                n for n in depth if n != start.id and g.nodes[n].kind == "Group" and not g.nodes[n].tier_zero
            )
            for gid in groups[:limit]:
                stack = [gid]
                while stack:
                    cur = stack.pop()
                    group_nodes[cur] = g.nodes[cur]
                    for prev, kind in way.get(cur, ()):
                        if (prev, kind, cur) not in group_edges:
                            group_edges.add((prev, kind, cur))
                            stack.append(prev)
            return _graph(list(group_nodes.values()), sorted(group_edges))

        if m := _ALL_SHORTEST.search(query):
            label, oid, rels, max_hops, _label, target_oid = m.groups()
            is_target = self._target_test(target_oid)
            start = g.by_oid.get(oid)
            if start is None or start.kind != label:
                return _graph([])
            allowed, depth = set(rels.split("|")), {start.id: 0}
            parents: dict[int, list[tuple[int, str]]] = {}
            frontier = [start.id]
            while frontier and depth[frontier[0]] < int(max_hops):
                nxt_frontier = []
                for cur in frontier:
                    if is_target(cur) and cur != start.id:
                        continue  # shortest paths stop at their target
                    for kind, nxt in g.out.get(cur, ()):
                        if kind not in allowed:
                            continue
                        if nxt not in depth:
                            depth[nxt] = depth[cur] + 1
                            nxt_frontier.append(nxt)
                        if depth[nxt] == depth[cur] + 1:
                            parents.setdefault(nxt, []).append((cur, kind))
                frontier = nxt_frontier
            found: dict[int, DemoNode] = {start.id: start}
            found_edges: set[tuple[int, str, int]] = set()
            budget = limit
            for target in sorted(n for n in depth if n != start.id and is_target(n)):
                stack = [target]
                while stack and budget > 0:
                    cur = stack.pop()
                    found[cur] = g.nodes[cur]
                    for prev, kind in parents.get(cur, ()):
                        if (prev, kind, cur) not in found_edges:
                            found_edges.add((prev, kind, cur))
                            stack.append(prev)
                budget -= 1
            return _graph(list(found.values()), sorted(found_edges))

        if m := _SHORTEST.search(query):
            label, oid, rels, max_hops, _label, target_oid = m.groups()
            is_target = self._target_test(target_oid)
            start = g.by_oid.get(oid)
            if start is None or start.kind != label:
                return _graph([])
            allowed = set(rels.split("|"))
            parent: dict[int, tuple[int, str]] = {}
            depth = {start.id: 0}
            queue = deque([start.id])
            while queue:
                cur = queue.popleft()
                if depth[cur] >= int(max_hops):
                    continue
                for kind, nxt in g.out.get(cur, ()):
                    if kind in allowed and nxt not in depth:
                        depth[nxt] = depth[cur] + 1
                        parent[nxt] = (cur, kind)
                        queue.append(nxt)
            targets = sorted((n for n in depth if n != start.id and is_target(n)), key=lambda n: depth[n])
            on_path: dict[int, DemoNode] = {start.id: start}
            path_edges: set[tuple[int, str, int]] = set()
            for t in targets[:limit]:
                cur = t
                while cur != start.id:
                    prev, kind = parent[cur]
                    path_edges.add((prev, kind, cur))
                    on_path[cur] = g.nodes[cur]
                    cur = prev
            return _graph(list(on_path.values()), sorted(path_edges))

        if "AS members" in query:
            group_match = re.search(r"g:Group \{objectid: '([^']+)'\}", query)
            if group_match is None or group_match.group(1) not in g.by_oid:
                return _graph([], literals=[("members", 0)])
            group = g.by_oid[group_match.group(1)]
            return _graph([], literals=[("members", len(self._members({group.id}, 10)))])

        if "AS users" in query:
            ids = [i for lst in re.findall(r"IN \[(.*?)\]", query) for i in re.findall(r"'([^']+)'", lst)]
            group_ids = {g.by_oid[i].id for i in ids if i in g.by_oid}
            return _graph([], literals=[("users", len(self._members(group_ids, 10)))])

        raise QueryError(f"The demo backend does not understand this query: {query}")

    async def aclose(self) -> None:
        pass
