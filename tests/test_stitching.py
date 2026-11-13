"""Paths longer than Hunter's hop limit: stitching and the hop-limit warning."""

import json

import pytest

from goodhound_enterprise import cypher, report
from goodhound_enterprise.analysis import analyse
from goodhound_enterprise.backends.base import QueryError
from goodhound_enterprise.backends.demo import DOMAIN_SID, DemoExecutor, build_demo_graph
from goodhound_enterprise.config import Settings
from goodhound_enterprise.source import CypherGraphSource

D = 0.95
SESSION, ADMIN, ACCESS = 0.6 * D, 0.9 * D, 0.9 * D
PAM_OPERATORS = f"{DOMAIN_SID}-1210"


async def run(graph, executor=None, **settings_kw):
    settings_kw.setdefault("session_half_life_days", 0)
    executor = executor or DemoExecutor(graph)
    source = CypherGraphSource(executor, Settings(rate_limit=0, **settings_kw))
    return await analyse(source, tenant="demo", results=5), executor


def by_start(result):
    return {r.path.start.name.split("@")[0]: r for r in result.all_paths}


def session_chain(g, start, rid, pairs, end):
    """start -AdminTo-> computer -HasSession-> user, ``pairs`` times, then the last user -MemberOf-> end."""
    at = start
    for i in range(pairs):
        computer = g.add(str(rid + 2 * i), f"DEEP{rid + 2 * i}.CONTOSO.LOCAL", "Computer")
        user = g.add(str(rid + 2 * i + 1), f"DEEPUSER{rid + 2 * i + 1}", "User")
        g.link(at, "AdminTo", computer)
        g.link(computer, "HasSession", user)
        at = user
    g.link(at, "MemberOf", end)


def deep_graph():
    """BRANCH ADMINS: three admin/session pairs, then a group synced into CyberArk: 11 hops to Tier Zero."""
    g = build_demo_graph()
    branch = g.add("5000", "BRANCH ADMINS", "Group")
    session_chain(g, branch, 5100, 3, g.by_oid[PAM_OPERATORS])
    return g, branch


async def test_a_path_over_the_hop_limit_is_stitched():
    g, branch = deep_graph()
    result, executor = await run(g, opengraph=["CyberArk"])
    row = by_start(result)["BRANCH ADMINS"]
    assert row.path.length == 11 and row.stitched
    assert [h.kind for h in row.path.hops] == [
        *["AdminTo", "HasSession"] * 3,
        "MemberOf",
        "CyberArk_SyncsToGroup",
        "CyberArk_HasAccessTo",
        "CyberArk_Contains",
        "CyberArk_SyncsToADUser",
    ]
    assert row.reach == pytest.approx((ADMIN * SESSION) ** 3 * ACCESS)
    assert result.stitched == [branch.objectid] and result.hop_limited == []
    assert not by_start(result)["PAM OPERATORS"].stitched
    summary = dict(report._summary(result))
    assert summary["Start nodes with paths over 10 hops"].startswith("1:")
    doc = json.loads(report.to_json(result))
    assert doc["stitched"] == [branch.objectid]
    assert all(p["stitched"] == (p["start"]["objectid"] == branch.objectid) for p in doc["busiest_paths"])
    for q in executor.log:
        cypher.assert_hunter_safe(q)
    cypher.assert_hunter_safe(row.query)  # a fixed-length pattern: no variable-length bound applies


async def test_without_stitching_the_deep_path_is_invisible():
    g, _ = deep_graph()
    result, executor = await run(g, opengraph=["CyberArk"], stitch=False)
    assert "BRANCH ADMINS" not in by_start(result)
    assert result.stitched == [] and result.hop_limited == []
    assert not any("(w:Group)" in q for q in executor.log)


async def test_stitched_groups_are_waypoints_for_deeper_ones():
    g, branch = deep_graph()
    remote = g.add("6000", "REMOTE SITE ADMINS", "Group")
    session_chain(g, remote, 6100, 4, branch)  # 9 hops to BRANCH ADMINS, 20 to Tier Zero
    result, _ = await run(g, opengraph=["CyberArk"])
    row = by_start(result)["REMOTE SITE ADMINS"]
    assert row.path.length == 20 and row.stitched
    assert row.reach == pytest.approx((ADMIN * SESSION) ** 7 * ACCESS)
    assert result.stitched == sorted([branch.objectid, remote.objectid])


async def test_a_user_with_a_deep_path_of_their_own_is_stitched():
    g = build_demo_graph()
    user = g.add("7000", "LONE.ADMIN", "User")
    session_chain(g, user, 7100, 3, g.by_oid[PAM_OPERATORS])
    result, _ = await run(g, opengraph=["CyberArk"], include_users=True)
    row = by_start(result)["LONE.ADMIN"]
    assert row.start_label == "User" and row.path.length == 11 and row.stitched
    assert user.objectid in result.stitched


async def test_start_nodes_cut_off_at_the_hop_limit_are_reported():
    g = build_demo_graph()
    chain = [g.add(str(8000 + i), f"NESTED{i:02d}", "Group") for i in range(12)]
    for a, b in zip(chain, chain[1:], strict=False):
        g.link(a, "MemberOf", b)  # leads nowhere, but is longer than the hop limit
    result, _ = await run(g)
    # NESTED00 and NESTED01 see a group exactly 10 hops away; NESTED02 sees the end of the chain.
    assert result.hop_limited == [chain[0].objectid, chain[1].objectid]
    assert result.stitched == [] and "NESTED00" not in by_start(result)
    assert dict(report._summary(result))["Start nodes cut off at the hop limit"].startswith("2:")
    assert json.loads(report.to_json(result))["hop_limited"] == result.hop_limited


async def test_a_backend_that_rejects_the_stitching_query_only_loses_stitching():
    class Strict(DemoExecutor):
        refused = 0

        async def run(self, query):
            if "(w:Group)" in query:
                self.refused += 1
                raise QueryError("unsupported pattern")
            return await super().run(query)

    g, _ = deep_graph()
    baseline, _ = await run(build_demo_graph(), opengraph=["CyberArk"], stitch=False)
    result, executor = await run(g, Strict(g), opengraph=["CyberArk"], concurrency=1)
    assert result.stitch_unavailable and result.stitched == []
    assert executor.refused == 2  # both variants for the first group, then switched off
    assert set(by_start(result)) == set(by_start(baseline))
    assert "Stitching" in dict(report._summary(result))


def test_stitching_query_shape():
    settings = Settings()
    query = cypher.paths_to_groups(settings, "Group", "S-1-5-21-1-2-3-1104", all_paths=False)
    assert "shortestPath((s:Group {objectid: 'S-1-5-21-1-2-3-1104'})" in query
    assert "*1..10]->(w:Group)) WHERE NOT w:Tag_Tier_Zero AND s <> w RETURN p LIMIT 100" in query
    cypher.assert_hunter_safe(query)
