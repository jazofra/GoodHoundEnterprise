import pytest

from goodhound_enterprise import cypher
from goodhound_enterprise.config import Settings, load_settings


@pytest.fixture
def settings():
    return Settings()


def all_queries(settings):
    return [
        cypher.count_enabled_users(settings),
        cypher.list_start_nodes(settings, "Group", None),
        cypher.list_start_nodes(settings, "User", "S-1-5-21-1-2-3-1000"),
        cypher.shortest_paths_from(settings, "Group", "S-1-5-21-1-2-3-513"),
        cypher.member_count(settings, "S-1-5-21-1-2-3-513"),
        cypher.unique_members(settings, ["A", "B"]),
        cypher.list_domains(),
        cypher.view_path([("A", "MemberOf", "B"), ("B", "AdminTo", "C")]),
    ]


def test_every_generated_query_respects_hunter_rules(settings):
    for q in all_queries(settings):
        cypher.assert_hunter_safe(q)


def test_domain_filter_is_applied():
    s = Settings(domain_sid="S-1-5-21-9")
    assert "domainsid = 'S-1-5-21-9'" in cypher.list_start_nodes(s, "Group", None)
    assert "domainsid = 'S-1-5-21-9'" in cypher.count_enabled_users(s)


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (n) RETURN n",  # no LIMIT
        "MATCH (n) RETURN n LIMIT 500",  # LIMIT too large
        "MATCH p=shortestPath((a)-[*1..]->(b)) RETURN p LIMIT 1",  # unbounded
        "MATCH p=(a)-[*]->(b) RETURN p LIMIT 1",  # unbounded
        "MATCH p=(a)-[:MemberOf*1..15]->(b) RETURN p LIMIT 1",  # > 10 hops
        "MATCH (n) SET n.cost = 1 RETURN n LIMIT 1",  # write
        "MATCH (n) RETURN collect(n) LIMIT 1",  # collection result
    ],
)
def test_unsafe_queries_are_rejected(query):
    with pytest.raises(cypher.UnsafeQueryError):
        cypher.assert_hunter_safe(query)


def test_literals_are_escaped_and_do_not_confuse_the_checker():
    q = cypher.view_path([("O'BRIEN SET LIMIT 5", "MemberOf", "B")])
    assert "O\\'BRIEN" in q
    cypher.assert_hunter_safe(q)


def test_labels_are_validated():
    with pytest.raises(cypher.UnsafeQueryError):
        cypher.rel_types(["MemberOf]->(x) DETACH DELETE x //"])


def test_settings_enforce_hunter_limits():
    with pytest.raises(ValueError):
        Settings(max_hops=11)
    with pytest.raises(ValueError):
        Settings(page_size=101)


def test_targeted_costs_match_goodhound():
    s = Settings()
    assert s.cost("GenericAll", "User") == 1
    assert s.cost("GenericAll", "Domain") == 2
    assert s.cost("HasSession") == 3
    assert s.cost("SomethingNew") == s.default_cost
    assert s.max_path_cost == 31  # 10 hops * cost 3 + 1


def test_load_settings_from_toml(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("max_hops = 6\n[edges]\nHasSession = 5\nCustomEdge = 2\n")
    s = load_settings(cfg, domain_sid="S-1", max_hops=None)
    assert s.max_hops == 6 and s.domain_sid == "S-1"
    assert s.cost("HasSession") == 5 and s.cost("CustomEdge") == 2
    assert "MemberOf" in s.edge_costs  # defaults kept unless replace_default_edges
