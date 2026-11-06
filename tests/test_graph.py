import json

from goodhound_enterprise.config import Settings
from goodhound_enterprise.graph import best_path, parse_graph


def node(name, kind, oid, tz=False):
    kinds = [kind, "Base"] + (["Tag_Tier_Zero"] if tz else [])
    return {"label": name, "kind": kind, "kinds": kinds, "objectId": oid, "isTierZero": tz, "properties": {}}


def bhe_result():
    return {
        "data": {
            "nodes": {
                "1": node("HELPDESK@X", "Group", "G1"),
                "2": node("SRV01.X", "Computer", "C1"),
                "3": node("ADM@X", "User", "U1", tz=True),
                "4": node("DOMAIN ADMINS@X", "Group", "DA", tz=True),
                "5": node("BACKUP OPS@X", "Group", "G2"),
            },
            "edges": [
                {"source": "1", "target": "2", "kind": "AdminTo"},
                {"source": "2", "target": "3", "kind": "HasSession"},
                {"source": "3", "target": "4", "kind": "MemberOf"},
                {"source": "1", "target": "5", "kind": "MemberOf"},
                {"source": "5", "target": "4", "kind": "GenericAll"},
            ],
            "literals": [],
        }
    }


def test_parse_bhe_rest_shape():
    g = parse_graph(bhe_result())
    assert len(g.nodes) == 5 and len(g.edges) == 5
    assert g.nodes["3"].tier_zero and not g.nodes["1"].tier_zero
    assert g.by_objectid("G1").name == "HELPDESK@X"


def test_parse_tolerates_wrapped_and_text_envelopes():
    wrapped = {"result": {"graph": bhe_result()["data"]}}
    as_text = {"text": json.dumps(bhe_result())}
    assert len(parse_graph(wrapped).nodes) == 5
    assert len(parse_graph(as_text).nodes) == 5
    assert parse_graph({"something": "else"}).nodes == {}


def test_literals():
    g = parse_graph({"data": {"literals": [{"key": "total", "value": 42}]}})
    assert g.literal("total") == 42
    g = parse_graph({"data": {"literals": [{"key": "count(u)", "value": 7}]}})
    assert g.literal("total") == 7  # single literal falls back regardless of name


def test_best_path_prefers_fewest_hops_then_lowest_cost_and_stops_at_tier_zero():
    s = Settings()
    g = parse_graph(bhe_result())
    path = best_path(g, "G1", s.cost)
    # Both G1->C1->U1 (AdminTo 1 + HasSession 3) and G1->G2->DA (MemberOf 0 + GenericAll 1) are 2 hops;
    # the cheaper one wins, and the search never continues past the first Tier Zero node.
    assert [h.kind for h in path.hops] == ["MemberOf", "GenericAll"]
    assert path.cost == 1 and path.length == 2
    assert path.target.objectid == "DA"
    assert path.text == "HELPDESK@X - MemberOf -> BACKUP OPS@X - GenericAll -> DOMAIN ADMINS@X"


def test_best_path_respects_allowed_edges_and_missing_start():
    s = Settings()
    g = parse_graph(bhe_result())
    path = best_path(g, "G1", s.cost, allowed_edges=["AdminTo", "HasSession"])
    assert [h.kind for h in path.hops] == ["AdminTo", "HasSession"] and path.cost == 4
    assert best_path(g, "NOPE", s.cost) is None
    assert best_path(g, "U1", s.cost) is None  # Tier Zero start


def test_uid_is_stable_across_renames():
    s = Settings()
    a = best_path(parse_graph(bhe_result()), "G1", s.cost)
    renamed = bhe_result()
    renamed["data"]["nodes"]["1"]["label"] = "HELPDESK-RENAMED@X"
    b = best_path(parse_graph(renamed), "G1", s.cost)
    assert a.uid == b.uid and a.text != b.text
