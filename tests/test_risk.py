"""The probability maths, checked against brute force."""

import itertools
import random
from datetime import UTC, datetime, timedelta

import pytest

from goodhound_enterprise.config import Settings, load_settings
from goodhound_enterprise.graph import Node
from goodhound_enterprise.risk import AttackGraph, GEdge, distinct_exposure


def node(oid: str) -> Node:
    return Node(oid, oid, oid, "Group", (), oid.startswith("T"))


def brute_force_reach(edges: list[GEdge], start: str) -> float:
    """Sum over every possible world (each edge present or not) of P(world) x reachable(world)."""
    total = 0.0
    for world in itertools.product((False, True), repeat=len(edges)):
        prob, adj = 1.0, {}
        for e, on in zip(edges, world, strict=True):
            prob *= e.p if on else 1 - e.p
            if on:
                adj.setdefault(e.src, []).append(e.dst)
        seen, stack, hit = {start}, [start], False
        while stack:
            n = stack.pop()
            if n.startswith("T") and n != start:
                hit = True
                break
            for d in adj.get(n, ()):
                if d not in seen:
                    seen.add(d)
                    stack.append(d)
        total += prob * hit
    return total


def random_graph(rng: random.Random, n_mid: int, n_edges: int) -> tuple[dict[str, Node], list[GEdge]]:
    mids = [f"M{i}" for i in range(n_mid)]
    nodes = {o: node(o) for o in ["S", *mids, "T1", "T2"]}
    edges, used = [], set()
    while len(edges) < n_edges:
        src = rng.choice(["S", *mids])
        dst = rng.choice([*mids, "T1", "T2"])
        if src == dst or (src, dst) in used:
            continue
        used.add((src, dst))
        edges.append(GEdge(src, dst, f"K{len(edges)}", round(rng.uniform(0.1, 1.0), 2), 1))
    return nodes, edges


@pytest.mark.parametrize("seed", range(25))
def test_exact_reach_matches_brute_force_on_random_graphs(seed):
    rng = random.Random(seed)
    nodes, edges = random_graph(rng, n_mid=4, n_edges=9)  # cycles allowed
    ag = AttackGraph.from_edges(nodes["S"], nodes, edges)
    expected = brute_force_reach(edges, "S")
    if ag is None:
        assert expected == 0
        return
    reach = ag.reach(Settings(exact_path_limit=16))
    assert reach.exact
    assert reach.probability == pytest.approx(expected, abs=1e-9)
    # Removing one relationship equals brute force on the graph without it.
    key = ag.edges[0].key
    without = [e for e in edges if e.key != key]
    assert ag.reach(Settings(exact_path_limit=16), exclude=[key]).probability == pytest.approx(
        brute_force_reach(without, "S"), abs=1e-9
    )


def test_monte_carlo_is_close_to_exact_and_deterministic():
    rng = random.Random(7)
    nodes, edges = random_graph(rng, n_mid=5, n_edges=14)
    exact = AttackGraph.from_edges(nodes["S"], nodes, edges).reach(Settings(exact_path_limit=16))
    settings = Settings(exact_path_limit=1, monte_carlo_samples=20000)
    mc1 = AttackGraph.from_edges(nodes["S"], nodes, edges).reach(settings)
    mc2 = AttackGraph.from_edges(nodes["S"], nodes, edges).reach(settings)
    assert not mc1.exact and mc1 == mc2  # seeded: reruns give the same number (stable history)
    assert mc1.probability == pytest.approx(exact.probability, abs=0.015)


def test_choke_point_caps_reach_and_alternatives_raise_it():
    nodes = {o: node(o) for o in ["S", "C", "A", "B", "T1"]}
    choke = [
        GEdge("S", "C", "x", 0.5, 1),
        GEdge("C", "A", "y", 0.9, 1),
        GEdge("C", "B", "z", 0.9, 1),
        GEdge("A", "T1", "u", 0.9, 1),
        GEdge("B", "T1", "v", 0.9, 1),
    ]
    ag = AttackGraph.from_edges(nodes["S"], nodes, choke)
    two_routes = 1 - (1 - 0.81) ** 2
    assert ag.reach(Settings()).probability == pytest.approx(0.5 * two_routes)  # never above the choke point
    assert ag.reach(Settings()).paths == 2
    assert ag.reach(Settings(), exclude=[("S", "x", "C")]).probability == 0


def test_most_likely_path_beats_shortest_path():
    nodes = {o: node(o) for o in ["S", "A", "B", "T1"]}
    edges = [
        GEdge("S", "T1", "risky", 0.2, 3),
        GEdge("S", "A", "a", 0.9, 1),
        GEdge("A", "B", "b", 0.9, 1),
        GEdge("B", "T1", "c", 0.9, 1),
    ]
    ag = AttackGraph.from_edges(nodes["S"], nodes, edges)
    assert [h.kind for h in ag.best_path("probability").hops] == ["a", "b", "c"]
    assert [h.kind for h in ag.best_path("hops").hops] == ["risky"]
    assert ag.best_path().probability == pytest.approx(0.729)


def test_tier_zero_is_terminal_and_dead_ends_are_pruned():
    nodes = {o: node(o) for o in ["S", "T1", "T2", "X"]}
    edges = [GEdge("S", "T1", "a", 0.5, 1), GEdge("T1", "T2", "b", 1.0, 0), GEdge("S", "X", "dead", 1.0, 0)]
    ag = AttackGraph.from_edges(nodes["S"], nodes, edges)
    assert {e.kind for e in ag.edges} == {"a"}
    assert ag.reach(Settings()).probability == 0.5


def test_edge_probability_model():
    now = datetime(2026, 11, 6, tzinfo=UTC)
    s = Settings()
    assert s.probability("MemberOf") == 1.0  # structural: no action, no detection
    assert s.probability("AdminTo") == pytest.approx(0.9 * 0.95)
    fresh = s.probability("HasSession", "User", now.isoformat(), now)
    two_weeks = s.probability("HasSession", "User", (now - timedelta(days=14)).isoformat(), now)
    assert fresh == pytest.approx(0.6 * 0.95) and two_weeks == pytest.approx(fresh / 2)
    assert s.probability("HasSession", "User", "not a date", now) == fresh
    assert Settings(session_half_life_days=0).probability("HasSession", "User", "2020-01-01T00:00:00Z", now) == fresh
    assert s.probability("SomethingNew") == pytest.approx(0.7 * 0.95)
    targeted = Settings(targeted_probability={"GenericAll->Domain": 0.5})
    assert targeted.probability("GenericAll", "Domain") == pytest.approx(0.5 * 0.95)
    assert targeted.probability("GenericAll", "User") == pytest.approx(0.9 * 0.95)


def test_probability_settings_are_validated_and_loadable(tmp_path):
    with pytest.raises(ValueError):
        Settings(edge_probability={"AdminTo": 1.5})
    with pytest.raises(ValueError):
        Settings(per_action_detection=-0.1)
    with pytest.raises(ValueError):
        Settings(risk_model="vibes")
    cfg = tmp_path / "c.toml"
    cfg.write_text("per_action_detection = 0.1\n[edge_probability]\nCanRDP = 0.7\nNewEdge = 0.3\n")
    s = load_settings(cfg)
    assert s.edge_probability["CanRDP"] == 0.7 and s.edge_probability["AdminTo"] == 0.9
    assert "NewEdge" in s.traversable_edges and s.per_action_detection == 0.1


# ---------------------------------------------------------------- exposure


async def test_distinct_exposure_matches_per_user_brute_force():
    rng = random.Random(3)
    users = [f"u{i}" for i in range(200)]
    # Overlapping and nested groups.
    membership = {
        "everyone": set(users),
        "g1": set(users[:60]),
        "g2": set(users[40:120]),
        "g1nested": set(users[:20]),
        "g3": set(rng.sample(users, 50)),
    }
    reach = {"everyone": 0.2, "g1": 0.6, "g2": 0.45, "g1nested": 0.9, "g3": 0.6}

    async def count_users(groups):
        return len(set().union(*(membership[g] for g in groups)))

    exposure, estimate = await distinct_exposure(reach, {}, len(users), count_users, 25)
    expected = 100 * sum(max(reach[g] for g in membership if u in membership[g]) for u in users) / len(users)
    assert exposure == pytest.approx(expected, abs=1e-6) and not estimate

    # Too many distinct levels: coarsened to a grid, a lower bound flagged as an estimate.
    coarse, est = await distinct_exposure(reach, {}, len(users), count_users, 2)
    assert est and coarse <= expected


async def test_distinct_exposure_failure_and_empty_cases():
    async def broken(_groups):
        return None

    assert await distinct_exposure({"g": 0.5}, {}, 10, broken, 25) == (None, True)
    assert await distinct_exposure({}, {}, 10, broken, 25) == (0.0, False)
    assert await distinct_exposure({"g": 0.5}, {}, 0, broken, 25) == (0.0, False)
