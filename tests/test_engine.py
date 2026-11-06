import sqlite3

import pytest

from goodhound_enterprise import cypher, history, report
from goodhound_enterprise.analysis import analyse, risk_score
from goodhound_enterprise.backends.demo import DOMAIN_SID, DemoExecutor, build_demo_graph
from goodhound_enterprise.config import Settings
from goodhound_enterprise.source import CypherGraphSource

# Effective hop probabilities with the defaults (5% detection per action) and no session decay.
D = 0.95
RDP, SESSION, ADMIN, WRITE, ESC1, RESET = 0.4 * D, 0.6 * D, 0.9 * D, 0.9 * D, 0.9 * D, 0.95 * D
N = 386  # enabled non-Tier Zero users in the demo


async def run_demo(graph=None, **settings_kw):
    settings_kw.setdefault("session_half_life_days", 0)  # demo timestamps are fixed; keep numbers stable
    executor = DemoExecutor(graph)
    source = CypherGraphSource(executor, Settings(rate_limit=0, **settings_kw))
    result = await analyse(source, tenant="demo", results=5)
    return result, executor


def by_start(result):
    return {r.path.start.name.split("@")[0]: r for r in result.all_paths}


async def test_reach_risk_and_most_likely_paths():
    result, executor = await run_demo()
    rows = by_start(result)
    assert result.total_enabled_users == N and "MARKETING" not in rows

    du = rows["DOMAIN USERS"]
    assert [h.kind for h in du.path.hops] == ["CanRDP", "HasSession"]
    assert du.path.probability == pytest.approx(RDP * SESSION)
    assert du.risk == pytest.approx(100 * RDP * SESSION * 386 / N, abs=0.01)

    # Two independent equally short routes (via WS-ADMIN01 and via SQL01): reach = 1 - (1 - p)^2.
    route = ADMIN * SESSION
    it = rows["IT SUPPORT"]
    assert it.paths == 2 and it.path.probability == pytest.approx(route)
    assert it.reach == pytest.approx(1 - (1 - route) ** 2)
    assert rows["HELPDESK"].reach == pytest.approx(it.reach)  # MemberOf hops are free

    # Hops matter: every extra action multiplies by a probability below 1.
    assert rows["DEVELOPERS"].reach == pytest.approx(WRITE * ADMIN * SESSION)
    assert rows["DEVELOPERS"].reach < rows["SERVER ADMINS"].reach
    assert rows["FINANCE"].reach == pytest.approx(ESC1)

    # Busiest = highest expected exposure, not just most users.
    assert [r.path.start.name.split("@")[0] for r in result.busiest[:3]] == ["DOMAIN USERS", "FINANCE", "IT SUPPORT"]
    for q in executor.log:
        cypher.assert_hunter_safe(q)


async def test_exposure_counts_each_user_once_at_their_best_path():
    result, _ = await run_demo()
    rows = by_start(result)
    # Departments are disjoint and everyone is in Domain Users, so each user's best path is their
    # department's (if better) and Domain Users' otherwise.
    best = {
        "FINANCE": rows["FINANCE"].reach,
        "IT SUPPORT": rows["IT SUPPORT"].reach,  # includes nested HELPDESK
        "DEVELOPERS": rows["DEVELOPERS"].reach,  # includes nested CONTRACTORS
        "SQL ADMINS": rows["SQL ADMINS"].reach,
    }
    members = {"FINANCE": 38, "IT SUPPORT": 40, "DEVELOPERS": 68, "SQL ADMINS": 1}
    rest = N - sum(members.values())
    expected = 100 * (sum(best[g] * members[g] for g in best) + rest * rows["DOMAIN USERS"].reach) / N
    assert result.exposure == pytest.approx(expected, abs=0.02)
    assert not result.exposure_is_estimate


async def test_weakest_links_rank_by_exposure_removed():
    result, _ = await run_demo()
    links = [(w.hop.source.name.split("@")[0].split(".")[0], w.hop.kind) for w in result.weakest]
    # The Domain Users path's two links remove the most exposure, even though only one path uses them.
    assert set(links[:2]) == {("APP01", "HasSession"), ("DOMAIN USERS", "CanRDP")}
    du_only = N - (38 + 40 + 68 + 1)  # users whose only path is Domain Users'
    assert result.weakest[0].risk_reduction == pytest.approx(100 * du_only * RDP * SESSION / N, abs=0.02)
    assert result.weakest[0].users_exposed == N
    assert links[2] == ("FINANCE", "ADCSESC1")
    assert result.weakest[2].risk_reduction == pytest.approx(100 * 38 * (ESC1 - RDP * SESSION) / N, abs=0.02)
    # SQL01's session sits on 6 start nodes' graphs but its users keep other paths: it ranks lower,
    # and its distinct users are counted once (CONTRACTORS are inside DEVELOPERS, HELPDESK inside IT SUPPORT).
    sql = next(w for w in result.weakest if w.hop.source.name.startswith("SQL01"))
    assert sql.paths == 6 and sql.users_exposed == 68 + 40 + 1
    assert sql.risk_reduction < result.weakest[2].risk_reduction


async def test_detection_and_session_age_lower_probabilities():
    base, _ = await run_demo(per_action_detection=0)
    careful, _ = await run_demo(per_action_detection=0.2)
    assert by_start(careful)["DEVELOPERS"].reach == pytest.approx(by_start(base)["DEVELOPERS"].reach * 0.8**3)
    assert by_start(careful)["HELPDESK"].reach < by_start(base)["HELPDESK"].reach
    fresh, _ = await run_demo(session_half_life_days=1e9)
    stale, _ = await run_demo(session_half_life_days=0.5)  # demo sessions were seen days ago
    assert by_start(stale)["DOMAIN USERS"].reach < by_start(fresh)["DOMAIN USERS"].reach
    assert stale.exposure < fresh.exposure


async def test_goodhound_model_reproduces_the_original_numbers():
    result, _ = await run_demo(risk_model="goodhound")
    rows = by_start(result)
    assert rows["DOMAIN USERS"].risk == risk_score(3, 100.0, 31) == 90.3
    assert rows["DEVELOPERS"].risk == 14.8 and rows["FINANCE"].risk == 9.2
    assert result.exposure is None
    top = result.weakest[0]
    assert (top.hop.source.name, top.hop.kind) == ("SQL01.CONTOSO.LOCAL", "HasSession")
    # Same as GoodHound's original output for this graph: 4 paths, 134 users (summed, with double counting).
    assert top.risk_reduction is None and top.paths == 4 and top.users_exposed == 134


async def test_suffix_reuse_saves_queries_only_when_enabled():
    _, executor = await run_demo(concurrency=1)
    assert sum("ShortestPaths(" in q for q in executor.log) == 10  # every non-Tier Zero group
    result, executor = await run_demo(concurrency=1, reuse_suffixes=True)
    assert sum("ShortestPaths(" in q for q in executor.log) < 10
    assert len(result.all_paths) == 9


async def test_falls_back_to_shortest_path_when_all_shortest_is_rejected():
    from goodhound_enterprise.backends.base import QueryError

    class NoAllShortest(DemoExecutor):
        async def run(self, query):
            if "allShortestPaths" in query:
                raise QueryError("unsupported")
            return await super().run(query)

    executor = NoAllShortest()
    source = CypherGraphSource(executor, Settings(rate_limit=0, session_half_life_days=0))
    result = await analyse(source, tenant="demo")
    assert sum("allShortestPaths" in q for q in executor.log) == 0  # QueryError is raised before logging
    assert by_start(result)["IT SUPPORT"].paths == 1  # one path per target: the alternative is not visible


async def test_include_users_finds_direct_user_paths_but_not_inherited_ones():
    result, _ = await run_demo(include_users=True)
    user_rows = [r for r in result.all_paths if r.start_label == "User"]
    assert [r.path.start.name for r in user_rows] == ["USER0007@CONTOSO.LOCAL"]
    assert user_rows[0].path.hops[0].kind == "ForceChangePassword"
    # After resetting SVC_SQL's password the attacker has both of SVC_SQL's routes: via SQL ADMINS -> SQL01,
    # and via its own Domain Users membership -> APP01.
    assert user_rows[0].path.probability == pytest.approx(RESET * ADMIN * SESSION)
    assert user_rows[0].reach == pytest.approx(RESET * (1 - (1 - ADMIN * SESSION) * (1 - RDP * SESSION)))
    assert result.users_with_path_is_estimate and result.exposure_is_estimate


async def test_fixed_path_shows_as_resolved_in_history(tmp_path):
    db = tmp_path / "h.db"
    first, _ = await run_demo()
    d1 = history.record(first, db)
    assert d1.new_paths == 9 and d1.seen_before == 0 and d1.previous_run_at is None

    # Remediate: remove the RDP right that exposes Domain Users.
    graph = build_demo_graph()
    du = graph.by_oid[f"{DOMAIN_SID}-513"]
    graph.out[du.id] = [e for e in graph.out[du.id] if e[0] != "CanRDP"]
    second, _ = await run_demo(graph)
    d2 = history.record(second, db)
    assert d2.new_paths == 0 and d2.seen_before == 8
    assert [start for start, _ in d2.resolved] == ["DOMAIN USERS@CONTOSO.LOCAL"]
    assert d2.previous_exposure == first.exposure and second.exposure < first.exposure
    assert second.users_with_path < first.users_with_path


async def test_history_upgrades_an_old_database(tmp_path):
    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    old.executescript(
        """CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, generated_at TEXT NOT NULL,
               total_enabled_users INTEGER NOT NULL, users_with_path INTEGER, total_paths INTEGER NOT NULL);
           CREATE TABLE observations (run_id INTEGER NOT NULL, uid TEXT NOT NULL, members INTEGER NOT NULL,
               percentage REAL NOT NULL, hops INTEGER NOT NULL, cost INTEGER NOT NULL, risk REAL NOT NULL,
               PRIMARY KEY (run_id, uid));
           INSERT INTO runs (tenant, generated_at, total_enabled_users, users_with_path, total_paths)
               VALUES ('demo', '2026-01-01T00:00:00+00:00', 386, 386, 9);"""
    )
    old.commit()
    old.close()
    result, _ = await run_demo()
    delta = history.record(result, db)
    assert delta.previous_run_at == "2026-01-01T00:00:00+00:00" and delta.previous_exposure is None
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(observations)")}
    assert {"path_probability", "reach", "paths"} <= cols


async def test_unparseable_count_is_an_error_not_zero():
    from goodhound_enterprise.backends.base import QueryError

    class Broken(DemoExecutor):
        async def run(self, query):
            if "AS total" in query:
                return {"data": {"nodes": {}, "edges": []}}
            return await super().run(query)

    with pytest.raises(QueryError, match="Expected a number"):
        await analyse(CypherGraphSource(Broken(), Settings(rate_limit=0)), tenant="demo")


@pytest.mark.parametrize("model", ["probability", "goodhound"])
@pytest.mark.parametrize("fmt", report.FORMATS)
async def test_reports_render(tmp_path, fmt, model, capsys):
    result, _ = await run_demo(risk_model=model)
    result.history = {
        "previous_run_at": "2026-01-01T00:00:00",
        "previous_exposure": 40.0,
        "new_paths": 1,
        "pct_seen_before": 50.0,
        "resolved_paths": 1,
        "resolved": [("<script>X</script>", "a - b -> c")],
    }
    written = report.emit(result, [fmt], tmp_path)
    if fmt == "stdout":
        out = capsys.readouterr().out
        assert "BUSIEST PATHS" in out and ("Reach Prob." in out) == (model == "probability")
        return
    assert written
    text = "".join(f.read_text() for f in written)
    assert "DOMAIN USERS@CONTOSO.LOCAL" in text
    if fmt == "html":
        assert "<script>X</script>" not in text and "&lt;script&gt;" in text
        if model == "probability":
            assert "exposure change since last run" in text


async def test_weakest_link_early_stop_matches_exhaustive_ranking():
    async def run(results):
        source = CypherGraphSource(DemoExecutor(), Settings(rate_limit=0, session_half_life_days=0))
        return await analyse(source, tenant="demo", results=results)

    top3, everything = await run(3), await run(100)
    key = lambda w: (w.hop.source.objectid, w.hop.kind, w.hop.target.objectid, w.risk_reduction)  # noqa: E731
    assert [key(w) for w in top3.weakest] == [key(w) for w in everything.weakest[:3]]
    assert top3.queries_sent < everything.queries_sent  # the bound skipped exact scoring of the tail
