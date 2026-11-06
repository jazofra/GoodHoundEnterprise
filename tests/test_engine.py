import pytest

from goodhound_enterprise import cypher, history, report
from goodhound_enterprise.analysis import analyse, risk_score
from goodhound_enterprise.backends.demo import DemoExecutor, build_demo_graph
from goodhound_enterprise.config import Settings
from goodhound_enterprise.source import CypherGraphSource


async def run_demo(**settings_kw):
    executor = DemoExecutor()
    source = CypherGraphSource(executor, Settings(rate_limit=0, **settings_kw))
    result = await analyse(source, tenant="demo", results=5)
    return result, executor


def by_start(result):
    return {r.path.start.name: r for r in result.all_paths}


async def test_busiest_paths_on_demo_tenant():
    result, executor = await run_demo()
    rows = by_start(result)
    assert result.total_enabled_users == 386
    assert result.busiest[0].path.start.name == "DOMAIN USERS@CONTOSO.LOCAL"
    top = result.busiest[0]
    assert [h.kind for h in top.path.hops] == ["CanRDP", "HasSession"]
    assert top.members == 386 and top.percentage == 100.0
    assert top.risk == risk_score(3, 100.0, 31) == 90.3
    assert "MARKETING@CONTOSO.LOCAL" not in rows  # no path
    assert rows["FINANCE@CONTOSO.LOCAL"].path.length == 1
    # Nested membership: CONTRACTORS are counted as DEVELOPERS too.
    assert rows["DEVELOPERS@CONTOSO.LOCAL"].members > rows["CONTRACTORS@CONTOSO.LOCAL"].members
    # Every query the engine produced is Hunter-compliant.
    for q in executor.log:
        cypher.assert_hunter_safe(q)


async def test_suffix_reuse_saves_queries():
    result, executor = await run_demo()
    shortest = [q for q in executor.log if "shortestPath" in q]
    assert len(shortest) < 10  # 10 groups scanned, intermediate groups reuse their suffix
    assert len(result.all_paths) == 9


async def test_weakest_links():
    result, _ = await run_demo()
    top = result.weakest[0]
    assert top.hop.kind == "HasSession"
    assert top.hop.target.name == "ADM.JSMITH@CONTOSO.LOCAL"
    assert top.paths >= 3 and top.percentage == round(top.paths / result.total_paths * 100, 1)


async def test_include_users_finds_direct_user_paths_but_not_inherited_ones():
    result, _ = await run_demo(include_users=True)
    user_rows = [r for r in result.all_paths if r.start_label == "User"]
    assert [r.path.start.name for r in user_rows] == ["USER0007@CONTOSO.LOCAL"]
    assert user_rows[0].path.hops[0].kind == "ForceChangePassword"
    assert result.users_with_path_is_estimate


async def test_fixed_path_shows_as_resolved_in_history(tmp_path):
    db = tmp_path / "h.db"
    first, _ = await run_demo()
    d1 = history.record(first, db)
    assert d1.new_paths == 9 and d1.seen_before == 0 and d1.previous_run_at is None

    # Remediate: remove the RDP right that exposes Domain Users.
    graph = build_demo_graph()
    du = graph.by_oid["S-1-5-21-1004336348-1177238915-682003330-513"]
    graph.out[du.id] = [e for e in graph.out[du.id] if e[0] != "CanRDP"]
    source = CypherGraphSource(DemoExecutor(graph), Settings(rate_limit=0))
    second = await analyse(source, tenant="demo")
    d2 = history.record(second, db)
    assert d2.new_paths == 0 and d2.seen_before == 8
    assert [start for start, _ in d2.resolved] == ["DOMAIN USERS@CONTOSO.LOCAL"]
    assert second.users_with_path < first.users_with_path


@pytest.mark.parametrize("fmt", report.FORMATS)
async def test_reports_render(tmp_path, fmt, capsys):
    result, _ = await run_demo()
    result.history = {
        "previous_run_at": "2026-01-01T00:00:00",
        "new_paths": 1,
        "pct_seen_before": 50.0,
        "resolved_paths": 1,
        "resolved": [("<script>X</script>", "a - b -> c")],
    }
    written = report.emit(result, [fmt], tmp_path)
    if fmt == "stdout":
        assert "BUSIEST PATHS" in capsys.readouterr().out
        return
    assert written
    text = "".join(f.read_text() for f in written)
    assert "DOMAIN USERS@CONTOSO.LOCAL" in text
    if fmt == "html":
        assert "<script>X</script>" not in text and "&lt;script&gt;" in text
