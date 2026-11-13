"""Input validation, failure isolation, interrupted runs and the comparability of history."""

import asyncio
import csv
import dataclasses
import json
import os

import pytest

from goodhound_enterprise import cli, history, report
from goodhound_enterprise.analysis import analyse, goodhound_weakest_links, probability_weakest_links
from goodhound_enterprise.backends import hunter
from goodhound_enterprise.backends.base import QueryError, RetryableQueryError
from goodhound_enterprise.backends.demo import DOMAIN_SID, DemoExecutor, build_demo_graph
from goodhound_enterprise.checkpoint import Checkpoint
from goodhound_enterprise.config import Settings, load_settings
from goodhound_enterprise.fleet import FleetConfig, run_fleet
from goodhound_enterprise.fleet.gateway import Gateway
from goodhound_enterprise.graph import AttackPath, parse_graph, reaches_path_limit
from goodhound_enterprise.source import CypherGraphSource
from tests.test_fleet import FakeModel

D = 0.95  # 5% detection per attacker action
DOMAIN_USERS = f"{DOMAIN_SID}-513"
MARKETING = f"{DOMAIN_SID}-1208"


def demo_settings(**kw) -> Settings:
    kw.setdefault("session_half_life_days", 0)  # demo timestamps are fixed; keep numbers stable
    return Settings(rate_limit=0, **kw)


async def run_demo(executor=None, *, checkpoint=None, retries=3, **settings_kw):
    executor = executor or DemoExecutor()
    source = CypherGraphSource(executor, demo_settings(**settings_kw), retries=retries, checkpoint=checkpoint)
    return await analyse(source, tenant="demo"), executor


# ---------------------------------------------------------------- settings and the command line


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"concurrency": 0}, "concurrency must be at least 1"),
        ({"rate_limit": -1}, "rate_limit"),
        ({"dual_control_probability": 7}, "dual_control_probability must be between 0 and 1"),
        ({"monte_carlo_samples": 0}, "monte_carlo_samples must be at least 1"),
        ({"exposure_levels": 0}, "exposure_levels must be at least 1"),
        ({"max_hops": "ten"}, "max_hops must be a whole number"),
        ({"concurrency": True}, "concurrency must be a whole number"),
        ({"rate_limit": "fast"}, "rate_limit must be a number"),
        ({"include_users": "yes"}, "include_users must be true or false"),
        ({"opengraph": "CyberArk"}, "opengraph must be a list"),
        ({"edge_probability": {"AdminTo": "high"}}, "AdminTo must be a number"),
        ({"edge_costs": {"AdminTo": 1.5}}, "AdminTo must be a whole number"),
    ],
)
def test_bad_settings_are_rejected_by_name(kw, message):
    with pytest.raises(ValueError, match=message):
        Settings(**kw)


def test_config_file_problems_are_plain_errors(tmp_path):
    with pytest.raises(ValueError, match="Cannot read the config file"):
        load_settings(tmp_path / "missing.toml")
    broken = tmp_path / "broken.toml"
    broken.write_text("max_hops = = 3")
    with pytest.raises(ValueError, match="not valid TOML"):
        load_settings(broken)
    wrong = tmp_path / "wrong.toml"
    wrong.write_text('edges = "none"')
    with pytest.raises(ValueError, match=r"\[edges\] must be a table"):
        load_settings(wrong)
    wrong.write_text('[edge_probability]\nHasSession = "often"')
    with pytest.raises(ValueError, match="HasSession must be a number"):
        load_settings(wrong)


def test_cli_reports_bad_input_without_a_traceback(tmp_path, capsys):
    base = ["run", "--backend", "demo", "--db-skip", "-q", "-d", str(tmp_path)]
    assert cli.main([*base, "-c", str(tmp_path / "missing.toml")]) == 2
    assert "Cannot read the config file" in capsys.readouterr().err
    bad = tmp_path / "bad.toml"
    bad.write_text('max_hops = "ten"')
    assert cli.main([*base, "-c", str(bad)]) == 2
    assert "max_hops must be a whole number" in capsys.readouterr().err
    assert cli.main([*base, "--dual-control-probability", "7"]) == 2
    assert "between 0 and 1" in capsys.readouterr().err
    for flags in (["-r", "0"], ["--concurrency", "0"], ["-r", "many"]):
        with pytest.raises(SystemExit) as exit_info:  # argparse usage error
            cli.main([*base, *flags])
        assert exit_info.value.code == 2


def test_cli_run_writes_every_format(tmp_path, capsys):
    args = ["run", "--backend", "demo", "--db", str(tmp_path / "h.db"), "-d", str(tmp_path)]
    assert cli.main([*args, "-o", "stdout", "-o", "json", "-o", "csv", "-o", "md", "-o", "html"]) == 0
    out = capsys.readouterr()
    assert "BUSIEST PATHS" in out.out and "First run for this tenant" in out.out
    assert sorted(p.suffix for p in tmp_path.iterdir() if p.suffix != ".db") == [
        ".csv",
        ".csv",
        ".csv",
        ".html",
        ".json",
        ".md",
    ]
    # The demo keeps nothing on disk unless asked to.
    assert not cli.DEFAULT_CHECKPOINT.exists()


async def test_weakest_links_tolerate_a_zero_limit():
    result, _ = await run_demo()
    assert goodhound_weakest_links(result.all_paths, 0) == []

    async def count_users(groups):
        return 0

    assert await probability_weakest_links(result.all_paths, 0, result.settings, 386, 10.0, count_users) == []


# ---------------------------------------------------------------- failures stay local


async def test_backoff_does_not_hold_a_query_slot(monkeypatch):
    import goodhound_enterprise.source as source_mod

    backing_off, release = asyncio.Event(), asyncio.Event()

    async def fake_sleep(_seconds):
        backing_off.set()
        await release.wait()

    class FlakyOnce(DemoExecutor):
        failed = False

        async def run(self, query):
            if "Domain" in query and not self.failed:
                self.failed = True
                raise RetryableQueryError("query_timed_out")
            return await super().run(query)

    monkeypatch.setattr(source_mod.asyncio, "sleep", fake_sleep)
    source = CypherGraphSource(FlakyOnce(), demo_settings(concurrency=1))
    slow = asyncio.ensure_future(source.domains())
    await backing_off.wait()
    # The only slot is free while the failed query waits to retry.
    assert await asyncio.wait_for(source.count_enabled_users(), 2) == 386
    release.set()
    assert [d.kind for d in await slow] == ["Domain"]


async def test_a_failing_user_is_skipped_not_fatal():
    graph = build_demo_graph()
    victim = next(n.objectid for n in graph.nodes.values() if n.kind == "User" and n.enabled and not n.tier_zero)

    class OneBadUser(DemoExecutor):
        async def run(self, query):
            if query.startswith("MATCH p=(s:User") and victim in query:
                raise RetryableQueryError("query_timed_out")
            return await super().run(query)

    result, _ = await run_demo(OneBadUser(graph), include_users=True, retries=1)
    assert result.skipped_start_nodes == [victim]
    assert [r.path.start.name for r in result.all_paths if r.start_label == "User"] == ["USER0007@CONTOSO.LOCAL"]
    assert dict(report._summary(result))["Start nodes skipped (query failed)"].startswith("1:")

    class Rejecting(DemoExecutor):
        async def run(self, query):
            if query.startswith("MATCH p=(s:User"):
                raise QueryError("rejected by the validator")
            return await super().run(query)

    with pytest.raises(QueryError, match="rejected"):  # a rejected query is a bug, not a slow user
        await run_demo(Rejecting(), include_users=True)


def test_path_limit_detection():
    def graph(paths):
        nodes = {"s": {"kind": "Group", "objectId": "S"}, "t": {"kind": "User", "objectId": "T", "isTierZero": True}}
        edges = []
        for i in range(paths):
            nodes[f"m{i}"] = {"kind": "Computer", "objectId": f"M{i}"}
            edges += [{"source": "s", "target": f"m{i}", "kind": "AdminTo"}]
            edges += [{"source": f"m{i}", "target": "t", "kind": "HasSession"}]
        return parse_graph({"data": {"nodes": nodes, "edges": edges}})

    assert not reaches_path_limit(graph(3), "S", 4)
    assert reaches_path_limit(graph(4), "S", 4)
    assert not reaches_path_limit(graph(4), "missing", 4)


async def test_results_at_the_row_limit_are_flagged():
    full, _ = await run_demo()
    assert full.possibly_truncated == []
    assert "Start nodes at the query row limit" not in dict(report._summary(full))

    cut, _ = await run_demo(paths_per_start=1)
    assert DOMAIN_USERS in cut.possibly_truncated
    assert dict(report._summary(cut))["Start nodes at the query row limit"].startswith(
        f"{len(cut.possibly_truncated)}:"
    )
    assert json.loads(report.to_json(cut))["possibly_truncated"] == cut.possibly_truncated


# ---------------------------------------------------------------- interrupted runs


class DiesAfter(DemoExecutor):
    """Fails for good after ``n`` path queries, like a tenant that goes away mid-run."""

    def __init__(self, n):
        super().__init__()
        self.left = n

    async def run(self, query):
        if "shortest" in query.lower():
            if self.left == 0:
                raise QueryError("connection lost for good")
            self.left -= 1
        return await super().run(query)


async def test_an_interrupted_run_resumes_from_its_checkpoint(tmp_path):
    path = tmp_path / "cp.db"
    fresh, fresh_executor = await run_demo()

    with pytest.raises(QueryError, match="connection lost"):
        await run_demo(DiesAfter(6), checkpoint=Checkpoint(path, "demo"), concurrency=1)
    assert os.stat(path).st_mode & 0o777 == 0o600

    checkpoint = Checkpoint(path, "demo", resume=True)
    assert checkpoint.available > 6
    resumed, executor = await run_demo(checkpoint=checkpoint)
    assert resumed.resumed_queries == checkpoint.available
    assert len(executor.log) == len(fresh_executor.log) - checkpoint.available  # only the rest was asked
    assert resumed.exposure == fresh.exposure
    assert [r.path.uid for r in resumed.all_paths] == [r.path.uid for r in fresh.all_paths]
    assert dict(report._summary(resumed))["Answers reused from the interrupted run"] == str(checkpoint.available)

    checkpoint.complete()
    assert not path.exists()


def test_checkpoint_scopes_and_ages(tmp_path):
    path = tmp_path / "cp.db"
    first = Checkpoint(path, "tenant-a")
    first.put("q1", {"data": 1})
    first.put("q2", None)  # an empty answer is still an answer
    first.put("q3", {"not": {1, 2}})  # not JSON: skipped
    first.close()

    other = Checkpoint(path, "tenant-b", resume=True)
    assert other.available == 0 and other.get("q1") is Checkpoint.MISSING
    other.put("q1", "b")
    other.complete()
    assert path.exists()  # tenant-a's answers are still in it

    again = Checkpoint(path, "tenant-a", resume=True)
    assert again.available == 2 and again.get("q1") == {"data": 1} and again.get("q2") is None
    assert again.get("q3") is Checkpoint.MISSING and again.hits == 2
    again.close()

    assert Checkpoint(path, "tenant-a", resume=True, max_age_hours=0).available == 0  # too old to trust
    stale = Checkpoint(path, "tenant-a")
    stale.put("q1", 1)
    stale.close()
    assert Checkpoint(path, "tenant-a").available == 0  # a new run without --resume starts afresh


def test_cli_checkpoint_is_removed_after_a_complete_run(tmp_path, capsys):
    path = tmp_path / "cp.db"
    base = ["run", "--backend", "demo", "--db-skip", "-o", "json", "-d", str(tmp_path), "--checkpoint", str(path)]
    assert cli.main(base) == 0
    assert not path.exists()
    assert cli.main([*base, "--resume"]) == 0
    assert "Nothing to resume" in capsys.readouterr().err
    assert cli.main([*base, "--resume", "--no-checkpoint"]) == 2


# ---------------------------------------------------------------- history


async def test_trend_is_flagged_when_the_settings_changed(tmp_path):
    db = tmp_path / "h.db"
    first, _ = await run_demo()
    history.record(first, db)

    same, _ = await run_demo(concurrency=2)  # throughput settings do not change the findings
    delta = history.record(same, db)
    assert delta.comparable and delta.previous_exposure == first.exposure

    stricter, _ = await run_demo(per_action_detection=0.5)
    delta = history.record(stricter, db)
    assert not delta.comparable and delta.previous_exposure is None
    stricter.history = delta.as_dict(stricter.total_paths)
    assert "settings changed" in dict(report._summary(stricter))["Trend"]
    assert "exposure change since last run" not in report.to_html(stricter)


async def test_a_changed_route_is_neither_new_nor_resolved(tmp_path):
    db = tmp_path / "h.db"
    first, _ = await run_demo()
    history.record(first, db)

    second, _ = await run_demo()
    row = next(r for r in second.all_paths if r.path.start.objectid == DOMAIN_USERS)
    # Same start node, another most likely route (as happens when a session ages).
    hops = (dataclasses.replace(row.path.hops[0], kind="CanPSRemote"), *row.path.hops[1:])
    row.path = AttackPath(row.path.start, hops, row.path.cost)
    delta = history.record(second, db)
    assert (delta.new_paths, delta.rerouted, delta.resolved) == (0, 1, [])
    second.history = delta.as_dict(second.total_paths)
    assert dict(report._summary(second))["Start nodes whose most likely path changed"] == "1"


# ---------------------------------------------------------------- reports


async def test_csv_cells_cannot_run_as_formulas(tmp_path):
    assert report._csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert report._csv_cell("@SUM(A1)") == "'@SUM(A1)" and report._csv_cell("-cmd") == "'-cmd"
    assert report._csv_cell("-1.5") == "-1.5" and report._csv_cell("DOMAIN USERS") == "DOMAIN USERS"

    graph = build_demo_graph()
    graph.by_oid[DOMAIN_USERS].name = "=cmd|' /C calc'!A0"  # whoever can rename an object controls this
    result, _ = await run_demo(DemoExecutor(graph))
    files = report.write_csv(result, tmp_path, "r")
    cells = [c for f in files for row in csv.reader(f.open(encoding="utf-8")) for c in row]
    assert any(c.startswith("'=cmd") for c in cells)
    assert not any(c.startswith(("=", "@", "+")) for c in cells)


# ---------------------------------------------------------------- fleet


async def test_one_failing_agent_does_not_lose_the_other_cards():
    source = CypherGraphSource(DemoExecutor(), demo_settings())
    gateway = Gateway(source, await analyse(source, tenant="demo"))

    class Flaky(FakeModel):
        async def create(self, **kwargs):
            if "Item: link-2" in str(kwargs["messages"][0]["content"]):
                raise RuntimeError("529 overloaded")
            return await super().create(**kwargs)

    fr = await run_fleet(gateway, Flaky(), FleetConfig(links=3, paths=1))
    errors = {c.task.item: c.run.error for c in fr.cards}
    assert errors["link-2"] == "RuntimeError: 529 overloaded"
    assert [item for item, error in errors.items() if error is None] == ["link-1", "link-3", "path-1"]
    assert fr.plan and len(fr.plan["actions"]) == 3 and fr.plan["caveats"] == ["link-2"]

    class LeadDown(FakeModel):
        async def create(self, **kwargs):
            if "Write the remediation plan" in str(kwargs["messages"][0]["content"]):
                raise RuntimeError("503")
            return await super().create(**kwargs)

    fr = await run_fleet(gateway, LeadDown(), FleetConfig(links=2, paths=0))
    assert len(fr.cards) == 2 and fr.plan is None and "lead agent failed" in fr.plan_error


async def test_gateway_turns_any_failure_into_a_tool_error():
    class Dropping(DemoExecutor):
        down = False

        async def run(self, query):
            if self.down:
                raise ConnectionError("session lost")
            return await super().run(query)

    executor = Dropping()
    source = CypherGraphSource(executor, demo_settings(), retries=1)
    gateway = Gateway(source, await analyse(source, tenant="demo"))
    executor.down = True
    text, is_error = await gateway.call("test", "get_object", {"objectid": DOMAIN_USERS})
    assert is_error and "session lost" in json.loads(text)["error"]
    assert gateway.audit[-1].ok is False


async def test_gateway_applies_dual_control_like_the_analysis():
    source = CypherGraphSource(DemoExecutor(), demo_settings(opengraph=["CyberArk"]))
    result = await analyse(source, tenant="demo")
    assert len(result.dual_control_keys) == result.dual_control_platforms == 1
    gateway = Gateway(source, result)
    args = {"start_objectid": MARKETING, "source_objectid": "x", "kind": "MemberOf", "target_objectid": "y"}
    text, is_error = await gateway.call("test", "path_without_link", args)
    assert not is_error
    reach = next(r.reach for r in result.all_paths if r.path.start.objectid == MARKETING)
    # 0.9 access x 5% detection x 0.25 for the approval: the same number as in the report.
    assert json.loads(text)["reach_probability_before"] == pytest.approx(reach, abs=1e-4)
    assert reach == pytest.approx(0.9 * D * 0.25)


# ---------------------------------------------------------------- token cache lock


async def test_token_lock_excludes_a_second_holder(tmp_path):
    storage = hunter.FileTokenStorage(tmp_path, "https://tenant.example/api/v2/hunter/mcp")
    fd = await storage.lock()
    other = os.open(storage.path.with_suffix(".lock"), os.O_RDWR)
    try:
        assert hunter._try_lock(other) is False
        storage.unlock(fd)
        assert hunter._try_lock(other) is True
    finally:
        hunter._release_lock(other)
        os.close(other)
