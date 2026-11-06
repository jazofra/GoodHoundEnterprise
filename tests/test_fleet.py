"""Fleet tests. No real model is called: a scripted fake client drives the agent loop, and one test runs
the real Anthropic SDK against a mocked HTTP transport to check the request bodies it actually sends."""

import json
import re
from types import SimpleNamespace

import pytest

from goodhound_enterprise import cli
from goodhound_enterprise.analysis import analyse
from goodhound_enterprise.backends.demo import DOMAIN_SID, DemoExecutor
from goodhound_enterprise.config import Settings
from goodhound_enterprise.fleet import FleetConfig, run_fleet
from goodhound_enterprise.fleet import report as fleet_report
from goodhound_enterprise.fleet.agent import FALLBACK_BETA, AgentConfig, TokenBudget, run_agent
from goodhound_enterprise.fleet.gateway import MAX_RESULT_CHARS, Gateway
from goodhound_enterprise.fleet.orchestrator import plan_tasks
from goodhound_enterprise.fleet.prompts import CARD_SCHEMA, PLAN_SCHEMA
from goodhound_enterprise.source import CypherGraphSource


def sid(rid: str) -> str:
    return f"{DOMAIN_SID}-{rid}"


SQL01, APP01, JSMITH, KLEE = sid("1302"), sid("1303"), sid("1105"), sid("1106")
DEVELOPERS, IT_SUPPORT, WS_ADMINS, WS01 = sid("1205"), sid("1202"), sid("1209"), sid("1301")


@pytest.fixture
async def gateway():
    source = CypherGraphSource(DemoExecutor(), Settings(rate_limit=0))
    result = await analyse(source, tenant="demo")
    return Gateway(source, result)


async def call(gw, tool_name, **args):
    text, is_error = await gw.call("test", tool_name, args)
    return json.loads(text), is_error


# ---------------------------------------------------------------- gateway


async def test_gateway_tools_answer_from_the_graph(gateway):
    out, err = await call(
        gateway, "relationship_exists", source_objectid=SQL01, kind="HasSession", target_objectid=JSMITH
    )
    assert not err and out["exists"] and out["last_seen"]
    out, _ = await call(gateway, "relationship_exists", source_objectid=SQL01, kind="HasSession", target_objectid=KLEE)
    assert not out["exists"]

    out, _ = await call(gateway, "get_object", objectid=SQL01)
    assert out["kind"] == "Computer" and "DBA team" in out["properties"]["description"]

    out, _ = await call(gateway, "inbound_control", objectid=SQL01)
    assert {r["name"] for r in out["controllers"]} == {"SQL ADMINS@CONTOSO.LOCAL", "SERVER ADMINS@CONTOSO.LOCAL"}

    out, _ = await call(gateway, "group_members", objectid=DEVELOPERS)
    assert out["enabled_non_tier_zero_users_including_nested"] == 68
    assert any(r["name"] == "CONTRACTORS@CONTOSO.LOCAL" for r in out["direct_members_sample"])

    out, _ = await call(gateway, "outbound_rights", objectid=APP01)
    assert out["relationships"][0]["relationship"] == "HasSession"

    out, _ = await call(gateway, "paths_using_link", source_objectid=SQL01, kind="HasSession", target_objectid=JSMITH)
    assert out["count"] == 4


async def test_path_without_link_shows_what_remains(gateway):
    out, _ = await call(
        gateway,
        "path_without_link",
        start_objectid=IT_SUPPORT,
        source_objectid=WS_ADMINS,
        kind="AdminTo",
        target_objectid=WS01,
    )
    assert "SERVER ADMINS" in out["remaining_path"] and out["hops"] == 3
    assert out["searched"] == "all shortest paths"
    out, _ = await call(
        gateway,
        "path_without_link",
        start_objectid=DEVELOPERS,
        source_objectid=SQL01,
        kind="HasSession",
        target_objectid=JSMITH,
    )
    assert out["remaining_path"] is None


async def test_gateway_guard_rails_and_audit(gateway):
    out, err = await call(gateway, "run_cypher", query="MATCH (n) DETACH DELETE n RETURN n LIMIT 1")
    assert err and "read-only" in out["error"]
    out, err = await call(gateway, "run_cypher", query="MATCH (n {objectid: '" + SQL01 + "'}) RETURN n LIMIT 1")
    assert not err and out["total_nodes"] == 1
    out, err = await call(gateway, "call_bloodhound_tool", tool="x", arguments_json="{}")
    assert err and "hunter backend" in out["error"]
    out, err = await call(gateway, "no_such_tool")
    assert err
    assert len(gateway.audit) == 4 and [a.ok for a in gateway.audit] == [False, True, False, False]


async def test_tool_results_are_truncated(gateway):
    async def huge(_args):
        return {"blob": "x" * (MAX_RESULT_CHARS * 2)}

    gateway.tools["get_object"].handler = huge
    text, _ = await gateway.call("t", "get_object", {"objectid": SQL01})
    assert len(text) < MAX_RESULT_CHARS + 100 and text.endswith("[truncated: narrow the request]")


def test_tool_schemas_are_strict(gateway):
    for param in gateway.tool_params():
        schema = param["input_schema"]
        assert param["strict"] is True and schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])


# ---------------------------------------------------------------- fake model


def block(type_, **kw):
    return SimpleNamespace(type=type_, **kw)


def message(content, stop_reason, **extra):
    usage = SimpleNamespace(
        input_tokens=1000, output_tokens=200, cache_read_input_tokens=500, cache_creation_input_tokens=100
    )
    return SimpleNamespace(content=content, stop_reason=stop_reason, usage=usage, **extra)


class FakeModel:
    """Investigates like a (very literal) analyst: one tool call, then a card based on its result."""

    def __init__(self, *, lie_about=(), refuse=(), non_json=()):
        self.requests: list[dict] = []
        self.lie_about, self.refuse, self.non_json = set(lie_about), set(refuse), set(non_json)
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        messages = kwargs["messages"]
        task = messages[0]["content"]
        if kwargs["output_config"]["format"]["schema"] is PLAN_SCHEMA:
            doc = json.loads(task.split("\n\n", 1)[1])
            plan = {
                "executive_summary": f"{doc['analysis']['percent_with_a_path']}% of users have a path.",
                "actions": [
                    {
                        "priority": i + 1,
                        "title": c["subject"],
                        "change": c["card"]["recommended_change"],
                        "owner": c["card"]["likely_owner"],
                        "impact": "see card",
                        "operational_risk": "low",
                        "based_on": [c["item"]],
                    }
                    for i, c in enumerate(doc["cards"])
                    if "card" in c
                ],
                "caveats": [c["item"] for c in doc["cards"] if c.get("verified") is False or "error" in c],
            }
            return message([block("text", text=json.dumps(plan))], "end_turn")
        item = re.search(r"Item: (\S+)", task).group(1)
        if item in self.refuse:
            return message([], "refusal", stop_details=SimpleNamespace(category="cyber"))
        if len(messages) == 1:
            ids = re.findall(r"\[(S-1-5-21-[\d-]+)\] -(\w+)-> [^\[]+\[(S-1-5-21-[\d-]+)\]", task)[0]
            use = block(
                "tool_use",
                id=f"toolu_{item}",
                name="relationship_exists",
                input={"source_objectid": ids[0], "kind": ids[1], "target_objectid": ids[2]},
            )
            return message([block("thinking", thinking="", signature="sig"), use], "tool_use")
        if item in self.non_json:
            return message([block("text", text="I think it is fine.")], "end_turn")
        result = json.loads(messages[-1]["content"][0]["content"])
        exists = result["exists"] and item not in self.lie_about
        card = {
            "item": item,
            "still_exists": exists,
            "verdict": "fix_now" if exists else "already_fixed",
            "headline": f"Cut {item}",
            "analysis": "From the tool result.",
            "evidence": [f"relationship_exists: {result['exists']}"],
            "likely_owner": "IT Operations",
            "recommended_change": "Remove it.",
            "change_risk": "Low.",
            "residual_risk": "None seen.",
            "bhe_finding": "",
            "confidence": "high",
        }
        return message([block("text", text=json.dumps(card))], "end_turn")


async def test_fleet_end_to_end_with_fake_model(gateway):
    model = FakeModel()
    cfg = FleetConfig(links=3, paths=2, concurrency=3)
    fr = await run_fleet(gateway, model, cfg)
    assert [c.task.item for c in fr.cards] == ["link-1", "link-2", "link-3", "path-1", "path-2"]
    assert all(c.verified for c in fr.cards)
    assert fr.plan and len(fr.plan["actions"]) == 5 and not fr.plan_error
    assert fr.budget.by_model["claude-sonnet-5-5"]["input"] == 10 * 1000  # 2 turns x 5 agents
    assert fr.budget.by_model["claude-opus-5-5"]["output"] == 200

    worker_req = model.requests[0]
    assert worker_req["model"] == "claude-sonnet-5-5"
    assert worker_req["output_config"]["effort"] == "medium"
    assert worker_req["output_config"]["format"]["schema"] is CARD_SCHEMA
    assert worker_req["cache_control"] == {"type": "ephemeral"}
    assert worker_req["fallbacks"] == "default" and worker_req["betas"] == [FALLBACK_BETA]
    assert all(t["strict"] for t in worker_req["tools"])
    lead_req = model.requests[-1]
    assert lead_req["model"] == "claude-opus-5-5" and "tools" not in lead_req


async def test_loop_is_append_only(gateway):
    model = FakeModel()
    await run_fleet(gateway, model, FleetConfig(links=1, paths=0))
    first, second = model.requests[0]["messages"], model.requests[1]["messages"]
    assert second[: len(first)] == first
    assistant = second[1]
    assert assistant["role"] == "assistant" and assistant["content"][0].type == "thinking"  # passed back as-is
    assert second[2]["content"][0]["tool_use_id"] == "toolu_link-1"


async def test_code_verification_catches_a_wrong_claim(gateway):
    fr = await run_fleet(gateway, FakeModel(lie_about={"link-2"}), FleetConfig(links=2, paths=0))
    by_item = {c.task.item: c for c in fr.cards}
    assert by_item["link-1"].verified is True
    assert by_item["link-2"].verified is False and "still in BloodHound" in by_item["link-2"].verification_note
    assert "link-2" in fr.plan["caveats"]


async def test_refusals_and_bad_answers_do_not_sink_the_run(gateway):
    fr = await run_fleet(gateway, FakeModel(refuse={"link-1"}, non_json={"link-2"}), FleetConfig(links=3, paths=0))
    by_item = {c.task.item: c for c in fr.cards}
    assert "declined" in by_item["link-1"].run.error and "cyber" in by_item["link-1"].run.error
    assert "not JSON" in by_item["link-2"].run.error
    assert by_item["link-3"].verified and fr.plan


async def test_token_budget_stops_new_work(gateway):
    fr = await run_fleet(gateway, FakeModel(), FleetConfig(links=3, paths=2, concurrency=1, token_budget=1))
    assert len(fr.cards) == 1 and fr.cards[0].run.error == "token budget exhausted"
    assert len(fr.skipped) == 4 and fr.plan is None


async def test_haiku_gets_no_fallbacks_param(gateway):
    model = FakeModel()
    budget = TokenBudget(10**9)
    task = plan_tasks(gateway.result, FleetConfig(links=1, paths=0))[0]
    await run_agent(
        model,
        gateway,
        name="x",
        system="s",
        task=task.prompt,
        schema=CARD_SCHEMA,
        cfg=AgentConfig("claude-haiku-5-5"),
        budget=budget,
    )
    assert "fallbacks" not in model.requests[0] and "betas" not in model.requests[0]


async def test_fleet_reports_render_and_escape(gateway, tmp_path):
    fr = await run_fleet(gateway, FakeModel(), FleetConfig(links=2, paths=1))
    fr.cards[0].run.output["headline"] = "<script>alert(1)</script>"
    files = fleet_report.write(fr, tmp_path)
    assert {f.suffix for f in files} == {".md", ".json", ".html"}
    html_text = next(f for f in files if f.suffix == ".html").read_text()
    assert "<script>alert(1)</script>" not in html_text and "&lt;script&gt;" in html_text
    doc = json.loads(next(f for f in files if f.suffix == ".json").read_text())
    assert doc["plan"]["actions"] and doc["audit"]


def test_cli_dry_run_calls_no_model(tmp_path, capsys):
    rc = cli.main(
        [
            "fleet",
            "--backend",
            "demo",
            "--db-skip",
            "--dry-run",
            "--links",
            "2",
            "--paths",
            "1",
            "-d",
            str(tmp_path),
            "-q",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0 and out.count("Produce the remediation card") == 3


# ---------------------------------------------------------------- real SDK, mocked HTTP


async def test_real_sdk_request_shape(gateway):
    import httpx2
    from anthropic import AsyncAnthropic, DefaultAsyncHttpxClient

    seen: list[tuple[dict, dict]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        seen.append((dict(request.headers), body))
        base = {
            "id": f"msg_{len(seen)}",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "stop_sequence": None,
            "usage": {
                "input_tokens": 50,
                "output_tokens": 10,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 40,
            },
        }
        if len(seen) == 1:
            return httpx2.Response(
                200,
                json={
                    **base,
                    "stop_reason": "tool_use",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "relationship_exists",
                            "input": {"source_objectid": SQL01, "kind": "HasSession", "target_objectid": JSMITH},
                        }
                    ],
                },
            )
        card = {k: "" for k in CARD_SCHEMA["required"]} | {
            "item": "link-1",
            "still_exists": True,
            "verdict": "fix_now",
            "evidence": [],
            "confidence": "high",
        }
        return httpx2.Response(
            200, json={**base, "stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(card)}]}
        )

    client = AsyncAnthropic(
        api_key="test-key", http_client=DefaultAsyncHttpxClient(transport=httpx2.MockTransport(handler))
    )
    task = plan_tasks(gateway.result, FleetConfig(links=1, paths=0))[0]
    run = await run_agent(
        client,
        gateway,
        name="link-1",
        system="sys",
        task=task.prompt,
        schema=CARD_SCHEMA,
        cfg=AgentConfig("claude-sonnet-5-5"),
        budget=TokenBudget(10**9),
    )
    assert run.output["verdict"] == "fix_now" and run.tool_calls == 1 and not run.error

    headers, body = seen[0]
    assert FALLBACK_BETA in headers["anthropic-beta"]
    assert body["fallbacks"] == "default" and body["cache_control"] == {"type": "ephemeral"}
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert all(t["strict"] for t in body["tools"])
    second = seen[1][1]["messages"]
    assert second[1]["role"] == "assistant" and second[1]["content"][0]["type"] == "tool_use"
    tool_result = second[2]["content"][0]
    assert tool_result["type"] == "tool_result" and json.loads(tool_result["content"])["exists"] is True


async def test_typed_hunter_tools_passthrough():
    from mcp import Client

    from goodhound_enterprise.backends.hunter import HunterExecutor
    from tests.test_hunter_mcp import fake_hunter

    srv, _ = fake_hunter()
    async with Client(srv) as client:
        hunter = HunterExecutor(client)
        await hunter.setup()
        source = CypherGraphSource(hunter, Settings(rate_limit=0))
        gw = Gateway(source, await analyse(source, tenant="fake"), hunter)
        out, err = await call(gw, "list_bloodhound_tools")
        names = {t["name"] for t in out["tools"]}
        assert not err and names == {"bloodhound_status", "bloodhound_list_findings"}  # cypher tool hidden
        out, err = await call(gw, "call_bloodhound_tool", tool="bloodhound_status", arguments_json="{}")
        assert not err and out["connected"] is True
        out, err = await call(gw, "call_bloodhound_tool", tool="bloodhound_cypher", arguments_json="{}")
        assert err and "run_cypher" in out["error"]
