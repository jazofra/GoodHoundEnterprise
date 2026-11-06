"""End-to-end through a real MCP client/server pair (in-process).

The fake server mimics what is publicly known about Hunter: a
``bloodhound_status`` tool, a ``bloodhound-top-findings`` prompt, a Cypher tool
that enforces the documented guard-rails, and unified-graph results.
"""

import datetime as dt
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from goodhound_enterprise.analysis import analyse
from goodhound_enterprise.backends.base import QueryError
from goodhound_enterprise.backends.demo import DemoExecutor
from goodhound_enterprise.backends.hunter import HunterExecutor, hunter_url, pick_cypher_tool
from goodhound_enterprise.backends.rest import RestExecutor, sign_request
from goodhound_enterprise.config import Settings
from goodhound_enterprise.cypher import UnsafeQueryError, assert_hunter_safe
from goodhound_enterprise.source import CypherGraphSource


def fake_hunter() -> tuple[MCPServer, DemoExecutor]:
    demo = DemoExecutor()
    srv = MCPServer("fake-hunter")

    @srv.tool()
    def bloodhound_status() -> dict[str, Any]:
        """Connection and tenant status."""
        return {"connected": True, "tenant": "demo"}

    @srv.tool()
    def bloodhound_list_findings(environment_id: str = "") -> dict[str, Any]:
        """A typed tool (not used by GoodHound Enterprise)."""
        return {"findings": []}

    @srv.tool()
    async def bloodhound_cypher(query: str, include_properties: bool = False) -> dict[str, Any]:
        """Run a bounded, read-only Cypher query (fallback)."""
        try:
            assert_hunter_safe(query)
        except UnsafeQueryError as exc:
            raise ValueError(str(exc)) from exc
        return await demo.run(query)

    @srv.prompt(name="bloodhound-top-findings")
    def top_findings() -> str:
        return "Summarise the top findings"

    return srv, demo


async def test_full_run_over_mcp():
    srv, demo = fake_hunter()
    async with Client(srv) as client:
        executor = HunterExecutor(client)
        await executor.setup()
        assert (executor.tool_name, executor.query_arg) == ("bloodhound_cypher", "query")
        source = CypherGraphSource(executor, Settings(rate_limit=0, concurrency=8))
        result = await analyse(source, tenant="fake")
    assert result.busiest[0].path.start.name == "DOMAIN USERS@CONTOSO.LOCAL"
    assert result.total_paths == 9
    assert result.queries_sent == len(demo.log)


async def test_server_side_rejection_surfaces_as_query_error():
    srv, _ = fake_hunter()
    async with Client(srv) as client:
        executor = HunterExecutor(client)
        with pytest.raises(QueryError, match="Hunter rejected"):
            await executor.run("MATCH (n) RETURN n")  # no LIMIT


async def test_describe_lists_tools_prompts_and_status():
    srv, _ = fake_hunter()
    async with Client(srv) as client:
        catalogue = await HunterExecutor(client).describe()
    assert {t["name"] for t in catalogue["tools"]} >= {"bloodhound_status", "bloodhound_cypher"}
    assert catalogue["prompts"][0]["name"] == "bloodhound-top-findings"
    assert catalogue["bloodhound_status"]["connected"] is True
    assert catalogue["selected_cypher_tool"]["tool"] == "bloodhound_cypher"
    assert catalogue["selected_cypher_tool"]["extra"] == {"include_properties": True}


class T:
    def __init__(self, name, props, required=()):
        self.name = name
        self.input_schema = {"properties": {p: {"type": t} for p, t in props.items()}, "required": list(required)}


def test_pick_cypher_tool_variants():
    # Community bloodhound_mcp style: cypher_query(info_type, query)
    tools = [T("user_info", {"user_id": "string"}), T("cypher_query", {"info_type": "string", "query": "string"})]
    assert pick_cypher_tool(tools)[:2] == ("cypher_query", "query")
    # Unknown argument name but a single required string
    assert pick_cypher_tool([T("hunter_cypher", {"cql": "string"}, ["cql"])])[:2] == ("hunter_cypher", "cql")
    # Explicit override
    assert pick_cypher_tool(tools, "cypher_query", "info_type")[:2] == ("cypher_query", "info_type")
    with pytest.raises(QueryError, match="No Cypher tool"):
        pick_cypher_tool([T("user_info", {"user_id": "string"})])


def test_hunter_url():
    assert hunter_url("acme.bloodhoundenterprise.io") == "https://acme.bloodhoundenterprise.io/api/v2/hunter/mcp"
    assert hunter_url("https://acme.example/") == "https://acme.example/api/v2/hunter/mcp"
    assert hunter_url("https://acme.example/custom/mcp") == "https://acme.example/custom/mcp"


def test_rest_signature_is_deterministic():
    when = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
    a = sign_request("id", "key", "POST", "/api/v2/graphs/cypher", b"{}", when)
    b = sign_request("id", "key", "POST", "/api/v2/graphs/cypher", b"{}", when)
    c = sign_request("id", "key", "POST", "/api/v2/graphs/cypher", b"{ }", when)
    assert a == b and a["Signature"] != c["Signature"]
    assert a["Authorization"] == "bhesignature id" and a["RequestDate"].startswith("2026-01-02T03")


async def test_rest_executor_handles_404_as_empty_and_4xx_as_error():
    import httpx2

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "bhesignature tid"
        if b"EMPTY" in request.content:
            return httpx2.Response(404, json={"errors": []})
        if b"BAD" in request.content:
            return httpx2.Response(400, json={"errors": [{"message": "syntax"}]})
        return httpx2.Response(200, json={"data": {"nodes": {}, "edges": [], "literals": [{"key": "n", "value": 1}]}})

    http = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    ex = RestExecutor("tenant.example", "tid", "tkey", http_client=http)
    assert (await ex.run("RETURN 1 AS n LIMIT 1"))["data"]["literals"][0]["value"] == 1
    assert (await ex.run("EMPTY LIMIT 1"))["data"]["nodes"] == {}
    with pytest.raises(QueryError, match="400"):
        await ex.run("BAD LIMIT 1")
    await ex.aclose()


@pytest.fixture
def http_hunter():
    """The fake Hunter served over real streamable HTTP at /api/v2/hunter/mcp."""
    import socket
    import threading
    import time

    import uvicorn

    srv, demo = fake_hunter()
    app = srv.streamable_http_app(streamable_http_path="/api/v2/hunter/mcp")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", demo
    server.should_exit = True
    thread.join(timeout=10)


async def test_connect_over_streamable_http(http_hunter, tmp_path):
    url, demo = http_hunter
    async with HunterExecutor.connect(url, token_dir=tmp_path, open_browser=False) as executor:
        await executor.setup()
        source = CypherGraphSource(executor, Settings(rate_limit=0))
        result = await analyse(source, tenant="http")
    assert result.busiest[0].path.start.name == "DOMAIN USERS@CONTOSO.LOCAL"
    assert len(demo.log) == result.queries_sent
