"""BloodHound Hunter MCP backend.

Hunter is a remote, read-only MCP server exposed by a BloodHound Enterprise
tenant at ``https://<tenant>/api/v2/hunter/mcp`` (closed beta at the time of
writing).  It speaks streamable HTTP and authenticates with OAuth 2.0
Authorization Code + PKCE using dynamic client registration, so no API token
is needed: the first run opens a browser, the user approves the
"Requesting client" in BloodHound, and the tokens are cached on disk.

SpecterOps has not published Hunter's tool catalogue, so the Cypher tool is
*discovered* at run time (any tool whose name contains "cypher"), and both the
tool name and its query argument can be overridden on the command line.
``goodhound-enterprise discover`` dumps the full catalogue to help with that.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sys
import threading
import time
import webbrowser
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .base import QueryError

log = logging.getLogger(__name__)

HUNTER_PATH = "/api/v2/hunter/mcp"
PREFERRED_TOOL_NAMES = ("bloodhound_cypher", "run_cypher", "cypher_query", "cypher", "execute_cypher")
QUERY_ARG_NAMES = ("query", "cypher", "cypher_query", "statement")


def hunter_url(url_or_host: str) -> str:
    """Accept a bare tenant host/URL and return the Hunter MCP endpoint."""
    url = url_or_host if "://" in url_or_host else f"https://{url_or_host}"
    parsed = urlparse(url)
    if parsed.path in ("", "/"):
        url = url.rstrip("/") + HUNTER_PATH
    return url


# --------------------------------------------------------------------------
# OAuth plumbing
# --------------------------------------------------------------------------


def default_token_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "goodhound-enterprise" / "tokens"


class FileTokenStorage:
    """Persists OAuth tokens and the dynamically registered client (mode 0600)."""

    def __init__(self, directory: Path, server_url: str) -> None:
        self.path = directory / (hashlib.sha256(server_url.encode()).hexdigest()[:24] + ".json")
        self.server_url = server_url

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)

    @property
    def expires_at(self) -> float | None:
        return self._load().get("expires_at")

    async def get_tokens(self):
        from mcp.shared.auth import OAuthToken

        raw = self._load().get("tokens")
        return OAuthToken.model_validate(raw) if raw else None

    async def set_tokens(self, tokens) -> None:
        data = self._load()
        data["server_url"] = self.server_url
        data["tokens"] = tokens.model_dump(mode="json")
        data["expires_at"] = time.time() + tokens.expires_in if tokens.expires_in else None
        self._save(data)

    async def get_client_info(self):
        from mcp.shared.auth import OAuthClientInformationFull

        raw = self._load().get("client_info")
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def set_client_info(self, client_info) -> None:
        data = self._load()
        data["client_info"] = client_info.model_dump(mode="json")
        self._save(data)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class BrowserCallback:
    """Handles the authorization redirect, via a loopback listener or by pasting the URL."""

    def __init__(self, port: int, *, open_browser: bool = True, manual: bool = False) -> None:
        self.port = port
        self.open_browser = open_browser
        self.manual = manual
        self._server: HTTPServer | None = None
        self._result: dict[str, str] = {}
        self._done = threading.Event()

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.port}/callback"

    def _start_listener(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                query = parse_qs(urlparse(self.path).query)
                if "code" in query or "error" in query:
                    outer._result = {k: v[0] for k, v in query.items()}
                    outer._done.set()
                    body = b"GoodHound Enterprise: authorization received. You can close this tab."
                    self.send_response(200)
                else:
                    body = b"Waiting for the BloodHound authorization redirect..."
                    self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    async def redirect_handler(self, authorization_url: str) -> None:
        if not self.manual and self._server is None:
            self._start_listener()
        print(
            "\nApprove GoodHound Enterprise in BloodHound (Hunter MCP > 'Approve Hunter Access'):\n"
            f"  {authorization_url}\n",
            file=sys.stderr,
        )
        if self.open_browser:
            webbrowser.open(authorization_url)

    async def callback_handler(self):
        from mcp.shared.auth import AuthorizationCodeResult

        if self.manual:
            pasted = await asyncio.to_thread(
                input, "Paste the full URL your browser was redirected to (it may show an error page): "
            )
            self._result = {k: v[0] for k, v in parse_qs(urlparse(pasted.strip()).query).items()}
        else:
            ok = await asyncio.to_thread(self._done.wait, 600)
            if self._server:
                self._server.shutdown()
                self._server.server_close()
                self._server = None
            if not ok:
                raise QueryError("Timed out waiting for the OAuth redirect")
        if "error" in self._result:
            raise QueryError(f"Authorization failed: {self._result.get('error_description') or self._result['error']}")
        return AuthorizationCodeResult(
            code=self._result["code"], state=self._result.get("state"), iss=self._result.get("iss")
        )


def _oauth_provider(url: str, storage: FileTokenStorage, callback: BrowserCallback):
    from mcp.client.auth import OAuthClientProvider
    from mcp.shared.auth import OAuthClientMetadata

    class Provider(OAuthClientProvider):
        async def _initialize(self) -> None:
            await super()._initialize()
            # The SDK forgets the expiry of tokens reloaded from storage; restore
            # it so expired access tokens are refreshed instead of re-prompting.
            expires_at = storage.expires_at
            if self.context.current_tokens is not None and expires_at is not None:
                self.context.token_expiry_time = expires_at

    metadata = OAuthClientMetadata(
        client_name="GoodHound Enterprise",
        redirect_uris=[callback.redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )
    return Provider(
        server_url=url,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=callback.redirect_handler,
        callback_handler=callback.callback_handler,
    )


# --------------------------------------------------------------------------
# Executor
# --------------------------------------------------------------------------


def _schema_props(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict((schema or {}).get("properties") or {})


def pick_cypher_tool(tools: list[Any], name: str | None = None, arg: str | None = None) -> tuple[str, str, dict]:
    """Choose the Cypher tool and its query argument from a tools/list result."""
    by_name = {t.name: t for t in tools}
    if name:
        if name not in by_name:
            raise QueryError(f"Tool {name!r} not found. Available: {', '.join(sorted(by_name))}")
        tool = by_name[name]
    else:
        candidates = [t for t in tools if "cypher" in t.name.lower()]
        candidates.sort(
            key=lambda t: (
                PREFERRED_TOOL_NAMES.index(t.name) if t.name in PREFERRED_TOOL_NAMES else len(PREFERRED_TOOL_NAMES),
                t.name,
            )
        )
        if not candidates:
            raise QueryError(
                "No Cypher tool found on the MCP server (is raw Cypher disabled for your role/ETAC?). "
                f"Available tools: {', '.join(sorted(by_name)) or 'none'}. Use --cypher-tool to choose one."
            )
        tool = candidates[0]
    props = _schema_props(tool.input_schema)
    if arg is None:
        arg = next((a for a in QUERY_ARG_NAMES if a in props), None)
    if arg is None:
        required = [
            r for r in (tool.input_schema or {}).get("required", []) if props.get(r, {}).get("type") == "string"
        ]
        if len(required) == 1:
            arg = required[0]
    if arg is None:
        raise QueryError(f"Cannot tell which argument of {tool.name!r} takes the query; use --cypher-arg")
    extras: dict[str, Any] = {}
    if props.get("include_properties", {}).get("type") == "boolean":
        extras["include_properties"] = True
    return tool.name, arg, extras


def _result_payload(result: Any) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    texts = [getattr(block, "text", "") for block in result.content or []]
    joined = "\n".join(t for t in texts if t)
    try:
        return json.loads(joined)
    except ValueError:
        return {"text": joined}


class HunterExecutor:
    name = "hunter"

    def __init__(
        self,
        client: Any,
        *,
        cypher_tool: str | None = None,
        cypher_arg: str | None = None,
        extra_args: Mapping[str, Any] | None = None,
    ) -> None:
        self.client = client
        self._tool_override = cypher_tool
        self._arg_override = cypher_arg
        self._extra = dict(extra_args or {})
        self.tool_name: str | None = None
        self.query_arg: str | None = None
        self.tools: list[Any] = []

    async def list_tools(self) -> list[Any]:
        tools: list[Any] = []
        cursor = None
        while True:
            page = await self.client.list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor = getattr(page, "next_cursor", None)
            if not cursor:
                return tools

    async def setup(self) -> None:
        self.tools = await self.list_tools()
        self.tool_name, self.query_arg, auto = pick_cypher_tool(self.tools, self._tool_override, self._arg_override)
        self._extra = {**auto, **self._extra}
        log.info("Using Hunter tool %s(%s=...)", self.tool_name, self.query_arg)

    async def run(self, query: str) -> Any:
        if self.tool_name is None:
            await self.setup()
        assert self.tool_name and self.query_arg
        result = await self.client.call_tool(self.tool_name, {**self._extra, self.query_arg: query})
        payload = _result_payload(result)
        if result.is_error:
            raise QueryError(f"Hunter rejected the query: {json.dumps(payload)[:500]}\nQuery: {query}")
        return payload

    async def describe(self) -> dict[str, Any]:
        """Tool/prompt catalogue plus the bloodhound_status result, for `discover`."""
        tools = self.tools or await self.list_tools()
        out: dict[str, Any] = {
            "tools": [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools],
        }
        try:
            prompts = await self.client.list_prompts()
            out["prompts"] = [
                {
                    "name": p.name,
                    "description": p.description,
                    "arguments": [a.model_dump(mode="json") for a in (p.arguments or [])],
                }
                for p in prompts.prompts
            ]
        except Exception as exc:  # prompts are optional
            out["prompts_error"] = str(exc)
        if any(t.name == "bloodhound_status" for t in tools):
            status = await self.client.call_tool("bloodhound_status", {})
            out["bloodhound_status"] = _result_payload(status)
        try:
            out["selected_cypher_tool"] = dict(zip(("tool", "argument", "extra"), pick_cypher_tool(tools), strict=True))
        except QueryError as exc:
            out["selected_cypher_tool"] = str(exc)
        return out

    async def aclose(self) -> None:
        pass

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        url: str,
        *,
        token_dir: Path | None = None,
        callback_port: int = 8765,
        open_browser: bool = True,
        manual_callback: bool = False,
        cypher_tool: str | None = None,
        cypher_arg: str | None = None,
        extra_args: Mapping[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> AsyncIterator[HunterExecutor]:
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client

        url = hunter_url(url)
        storage = FileTokenStorage(token_dir or default_token_dir(), url)
        callback = BrowserCallback(callback_port, open_browser=open_browser, manual=manual_callback)
        auth = _oauth_provider(url, storage, callback)
        async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(30.0, read=300.0)) as http:
            transport = streamable_http_client(url, http_client=http)
            async with Client(transport, read_timeout_seconds=timeout) as client:
                executor = cls(client, cypher_tool=cypher_tool, cypher_arg=cypher_arg, extra_args=extra_args)
                yield executor
