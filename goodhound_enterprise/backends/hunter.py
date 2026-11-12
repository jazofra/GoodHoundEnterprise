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
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .base import QueryError, RetryableQueryError

log = logging.getLogger(__name__)


def _try_lock(fd: int) -> bool:
    """Take an exclusive lock on ``fd`` without blocking; False if another process holds it."""
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined,unused-ignore]
        except OSError:
            return False
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _release_lock(fd: int) -> None:
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined,unused-ignore]
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


# JSON-RPC code the MCP SDK uses when the session's connection has gone away.
MCP_CONNECTION_CLOSED = -32000

HUNTER_PATH = "/api/v2/hunter/mcp"
GRAPH_CAPABILITIES_URI = "hunter://graph/capabilities"
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
        tmp = self.path.with_suffix(f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)

    async def lock(self) -> int:
        """Wait until this process holds the cache's refresh lock (shared by every process using it).

        Polls a non-blocking lock on the event loop rather than blocking a worker
        thread: a cancelled waiter must never end up holding the lock.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            while not _try_lock(fd):
                await asyncio.sleep(0.05)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def unlock(fd: int) -> None:
        try:
            _release_lock(fd)
        finally:
            os.close(fd)

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

    def save_metadata(self, prm: Any, asm: Any) -> None:
        data = self._load()
        data["oauth_metadata"] = asm.model_dump(mode="json") if asm is not None else None
        data["protected_resource_metadata"] = prm.model_dump(mode="json") if prm is not None else None
        self._save(data)

    def load_metadata(self) -> tuple[Any, Any]:
        from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata

        data = self._load()
        try:
            asm = OAuthMetadata.model_validate(data["oauth_metadata"]) if data.get("oauth_metadata") else None
            raw_prm = data.get("protected_resource_metadata")
            prm = ProtectedResourceMetadata.model_validate(raw_prm) if raw_prm else None
        except ValueError:
            return None, None
        return prm, asm

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


async def discover_oauth_metadata(server_url: str, *, transport: Any = None) -> tuple[Any, Any]:
    """Fetch the protected-resource (RFC 9728) and authorization-server (RFC 8414) metadata.

    The MCP SDK only discovers these after a 401. When valid tokens are loaded from
    the cache there is no 401, so a later refresh would go to ``<origin>/token``
    instead of the advertised token endpoint (Hunter's lives under
    ``/api/v2/hunter/oauth/token``) and fail with 404, forcing a new browser approval.
    """
    import httpx2
    from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata

    parsed = urlparse(server_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    async with httpx2.AsyncClient(timeout=30.0, transport=transport) as http:
        prm = None
        for candidate in (
            f"{origin}/.well-known/oauth-protected-resource{parsed.path}",
            f"{origin}/.well-known/oauth-protected-resource",
        ):
            response = await http.get(candidate)
            if response.status_code == 200:
                prm = ProtectedResourceMetadata.model_validate_json(response.content)
                break
        issuer = str(prm.authorization_servers[0]).rstrip("/") if prm and prm.authorization_servers else origin
        iparsed = urlparse(issuer)
        iorigin, ipath = f"{iparsed.scheme}://{iparsed.netloc}", iparsed.path.rstrip("/")
        for candidate in (
            f"{iorigin}/.well-known/oauth-authorization-server{ipath}",
            f"{iorigin}/.well-known/openid-configuration{ipath}",
            f"{issuer}/.well-known/openid-configuration",
        ):
            response = await http.get(candidate)
            if response.status_code == 200:
                return prm, OAuthMetadata.model_validate_json(response.content)
    return prm, None


def _oauth_provider(url: str, storage: FileTokenStorage, callback: BrowserCallback, discover: Any = None):
    from mcp.client.auth import OAuthClientProvider
    from mcp.shared.auth import OAuthClientMetadata

    _discover = discover or discover_oauth_metadata

    class Provider(OAuthClientProvider):
        async def _initialize(self) -> None:
            await super()._initialize()
            # The SDK forgets the expiry of tokens reloaded from storage; restore
            # it so expired access tokens are refreshed instead of re-prompting.
            expires_at = storage.expires_at
            if self.context.current_tokens is not None and expires_at is not None:
                self.context.token_expiry_time = expires_at
            # Refreshing needs the real token endpoint, which the SDK has not discovered yet.
            if self.context.current_tokens is not None and self.context.oauth_metadata is None:
                prm, asm = await self._discover_or_cached()
                if prm is not None:
                    self.context.protected_resource_metadata = prm
                if asm is not None:
                    self.context.oauth_metadata = asm

        async def _discover_or_cached(self) -> tuple[Any, Any]:
            """Discover the metadata, retrying briefly; fall back to the last copy that worked.

            Right after the machine wakes the network may not be up yet. Without the
            metadata the SDK refreshes at ``<origin>/token`` (404) and asks for a new
            browser approval, so a transient failure must not drop the endpoint.
            """
            for attempt in range(3):
                try:
                    prm, asm = await _discover(url)
                except Exception as exc:
                    log.warning("OAuth metadata discovery failed (%s); attempt %d of 3", exc, attempt + 1)
                else:
                    if asm is not None:
                        storage.save_metadata(prm, asm)
                        return prm, asm
                if attempt < 2:
                    await asyncio.sleep(2 ** (attempt + 1))
            prm, asm = storage.load_metadata()
            if asm is not None:
                log.warning("Using the cached OAuth metadata (token endpoint %s)", asm.token_endpoint)
            else:
                log.warning("No OAuth metadata: refreshing may fail and require a new approval")
            return prm, asm

        async def _adopt_stored_tokens(self) -> None:
            """Use tokens another process saved after ours: Hunter rotates refresh tokens on use."""
            stored = await storage.get_tokens()
            expires_at = storage.expires_at
            current = self.context.current_tokens
            if (
                stored is not None
                and expires_at is not None
                and expires_at > time.time()
                and (current is None or stored.access_token != current.access_token)
            ):
                self.context.current_tokens = stored
                self.context.token_expiry_time = expires_at

        async def _auth_flow(self, request):
            if self._initialized and self.context.is_token_valid():
                # The SDK's flow holds context.lock for the whole request, which serialises every
                # concurrent MCP call in the process. A valid token needs no coordination: attach
                # it and send, and only fall back to the SDK flow if the server rejects it.
                from mcp.shared.inbound import MCP_PROTOCOL_VERSION_HEADER

                self.context.protocol_version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)
                self._add_auth_header(request)
                response = yield request
                if response.status_code not in (401, 403):
                    return
            fd = await storage.lock()
            try:
                if self._initialized:
                    await self._adopt_stored_tokens()
                flow = super()._auth_flow(request)
                try:
                    outgoing = await flow.__anext__()
                    while True:
                        if fd is not None and outgoing.url == request.url:
                            # Any refresh is done and saved: release before the (possibly long) MCP call.
                            storage.unlock(fd)
                            fd = None
                        response = yield outgoing
                        outgoing = await flow.asend(response)
                except StopAsyncIteration:
                    pass
                finally:
                    await flow.aclose()
            finally:
                if fd is not None:
                    storage.unlock(fd)

    metadata = OAuthClientMetadata(
        client_name="GoodHound Enterprise",
        redirect_uris=[callback.redirect_uri],  # type: ignore[list-item]  # validated into AnyUrl
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


async def _list_tools_page(client: Any, *, cursor: str | None) -> Any:
    return await client.list_tools(cursor=cursor)


class HunterSessionLost(ConnectionError):
    """The MCP session died (dropped connection, server reset...) while a call was in flight."""


class _Session:
    """One MCP session hosted in its own task.

    The MCP SDK runs each streamable-HTTP POST in a task group tied to the
    ``Client`` context. A dropped connection (``httpx.ReadError``) fails that task
    group and cancels whatever task entered the context, so per-query retries
    never run and the whole analysis dies. Hosting the session in a dedicated task
    confines that failure to the session; callers get :class:`HunterSessionLost`
    and can reconnect.
    """

    def __init__(self, open_client: Callable[[], AbstractAsyncContextManager[Any]]) -> None:
        self._open = open_client
        self.client: Any = None
        self.error: BaseException | None = None
        self.dead = asyncio.Event()
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        await self._ready.wait()
        if self.client is None:
            raise HunterSessionLost(f"Could not open a Hunter MCP session: {self.error!r}") from self.error

    async def _run(self) -> None:
        try:
            async with self._open() as client:
                self.client = client
                self._ready.set()
                await self._stop.wait()
        except Exception as exc:  # includes the transport's ExceptionGroup
            self.error = exc
            if not self._stop.is_set():
                log.debug("Hunter MCP session ended with an error", exc_info=exc)
        finally:
            self.dead.set()
            self._ready.set()

    async def call(self, fn: Callable[[Any], Awaitable[Any]]) -> Any:
        if self.dead.is_set() or self._stop.is_set():
            raise HunterSessionLost(f"Hunter MCP session lost: {self.error!r}")
        call = asyncio.ensure_future(fn(self.client))
        dead = asyncio.ensure_future(self.dead.wait())
        try:
            done, _ = await asyncio.wait({call, dead}, return_when=asyncio.FIRST_COMPLETED)
        except BaseException:
            call.cancel()
            raise
        finally:
            dead.cancel()
        if call in done:
            exc = call.exception()
            if getattr(getattr(exc, "error", None), "code", None) == MCP_CONNECTION_CLOSED:
                self.error = exc
                self._stop.set()
                raise HunterSessionLost(f"Hunter MCP session lost: {exc!r}") from exc
            return call.result()
        call.cancel()
        raise HunterSessionLost(f"Hunter MCP session lost: {self.error!r}")

    @property
    def usable(self) -> bool:
        return not (self.dead.is_set() or self._stop.is_set())

    async def close(self) -> None:
        self._stop.set()
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)


class HunterExecutor:
    name = "hunter"
    max_reconnects = 5

    def __init__(
        self,
        client: Any = None,
        *,
        cypher_tool: str | None = None,
        cypher_arg: str | None = None,
        extra_args: Mapping[str, Any] | None = None,
        session_factory: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
    ) -> None:
        if client is None and session_factory is None:
            raise ValueError("HunterExecutor needs a client or a session_factory")
        self._client = client
        self._factory = session_factory
        self._session: _Session | None = None
        self._session_lock = asyncio.Lock()
        self.reconnects = 0
        self._tool_override = cypher_tool
        self._arg_override = cypher_arg
        self._extra = dict(extra_args or {})
        self.tool_name: str | None = None
        self.query_arg: str | None = None
        self.tools: list[Any] = []

    @property
    def client(self) -> Any:
        if self._factory is None:
            return self._client
        return self._session.client if self._session is not None else None

    async def _current_session(self) -> _Session:
        async with self._session_lock:
            if self._session is None or not self._session.usable:
                if self._session is not None:
                    await self._session.close()
                    self._session = None
                    self.reconnects += 1
                session = _Session(self._factory)  # type: ignore[arg-type]
                await session.start()
                self._session = session
            return self._session

    async def _call(self, fn: Callable[[Any], Awaitable[Any]]) -> Any:
        """Run ``fn(client)``, reconnecting with the cached OAuth tokens if the session drops."""
        if self._factory is None:
            return await fn(self._client)
        for attempt in range(self.max_reconnects + 1):
            try:
                session = await self._current_session()
                return await session.call(fn)
            except HunterSessionLost as exc:
                if attempt == self.max_reconnects:
                    raise
                delay = min(2 ** (attempt + 1), 30)
                log.warning("%s; reconnecting in %ss", exc, delay)
                await asyncio.sleep(delay)
        raise AssertionError("unreachable")

    async def list_tools(self) -> list[Any]:
        tools: list[Any] = []
        cursor = None
        while True:
            page = await self._call(partial(_list_tools_page, cursor=cursor))
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
        tool, arguments = self.tool_name, {**self._extra, self.query_arg: query}
        result = await self._call(lambda c: c.call_tool(tool, arguments))
        payload = _result_payload(result)
        if result.is_error:
            problem = payload.get("problem") if isinstance(payload, dict) else None
            error = (
                RetryableQueryError if isinstance(problem, dict) and problem.get("retryable") is True else QueryError
            )
            raise error(f"Hunter rejected the query: {json.dumps(payload)[:500]}\nQuery: {query}")
        return payload

    async def describe(self) -> dict[str, Any]:
        """Tool/prompt catalogue plus the bloodhound_status result, for `discover`."""
        tools = self.tools or await self.list_tools()
        out: dict[str, Any] = {
            "tools": [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools],
        }
        try:
            prompts = await self._call(lambda c: c.list_prompts())
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
            status = await self._call(lambda c: c.call_tool("bloodhound_status", {}))
            out["bloodhound_status"] = _result_payload(status)
        try:
            out["selected_cypher_tool"] = dict(zip(("tool", "argument", "extra"), pick_cypher_tool(tools), strict=True))
        except QueryError as exc:
            out["selected_cypher_tool"] = str(exc)
        return out

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Any:
        """Call any Hunter tool, surviving dropped sessions like :meth:`run` does."""
        return await self._call(lambda c: c.call_tool(name, dict(arguments)))

    async def relationship_catalog(self) -> dict[str, bool] | None:
        """Relationship kinds the tenant knows and whether each is traversable (None if unavailable)."""
        try:
            result = await self._call(lambda c: c.read_resource(GRAPH_CAPABILITIES_URI))
            text = "".join(getattr(part, "text", "") or "" for part in result.contents)
            kinds = json.loads(text).get("relationship_kinds") or []
            return {str(k["name"]): bool(k.get("traversable")) for k in kinds if k.get("name")}
        except Exception as exc:
            log.warning("Could not read %s: %s", GRAPH_CAPABILITIES_URI, exc)
            return None

    async def aclose(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

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

        @asynccontextmanager
        async def open_client() -> AsyncIterator[Any]:
            auth = _oauth_provider(url, storage, callback)
            async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(30.0, read=300.0)) as http:
                transport = streamable_http_client(url, http_client=http)
                async with Client(transport, read_timeout_seconds=timeout) as client:
                    yield client

        executor = cls(
            cypher_tool=cypher_tool, cypher_arg=cypher_arg, extra_args=extra_args, session_factory=open_client
        )
        try:
            await executor._current_session()
            yield executor
        finally:
            await executor.aclose()
