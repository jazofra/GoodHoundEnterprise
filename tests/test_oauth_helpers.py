import asyncio
import os
import stat
import time
import urllib.request

from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from goodhound_enterprise.backends.hunter import BrowserCallback, FileTokenStorage, _oauth_provider


async def _no_discovery(url):
    return None, None


async def test_token_storage_roundtrip_and_permissions(tmp_path):
    store = FileTokenStorage(tmp_path / "tokens", "https://t.example/api/v2/hunter/mcp")
    assert await store.get_tokens() is None
    await store.set_tokens(OAuthToken(access_token="a", expires_in=3600, refresh_token="r"))
    await store.set_client_info(
        OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:8765/callback"])
    )
    again = FileTokenStorage(tmp_path / "tokens", "https://t.example/api/v2/hunter/mcp")
    assert (await again.get_tokens()).refresh_token == "r"
    assert (await again.get_client_info()).client_id == "cid"
    assert 3500 < again.expires_at - time.time() <= 3600
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    store.clear()
    assert await again.get_tokens() is None


async def test_reloaded_expired_token_is_marked_invalid_so_it_gets_refreshed(tmp_path):
    store = FileTokenStorage(tmp_path, "https://t.example/api/v2/hunter/mcp")
    await store.set_tokens(OAuthToken(access_token="old", expires_in=1, refresh_token="r"))
    await store.set_client_info(
        OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:8765/callback"])
    )
    data = store._load()
    data["expires_at"] = time.time() - 10
    store._save(data)
    provider = _oauth_provider(store.server_url, store, BrowserCallback(0, open_browser=False), _no_discovery)
    await provider._initialize()
    assert provider.context.current_tokens.access_token == "old"
    assert not provider.context.is_token_valid()
    assert provider.context.can_refresh_token()


async def test_loopback_callback_receives_the_code():
    with __import__("socket").socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cb = BrowserCallback(port, open_browser=False)
    await cb.redirect_handler("https://t.example/authorize?x=1")
    waiter = asyncio.create_task(cb.callback_handler())
    await asyncio.to_thread(urllib.request.urlopen, f"http://127.0.0.1:{port}/callback?code=abc&state=xyz", timeout=5)
    result = await asyncio.wait_for(waiter, 5)
    assert (result.code, result.state) == ("abc", "xyz")


TENANT = "https://t.example"
MCP_URL = TENANT + "/api/v2/hunter/mcp"
TOKEN_ENDPOINT = TENANT + "/api/v2/hunter/oauth/token"


def _metadata_transport():
    import httpx2

    def handler(request):
        if request.url.path == "/.well-known/oauth-protected-resource/api/v2/hunter/mcp":
            return httpx2.Response(200, json={"resource": MCP_URL, "authorization_servers": [TENANT]})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx2.Response(
                200,
                json={
                    "issuer": TENANT,
                    "authorization_endpoint": TENANT + "/api/v2/hunter/oauth/authorize",
                    "token_endpoint": TOKEN_ENDPOINT,
                    "registration_endpoint": TENANT + "/api/v2/hunter/oauth/register",
                    "response_types_supported": ["code"],
                },
            )
        return httpx2.Response(404)

    return httpx2.MockTransport(handler)


async def _expired_store(tmp_path):
    store = FileTokenStorage(tmp_path, MCP_URL)
    await store.set_tokens(OAuthToken(access_token="old", expires_in=3600, refresh_token="r1"))
    await store.set_client_info(
        OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:8765/callback"])
    )
    data = store._load()
    data["expires_at"] = time.time() - 10
    store._save(data)
    return store


async def test_discovers_the_advertised_token_endpoint():
    from goodhound_enterprise.backends.hunter import discover_oauth_metadata

    prm, asm = await discover_oauth_metadata(MCP_URL, transport=_metadata_transport())
    assert str(prm.resource) == MCP_URL
    assert str(asm.token_endpoint) == TOKEN_ENDPOINT


async def test_cached_token_refreshes_at_the_discovered_endpoint(tmp_path):
    import httpx2

    from goodhound_enterprise.backends.hunter import discover_oauth_metadata

    async def discover(url):
        return await discover_oauth_metadata(url, transport=_metadata_transport())

    store = await _expired_store(tmp_path)
    provider = _oauth_provider(MCP_URL, store, BrowserCallback(0, open_browser=False), discover)
    flow = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    first = await flow.__anext__()
    await flow.aclose()
    # Without discovery the SDK would POST the refresh to https://t.example/token (404 on Hunter).
    assert str(first.url) == TOKEN_ENDPOINT
    assert b"grant_type=refresh_token" in first.content


async def test_adopts_tokens_another_process_refreshed(tmp_path):
    import httpx2

    store = await _expired_store(tmp_path)
    provider = _oauth_provider(MCP_URL, store, BrowserCallback(0, open_browser=False), _no_discovery)
    await provider._initialize()
    assert not provider.context.is_token_valid()

    # Another process sharing the cache refreshed meanwhile; Hunter rotated the refresh token.
    other = FileTokenStorage(tmp_path, MCP_URL)
    await other.set_tokens(OAuthToken(access_token="fresh", expires_in=3600, refresh_token="r2"))

    flow = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    first = await flow.__anext__()
    await flow.aclose()
    assert str(first.url) == MCP_URL  # no refresh with the stale, rotated-out refresh token
    assert first.headers["Authorization"] == "Bearer fresh"


async def test_cancelled_lock_waiter_does_not_leak_the_lock(tmp_path):
    store = FileTokenStorage(tmp_path, MCP_URL)
    held = await store.lock()
    waiter = asyncio.create_task(store.lock())
    await asyncio.sleep(0.1)
    waiter.cancel()
    with __import__("contextlib").suppress(asyncio.CancelledError):
        await waiter
    store.unlock(held)
    again = await asyncio.wait_for(store.lock(), timeout=2)
    store.unlock(again)


async def test_requests_with_a_valid_token_are_not_serialised(tmp_path):
    import httpx2

    store = FileTokenStorage(tmp_path, MCP_URL)
    await store.set_tokens(OAuthToken(access_token="ok", expires_in=3600, refresh_token="r"))
    await store.set_client_info(
        OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:8765/callback"])
    )
    provider = _oauth_provider(MCP_URL, store, BrowserCallback(0, open_browser=False), _no_discovery)
    warm = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    await warm.__anext__()
    await warm.aclose()

    # Two requests in flight at once: the SDK's own flow would block the second on its lock.
    first = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    second = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    a = await asyncio.wait_for(first.__anext__(), timeout=1)
    b = await asyncio.wait_for(second.__anext__(), timeout=1)
    assert a.headers["Authorization"] == b.headers["Authorization"] == "Bearer ok"
    for flow in (first, second):
        with __import__("pytest").raises(StopAsyncIteration):
            await flow.asend(httpx2.Response(200))


async def test_rejected_valid_token_falls_back_to_the_full_flow(tmp_path):
    import httpx2

    from goodhound_enterprise.backends.hunter import discover_oauth_metadata

    async def discover(url):
        return await discover_oauth_metadata(url, transport=_metadata_transport())

    store = FileTokenStorage(tmp_path, MCP_URL)
    await store.set_tokens(OAuthToken(access_token="revoked", expires_in=3600, refresh_token="r"))
    await store.set_client_info(
        OAuthClientInformationFull(client_id="cid", redirect_uris=["http://127.0.0.1:8765/callback"])
    )
    provider = _oauth_provider(MCP_URL, store, BrowserCallback(0, open_browser=False), discover)
    await provider._initialize()
    flow = provider._auth_flow(httpx2.Request("POST", MCP_URL))
    sent = await flow.__anext__()
    assert sent.headers["Authorization"] == "Bearer revoked"
    resent = await flow.asend(httpx2.Response(401))
    # The SDK flow takes over and resends (and would re-authorize on another 401).
    assert str(resent.url) == MCP_URL
    await flow.aclose()
