import asyncio
import os
import stat
import time
import urllib.request

from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from goodhound_enterprise.backends.hunter import BrowserCallback, FileTokenStorage, _oauth_provider


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
    provider = _oauth_provider(store.server_url, store, BrowserCallback(0, open_browser=False))
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
