"""BloodHound Enterprise REST API backend (HMAC-signed API token).

Hunter MCP is in closed beta and uses interactive OAuth that expires after 90
days.  For unattended, scheduled runs (the way GoodHound is usually deployed)
the same queries can be sent to ``POST /api/v2/graphs/cypher`` with a
non-interactive API token.  The request signing follows the scheme in the
BloodHound API documentation.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any

from .base import QueryError

CYPHER_PATH = "/api/v2/graphs/cypher"
EMPTY: dict[str, Any] = {"data": {"nodes": {}, "edges": [], "literals": []}}


def sign_request(
    token_id: str,
    token_key: str,
    method: str,
    uri: str,
    body: bytes | None,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Headers for one signed BHE API request."""
    request_date = (now or dt.datetime.now().astimezone()).isoformat("T")
    digester = hmac.new(token_key.encode(), None, hashlib.sha256)
    digester.update(f"{method}{uri}".encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update(request_date[:13].encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    if body is not None:
        digester.update(body)
    return {
        "User-Agent": "goodhound-enterprise",
        "Authorization": f"bhesignature {token_id}",
        "RequestDate": request_date,
        "Signature": base64.b64encode(digester.digest()).decode(),
        "Content-Type": "application/json",
    }


class RestExecutor:
    name = "rest"

    def __init__(
        self,
        base_url: str,
        token_id: str,
        token_key: str,
        *,
        timeout: float = 60.0,
        http_client: Any = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        import httpx2

        if "://" not in base_url:
            base_url = f"https://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.token_id = token_id
        self.token_key = token_key
        self._clock = clock
        self._http = http_client or httpx2.AsyncClient(timeout=timeout)

    async def run(self, query: str) -> Any:
        body = json.dumps({"query": query, "include_properties": True}).encode()
        headers = sign_request(
            self.token_id, self.token_key, "POST", CYPHER_PATH, body, self._clock() if self._clock else None
        )
        resp = await self._http.post(self.base_url + CYPHER_PATH, content=body, headers=headers)
        if resp.status_code == 404:
            return EMPTY  # BloodHound answers "no results" with 404
        if resp.status_code == 429 or resp.status_code >= 500:
            raise RuntimeError(f"BHE API {resp.status_code}: {resp.text[:200]}")  # retried by the source
        if resp.status_code >= 400:
            raise QueryError(f"BHE API {resp.status_code}: {resp.text[:500]}\nQuery: {query}")
        return resp.json()

    async def aclose(self) -> None:
        await self._http.aclose()
