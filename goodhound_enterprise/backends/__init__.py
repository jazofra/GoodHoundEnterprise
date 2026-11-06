"""Ways of running read-only Cypher against BloodHound Enterprise.

* ``hunter`` - the Hunter MCP server (remote streamable HTTP + OAuth 2.0/PKCE).
* ``rest``   - the classic BHE REST API with an API token (HMAC signed).
* ``demo``   - an in-memory synthetic environment for trying the tool and for tests.
"""

from .base import CypherExecutor, QueryError

__all__ = ["CypherExecutor", "QueryError"]
