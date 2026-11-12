"""Answers already received in a run, kept on disk so an interrupted run can resume.

A large tenant needs one query per group, which can take hours. Every answer is
stored here as it arrives; ``--resume`` then serves the queries the interrupted run
had already asked from this file and only sends the rest. The settings that shape a
run (hops, relationship kinds, target) are part of the query text, and the risk model
is applied on the client, so the query itself is the cache key.

The file holds graph data from the tenant: it is created with mode 0600 and emptied
when a run completes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_MAX_AGE_HOURS = 24.0
_MISSING = object()


class Checkpoint:
    #: Returned by :meth:`get` when a query has no stored answer (``None`` is a valid answer).
    MISSING: object = _MISSING

    def __init__(
        self, path: str | Path, scope: str, *, resume: bool = False, max_age_hours: float = DEFAULT_MAX_AGE_HOURS
    ) -> None:
        self.path = Path(path)
        self.scope = scope
        self.hits = 0
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        self._db: sqlite3.Connection | None = sqlite3.connect(self.path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS answers (scope TEXT NOT NULL, query TEXT NOT NULL, result TEXT NOT NULL, "
            "created REAL NOT NULL, PRIMARY KEY (scope, query))"
        )
        if resume:
            # Older answers describe a tenant that may have changed since.
            self._db.execute(
                "DELETE FROM answers WHERE scope = ? AND created < ?", (scope, time.time() - max_age_hours * 3600)
            )
        else:
            self._db.execute("DELETE FROM answers WHERE scope = ?", (scope,))
        self._db.commit()
        self.available = self._db.execute("SELECT count(*) FROM answers WHERE scope = ?", (scope,)).fetchone()[0]

    @staticmethod
    def _key(query: str) -> str:
        return hashlib.sha256(query.encode()).hexdigest()

    def get(self, query: str) -> Any:
        """The stored answer to ``query``, or ``Checkpoint.MISSING``."""
        if self._db is None or not self.available:
            return _MISSING
        row = self._db.execute(
            "SELECT result FROM answers WHERE scope = ? AND query = ?", (self.scope, self._key(query))
        ).fetchone()
        if row is None:
            return _MISSING
        self.hits += 1
        return json.loads(row[0])

    def put(self, query: str, result: Any) -> None:
        if self._db is None:
            return
        try:
            text = json.dumps(result)
        except (TypeError, ValueError):
            return  # not JSON: this answer is simply asked again after a restart
        self._db.execute(
            "INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?)", (self.scope, self._key(query), text, time.time())
        )
        self._db.commit()

    def complete(self) -> None:
        """The run finished: drop its answers, and the file once no other run uses it."""
        if self._db is None:
            return
        self._db.execute("DELETE FROM answers WHERE scope = ?", (self.scope,))
        self._db.commit()
        empty = self._db.execute("SELECT count(*) FROM answers").fetchone()[0] == 0
        self.close()
        if empty:
            self.path.unlink(missing_ok=True)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
