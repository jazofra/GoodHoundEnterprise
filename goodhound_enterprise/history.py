"""SQLite history, extended from GoodHound's single ``paths`` table.

GoodHound only stored first/last seen per path, so it could report "new" paths
but not paths that had been *fixed*.  Recording every run lets us report new,
recurring and resolved paths, and trend the headline numbers over time.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analysis import AnalysisResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    total_enabled_users INTEGER NOT NULL,
    users_with_path INTEGER,
    total_paths INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS paths (
    tenant TEXT NOT NULL,
    uid TEXT NOT NULL,
    start_objectid TEXT NOT NULL,
    start_name TEXT NOT NULL,
    path_text TEXT NOT NULL,
    query TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (tenant, uid)
);
CREATE TABLE IF NOT EXISTS observations (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    uid TEXT NOT NULL,
    members INTEGER NOT NULL,
    percentage REAL NOT NULL,
    hops INTEGER NOT NULL,
    cost INTEGER NOT NULL,
    risk REAL NOT NULL,
    PRIMARY KEY (run_id, uid)
);
"""

# Columns added after the first release; older databases are upgraded in place.
MIGRATIONS = {
    "runs": {"exposure": "REAL", "risk_model": "TEXT", "settings_hash": "TEXT"},
    "observations": {"path_probability": "REAL", "reach": "REAL", "paths": "INTEGER"},
}


def _migrate(db: sqlite3.Connection) -> None:
    for table, columns in MIGRATIONS.items():
        existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        for name, sql_type in columns.items():
            if name not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")


@dataclass
class HistoryDelta:
    new_paths: int  # start nodes that had no path at the previous run
    seen_before: int
    resolved: list[tuple[str, str]]  # (start name, path text): start nodes with a path last run and none now
    previous_run_at: str | None
    previous_users_with_path: int | None
    previous_exposure: float | None = None
    #: Start nodes that had a path last run and still have one, by a different most likely route
    #: (for example because a session aged). Nothing was fixed and nothing new appeared.
    rerouted: int = 0
    #: False when the previous run used other analysis settings: its numbers are not a trend.
    comparable: bool = True

    def as_dict(self, total_paths: int) -> dict[str, Any]:
        return {
            "new_paths": self.new_paths,
            "seen_before": self.seen_before,
            "pct_seen_before": round(self.seen_before / total_paths * 100, 1) if total_paths else 0.0,
            "resolved_paths": len(self.resolved),
            "resolved": self.resolved,
            "rerouted_paths": self.rerouted,
            "previous_run_at": self.previous_run_at,
            "previous_users_with_path": self.previous_users_with_path,
            "previous_exposure": self.previous_exposure,
            "comparable": self.comparable,
        }


def _db_path(path: str | Path) -> Path:
    p = Path(path)
    return p / "goodhound-enterprise.db" if p.is_dir() else p


def record(result: AnalysisResult, path: str | Path) -> HistoryDelta:
    db = sqlite3.connect(_db_path(path))
    try:
        db.executescript(SCHEMA)
        _migrate(db)
        now = result.generated_at.isoformat(timespec="seconds")
        model = result.settings.risk_model
        settings_hash = result.settings.fingerprint()
        prev = db.execute(
            "SELECT id, generated_at, users_with_path, exposure, risk_model, settings_hash FROM runs "
            "WHERE tenant = ? ORDER BY id DESC LIMIT 1",
            (result.tenant,),
        ).fetchone()
        # uid -> start node of every path seen at the previous run.
        previous: dict[str, str] = {}
        if prev:
            previous = dict(
                db.execute(
                    "SELECT o.uid, p.start_objectid FROM observations o JOIN paths p ON p.uid = o.uid "
                    "WHERE o.run_id = ? AND p.tenant = ?",
                    (prev[0], result.tenant),
                ).fetchall()
            )
        previous_uids = set(previous)
        previous_starts = set(previous.values())

        cur = db.execute(
            "INSERT INTO runs (tenant, generated_at, total_enabled_users, users_with_path, total_paths, exposure, "
            "risk_model, settings_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.tenant,
                now,
                result.total_enabled_users,
                result.users_with_path,
                result.total_paths,
                result.exposure,
                model,
                settings_hash,
            ),
        )
        run_id = cur.lastrowid
        new = seen = rerouted = 0
        current: set[str] = set()
        current_starts: set[str] = set()
        for row in result.all_paths:
            uid = row.path.uid
            current.add(uid)
            current_starts.add(row.path.start.objectid)
            exists = db.execute("SELECT 1 FROM paths WHERE tenant = ? AND uid = ?", (result.tenant, uid)).fetchone()
            if uid not in previous_uids and row.path.start.objectid in previous_starts:
                rerouted += 1  # same start node, different most likely route
            elif not exists:
                new += 1
            if exists:
                seen += 1
                db.execute(
                    "UPDATE paths SET last_seen = ?, start_name = ?, path_text = ? WHERE tenant = ? AND uid = ?",
                    (now, row.path.start.display, row.path.text, result.tenant, uid),
                )
            else:
                db.execute(
                    "INSERT INTO paths VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        result.tenant,
                        uid,
                        row.path.start.objectid,
                        row.path.start.display,
                        row.path.text,
                        row.query,
                        now,
                        now,
                    ),
                )
            db.execute(
                "INSERT INTO observations (run_id, uid, members, percentage, hops, cost, risk, path_probability, "
                "reach, paths) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    uid,
                    row.members,
                    row.percentage,
                    row.path.length,
                    row.path.cost,
                    row.risk,
                    row.path.probability,
                    row.reach,
                    row.paths,
                ),
            )
        # A path whose start node was skipped this run (query failed) was not re-checked, so it is not resolved.
        skipped = set(result.skipped_start_nodes)
        unchecked = (
            {
                r[0]
                for r in db.execute(
                    "SELECT uid, start_objectid FROM paths WHERE tenant = ?", (result.tenant,)
                ).fetchall()
                if r[1] in skipped
            }
            if skipped
            else set()
        )
        # A start node that still has a path was not fixed, whichever route is now its most likely one.
        resolved_uids = {uid for uid in previous_uids - current - unchecked if previous[uid] not in current_starts}
        resolved: list[tuple[str, str]] = []
        for uid in sorted(resolved_uids):
            r = db.execute(
                "SELECT start_name, path_text FROM paths WHERE tenant = ? AND uid = ?", (result.tenant, uid)
            ).fetchone()
            if r:
                resolved.append((r[0], r[1]))
        db.commit()
        # Numbers are only a trend between runs with the same analysis settings. Databases written
        # before the settings were recorded fall back to comparing the risk model.
        comparable = not prev or (prev[5] == settings_hash if prev[5] else prev[4] == model)
        return HistoryDelta(
            new,
            seen,
            resolved,
            prev[1] if prev else None,
            prev[2] if prev else None,
            prev[3] if prev and comparable else None,
            rerouted,
            comparable,
        )
    finally:
        db.close()
