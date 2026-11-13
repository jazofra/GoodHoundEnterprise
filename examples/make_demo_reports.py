"""Regenerate the sample reports in examples/demo-report/ from the built-in demo tenant.

    python examples/make_demo_reports.py

Two runs against the demo data: a baseline, then a second run after removing Domain
Users' RDP right. The clock is fixed, so session ageing (and with it every number)
is the same whenever this is run.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import goodhound_enterprise.analysis as analysis
from goodhound_enterprise import history, report
from goodhound_enterprise.backends.demo import DOMAIN_SID, DemoExecutor, build_demo_graph
from goodhound_enterprise.config import Settings
from goodhound_enterprise.source import CypherGraphSource

OUT = Path(__file__).parent / "demo-report"
RUN_AT = datetime(2026, 11, 6, 18, 42, 59, tzinfo=UTC)  # a day after the demo's sessions were last seen
TENANT = "demo (CONTOSO.LOCAL)"


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return RUN_AT


async def run(graph, db: Path, stem: str) -> None:
    source = CypherGraphSource(DemoExecutor(graph), Settings(rate_limit=0))
    result = await analysis.analyse(source, tenant=TENANT)
    result.history = history.record(result, db).as_dict(result.total_paths)
    for suffix, render in (("md", report.to_markdown), ("html", report.to_html), ("json", report.to_json)):
        (OUT / f"{stem}.{suffix}").write_text(render(result), encoding="utf-8")
    print(f"{stem}: exposure {result.exposure}%, {result.total_paths} start nodes with a path")


async def main() -> None:
    analysis.datetime = FixedClock  # type: ignore[attr-defined,misc]
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "history.db"
        await run(build_demo_graph(), db, "1-baseline")
        fixed = build_demo_graph()
        domain_users = fixed.by_oid[f"{DOMAIN_SID}-513"]
        fixed.out[domain_users.id] = [e for e in fixed.out[domain_users.id] if e[0] != "CanRDP"]
        await run(fixed, db, "2-after-fix")


if __name__ == "__main__":
    asyncio.run(main())
