"""Report writers: stdout, markdown, csv, html and json."""

from __future__ import annotations

import csv
import html
import json
from collections.abc import Sequence
from pathlib import Path

from .analysis import AnalysisResult

FORMATS = ("stdout", "md", "csv", "html", "json")


def _summary(r: AnalysisResult) -> list[tuple[str, str]]:
    users = (
        "n/a"
        if r.users_with_path is None
        else f"{r.users_with_path}{' (est.)' if r.users_with_path_is_estimate else ''}"
    )
    rows = [
        ("Tenant", r.tenant),
        ("Generated (UTC)", r.generated_at.strftime("%Y-%m-%d %H:%M")),
        ("Domains", ", ".join(d.display for d in r.domains) or "n/a"),
        ("Enabled non-Tier Zero users", str(r.total_enabled_users)),
        ("Non-Tier Zero users with a path", users),
        ("% of enabled non-Tier Zero users with a path", f"{r.percentage_with_path}%"),
        ("Start nodes with a path (total paths)", str(r.total_paths)),
    ]
    h = r.history
    if h and not h.get("previous_run_at"):
        rows.append(("History", "First run for this tenant: baseline recorded"))
    elif h:
        rows += [
            ("Previous run", str(h["previous_run_at"])),
            ("New paths since last run", str(h.get("new_paths", 0))),
            ("% of paths seen before", f"{h.get('pct_seen_before', 0.0)}%"),
            ("Paths no longer seen", str(h.get("resolved_paths", 0))),
        ]
    rows.append(("Queries sent", str(r.queries_sent)))
    return rows


BUSY_HEADERS = ["#", "Starting Node", "Users with Path", "% of Users", "Hops", "Exploit Cost", "Risk Score", "Path"]
WEAK_HEADERS = ["#", "Weakest Link", "Paths", "% of Paths", "Users Exposed (sum)", "Suggested Action"]


def _busy_rows(r: AnalysisResult) -> list[list[str]]:
    return [
        [
            str(i),
            p.path.start.display,
            str(p.members),
            f"{p.percentage}%",
            str(p.path.length),
            str(p.path.cost),
            str(p.risk),
            p.path.text,
        ]
        for i, p in enumerate(r.busiest, 1)
    ]


def _weak_rows(r: AnalysisResult) -> list[list[str]]:
    return [
        [str(i), w.text, str(w.paths), f"{w.percentage}%", str(w.users_exposed), w.hint]
        for i, w in enumerate(r.weakest, 1)
    ]


# --------------------------------------------------------------------------
# Text formats
# --------------------------------------------------------------------------


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], max_col: int = 70) -> str:
    def clip(s: str) -> str:
        return s if len(s) <= max_col else s[: max_col - 1] + "…"

    rows = [[clip(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(row[i]) for row in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)) for row in rows]
    return "\n".join(out)


def to_stdout(r: AnalysisResult) -> str:
    parts = ["GRAND TOTALS", _table(["Metric", "Value"], [list(x) for x in _summary(r)])]
    parts += ["", "BUSIEST PATHS", _table(BUSY_HEADERS, _busy_rows(r)) if r.busiest else "No paths to Tier Zero."]
    parts += ["", "THE WEAKEST LINKS", _table(WEAK_HEADERS, _weak_rows(r)) if r.weakest else "None."]
    return "\n".join(parts)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def to_markdown(r: AnalysisResult) -> str:
    parts = ["# GoodHound Enterprise report", "", "## Grand totals", _md_table(["Metric", "Value"], _summary(r))]
    parts += ["", "## Busiest paths", _md_table(BUSY_HEADERS, _busy_rows(r))]
    parts += ["", "### Queries to view these paths", ""]
    parts += [f"{i}. `{p.query}`" for i, p in enumerate(r.busiest, 1)]
    parts += ["", "## The weakest links", _md_table(WEAK_HEADERS, _weak_rows(r))]
    resolved = r.history.get("resolved") if r.history else None
    if resolved:
        parts += ["", "## Paths no longer seen since the previous run", ""]
        parts += [f"- **{_md_escape(start)}**: {_md_escape(text)}" for start, text in resolved]
    return "\n".join(parts) + "\n"


def to_json(r: AnalysisResult) -> str:
    def path_dict(p) -> dict:
        return {
            "uid": p.path.uid,
            "start": {"name": p.path.start.display, "objectid": p.path.start.objectid, "kind": p.start_label},
            "members": p.members,
            "percentage": p.percentage,
            "hops": p.path.length,
            "cost": p.path.cost,
            "risk": p.risk,
            "path": p.path.text,
            "edges": [
                {
                    "source": h.source.objectid,
                    "kind": h.kind,
                    "target": h.target.objectid,
                    "target_name": h.target.display,
                }
                for h in p.path.hops
            ],
            "query": p.query,
        }

    doc = {
        "tenant": r.tenant,
        "generated_at": r.generated_at.isoformat(),
        "summary": dict(_summary(r)),
        "settings": {
            "target_label": r.settings.target_label,
            "max_hops": r.settings.max_hops,
            "domain_sid": r.settings.domain_sid,
            "max_path_cost": r.settings.max_path_cost,
        },
        "busiest_paths": [path_dict(p) for p in r.busiest],
        "weakest_links": [
            {
                "link": w.text,
                "source": w.hop.source.objectid,
                "kind": w.hop.kind,
                "target": w.hop.target.objectid,
                "paths": w.paths,
                "percentage": w.percentage,
                "users_exposed": w.users_exposed,
                "hint": w.hint,
                "query": w.query,
            }
            for w in r.weakest
        ],
        "all_paths": [path_dict(p) for p in r.all_paths],
        "history": r.history,
    }
    return json.dumps(doc, indent=2, default=str)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_CSS = """
:root{--bg:#f7f7f8;--card:#fff;--ink:#1d1d22;--muted:#5d5d6b;--line:#e3e3e8;--accent:#c2410c;--chip:#f1f1f4}
@media (prefers-color-scheme:dark){:root{--bg:#141418;--card:#1d1d23;--ink:#ececf1;--muted:#a0a0ad;--line:#2e2e37;--accent:#fb923c;--chip:#26262e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.kpi b{display:block;font-size:24px}
.kpi span{color:var(--muted);font-size:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}td.n{text-align:right;font-variant-numeric:tabular-nums}
.path{font-size:12.5px}.edge{display:inline-block;background:var(--chip);border-radius:4px;padding:0 5px;margin:0 3px;color:var(--accent);font-weight:600}
details{margin-top:4px}summary{cursor:pointer;color:var(--muted);font-size:12px}code{font-size:11.5px;word-break:break-all}
.note{color:var(--muted);font-size:12px;margin-top:8px}
table.summary th{width:45%;white-space:normal}table.summary td{overflow-wrap:anywhere}
"""


def _html_path(r_path) -> str:
    parts = [f"<strong>{html.escape(r_path.start.display)}</strong>"]
    for hop in r_path.hops:
        parts.append(f'<span class="edge">{html.escape(hop.kind)}</span>{html.escape(hop.target.display)}')
    return " ".join(parts)


def to_html(r: AnalysisResult) -> str:
    e = html.escape
    kpi = [
        (str(r.users_with_path if r.users_with_path is not None else "n/a"), "non-Tier Zero users with a path"),
        (f"{r.percentage_with_path}%", "of enabled non-Tier Zero users"),
        (str(r.total_paths), "start nodes with a path"),
    ]
    if r.history and r.history.get("previous_run_at"):
        kpi.append((str(r.history.get("new_paths", 0)), "new paths since last run"))
        kpi.append((str(r.history.get("resolved_paths", 0)), "paths no longer seen"))
    kpis = "".join(f"<div class='kpi'><b>{e(v)}</b><span>{e(label)}</span></div>" for v, label in kpi)

    busy = []
    for i, p in enumerate(r.busiest, 1):
        busy.append(
            f"<tr><td class='n'>{i}</td><td>{e(p.path.start.display)}</td><td class='n'>{p.members}</td>"
            f"<td class='n'>{p.percentage}%</td><td class='n'>{p.path.length}</td><td class='n'>{p.path.cost}</td>"
            f"<td class='n'><b>{p.risk}</b></td><td class='path'>{_html_path(p.path)}"
            f"<details><summary>Cypher</summary><code>{e(p.query)}</code></details></td></tr>"
        )
    weak = []
    for i, w in enumerate(r.weakest, 1):
        weak.append(
            f"<tr><td class='n'>{i}</td><td class='path'><strong>{e(w.hop.source.display)}</strong>"
            f"<span class='edge'>{e(w.hop.kind)}</span>{e(w.hop.target.display)}"
            f"<details><summary>Cypher</summary><code>{e(w.query)}</code></details></td>"
            f"<td class='n'>{w.paths}</td><td class='n'>{w.percentage}%</td><td class='n'>{w.users_exposed}</td>"
            f"<td>{e(w.hint)}</td></tr>"
        )
    summary = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in _summary(r))
    resolved = r.history.get("resolved") if r.history else None
    resolved_html = ""
    if resolved:
        items = "".join(f"<tr><td>{e(s)}</td><td class='path'>{e(t)}</td></tr>" for s, t in resolved)
        resolved_html = (
            "<h2>Paths no longer seen since the previous run</h2><div class='card'><table>"
            f"<tr><th>Starting node</th><th>Path</th></tr>{items}</table></div>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GoodHound Enterprise Report</title><style>{_CSS}</style></head>
<body><main>
<h1>GoodHound Enterprise attack path report</h1>
<p class="sub">{e(r.tenant)} · generated {e(r.generated_at.strftime("%Y-%m-%d %H:%M"))} UTC · targets: {e(r.settings.target_label)} · max {r.settings.max_hops} hops</p>
<div class="kpis">{kpis}</div>
<h2>Busiest paths</h2>
<div class="card"><table><tr><th>#</th><th>Starting node</th><th>Users</th><th>% users</th><th>Hops</th><th>Cost</th><th>Risk</th><th>Path</th></tr>
{"".join(busy) or "<tr><td colspan='8'>No paths to Tier Zero.</td></tr>"}</table></div>
<p class="note">Risk = (1 − cost / {r.settings.max_path_cost}) × % of enabled non-Tier Zero users who are members of the starting node.</p>
<h2>The weakest links</h2>
<div class="card"><table><tr><th>#</th><th>Relationship</th><th>Paths</th><th>% paths</th><th>Users exposed</th><th>Suggested action</th></tr>
{"".join(weak) or "<tr><td colspan='6'>None.</td></tr>"}</table></div>
<p class="note">Removing a link breaks every path listed against it. "Users exposed" sums the members of each start group whose path uses the link (users in several groups are counted more than once).</p>
{resolved_html}
<h2>Summary</h2><div class="card"><table class="summary">{summary}</table></div>
</main></body></html>
"""


# --------------------------------------------------------------------------


def write_csv(r: AnalysisResult, out_dir: Path, stem: str) -> list[Path]:
    files = []
    tables = {
        "summary": (["Metric", "Value"], [list(x) for x in _summary(r)]),
        "busiestpaths": (
            BUSY_HEADERS + ["Cypher"],
            [row + [p.query] for row, p in zip(_busy_rows(r), r.busiest, strict=True)],
        ),
        "weakestlinks": (
            WEAK_HEADERS + ["Cypher"],
            [row + [w.query] for row, w in zip(_weak_rows(r), r.weakest, strict=True)],
        ),
    }
    for name, (headers, rows) in tables.items():
        path = out_dir / f"{stem}_{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            writer.writerows(rows)
        files.append(path)
    return files


def emit(r: AnalysisResult, formats: Sequence[str], out_dir: Path) -> list[Path]:
    """Print/write the requested formats; return the files written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{r.generated_at.strftime('%Y-%m-%d_%H%M')}_GoodHoundEnterprise"
    written: list[Path] = []
    for fmt in dict.fromkeys(formats):
        if fmt == "stdout":
            print(to_stdout(r))
        elif fmt == "md":
            path = out_dir / f"{stem}.md"
            path.write_text(to_markdown(r), encoding="utf-8")
            written.append(path)
        elif fmt == "html":
            path = out_dir / f"{stem}.html"
            path.write_text(to_html(r), encoding="utf-8")
            written.append(path)
        elif fmt == "json":
            path = out_dir / f"{stem}.json"
            path.write_text(to_json(r), encoding="utf-8")
            written.append(path)
        elif fmt == "csv":
            written += write_csv(r, out_dir, stem)
        else:
            raise ValueError(f"Unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    return written
