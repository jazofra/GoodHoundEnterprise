"""Report writers: stdout, markdown, csv, html and json."""

from __future__ import annotations

import csv
import html
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .analysis import AnalysisResult

FORMATS = ("stdout", "md", "csv", "html", "json")


def _probability_model(r: AnalysisResult) -> bool:
    return r.settings.risk_model == "probability"


def _pct(p: float) -> str:
    return f"{p * 100:.1f}%"


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
        ("Risk model", r.settings.risk_model),
        *([("Target", f"{r.target.display} ({r.target.kind}, {r.target.objectid})")] if r.target else []),
        *(
            [("Enabled users already in the target (not counted below)", str(r.target_members))]
            if r.target_members is not None
            else []
        ),
        ("Enabled non-Tier Zero users", str(r.total_enabled_users)),
        ("Non-Tier Zero users with a path", users),
        ("% of enabled non-Tier Zero users with a path", f"{r.percentage_with_path}%"),
    ]
    if _probability_model(r):
        exposure = "n/a" if r.exposure is None else f"{r.exposure}%{' (est.)' if r.exposure_is_estimate else ''}"
        rows.append(("Probability-weighted exposure", exposure))
    rows.append(("Start nodes with a path (total paths)", str(r.total_paths)))
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
        if h.get("rerouted_paths"):
            rows.append(("Start nodes whose most likely path changed", str(h["rerouted_paths"])))
        if _probability_model(r) and h.get("previous_exposure") is not None:
            rows.append(("Exposure at previous run", f"{h['previous_exposure']}%"))
        if h.get("comparable") is False:
            rows.append(
                (
                    "Trend",
                    "Analysis settings changed since the previous run: the differences above may come from "
                    "the settings, not the tenant",
                )
            )
    if r.opengraph:
        extensions = ", ".join(f"{p} ({len(k)} kinds)" for p, k in r.opengraph.items())
        if r.dual_control_platforms:
            extensions += (
                f"; {r.dual_control_platforms} dual-control platforms "
                f"(x{r.settings.dual_control_probability} per approval)"
            )
        rows.append(("OpenGraph edges traversed", extensions))
    if r.skipped_start_nodes:
        rows.append(
            (
                "Start nodes skipped (query failed)",
                f"{len(r.skipped_start_nodes)}: totals and exposure are a lower bound",
            )
        )
    if r.single_path_fallbacks:
        rows.append(
            (
                "Start nodes with shortestPath only",
                f"{len(r.single_path_fallbacks)}: allShortestPaths timed out, so their reach may be underestimated",
            )
        )
    if r.possibly_truncated:
        rows.append(
            (
                "Start nodes at the query row limit",
                f"{len(r.possibly_truncated)}: some of their paths may be missing, so their reach may be "
                "underestimated",
            )
        )
    rows.append(("Queries sent", str(r.queries_sent)))
    if r.resumed_queries:
        rows.append(("Answers reused from the interrupted run", str(r.resumed_queries)))
    return rows


# Column specs: (header, numeric?, value). One definition drives stdout, md, csv and html.
Column = tuple[str, bool, Callable[[Any], str]]


def _busy_columns(r: AnalysisResult) -> list[Column]:
    cols: list[Column] = [
        ("Starting Node", False, lambda p: p.path.start.display),
        ("Users", True, lambda p: str(p.members)),
        ("% of Users", True, lambda p: f"{p.percentage}%"),
        ("Hops", True, lambda p: str(p.path.length)),
    ]
    if _probability_model(r):
        cols += [
            ("Paths", True, lambda p: p.paths_label),
            ("Path Prob.", True, lambda p: _pct(p.path.probability)),
            ("Reach Prob.", True, lambda p: _pct(p.reach)),
            ("Risk", True, lambda p: f"{p.risk:.2f}"),
        ]
    else:
        cols += [("Exploit Cost", True, lambda p: str(p.path.cost)), ("Risk Score", True, lambda p: str(p.risk))]
    return cols


def _weak_columns(r: AnalysisResult) -> list[Column]:
    if _probability_model(r):
        return [
            ("Start Nodes", True, lambda w: str(w.paths)),
            ("Users (distinct)", True, lambda w: str(w.users_exposed)),
            ("Exposure Removed", True, lambda w: f"{w.risk_reduction:.2f} pts{'*' if w.estimate else ''}"),
            ("Suggested Action", False, lambda w: w.hint),
        ]
    return [
        ("Paths", True, lambda w: str(w.paths)),
        ("% of Paths", True, lambda w: f"{w.percentage}%"),
        ("Users Exposed (sum)", True, lambda w: str(w.users_exposed)),
        ("Suggested Action", False, lambda w: w.hint),
    ]


def _busy_table(r: AnalysisResult) -> tuple[list[str], list[list[str]]]:
    cols = _busy_columns(r)
    headers = ["#", *(c[0] for c in cols), "Path"]
    rows = [[str(i), *(c[2](p) for c in cols), p.path.text] for i, p in enumerate(r.busiest, 1)]
    return headers, rows


def _weak_table(r: AnalysisResult) -> tuple[list[str], list[list[str]]]:
    cols = _weak_columns(r)
    headers = ["#", "Weakest Link", *(c[0] for c in cols)]
    rows = [[str(i), w.text, *(c[2](w) for c in cols)] for i, w in enumerate(r.weakest, 1)]
    return headers, rows


def _risk_note(r: AnalysisResult) -> str:
    if _probability_model(r):
        return (
            "Risk = reach probability x users in the starting node / all enabled non-Tier Zero users x 100: the "
            "expected % of users whose compromise reaches Tier Zero through it. Reach = chance that at least one "
            "visible path works; each hop's probability combines technique success, session freshness and a "
            f"{r.settings.per_action_detection:.0%} chance per attacker action of being caught. "
            "Path shown = the most likely one. See docs/RISK_MODEL.md."
        )
    return (
        f"Risk = (1 - cost / {r.settings.max_path_cost}) x % of enabled non-Tier Zero users who are members "
        "of the starting node (GoodHound's formula)."
    )


def _weak_note(r: AnalysisResult) -> str:
    if _probability_model(r):
        return (
            "Exposure removed = how far probability-weighted exposure drops if only this relationship is removed, "
            "counting each user once at their best remaining path. Users = distinct users whose risk depends on it. "
            "* = estimate."
        )
    return (
        "Ranked by the number of paths the relationship appears in (GoodHound). Users exposed sums the members of "
        "each start group whose path uses it (users in several groups are counted more than once)."
    )


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
    parts += ["", "BUSIEST PATHS", _table(*_busy_table(r)) if r.busiest else "No paths to Tier Zero."]
    parts += ["", "THE WEAKEST LINKS", _table(*_weak_table(r)) if r.weakest else "None."]
    parts += ["", _risk_note(r), _weak_note(r)]
    return "\n".join(parts)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def to_markdown(r: AnalysisResult) -> str:
    parts = ["# GoodHound Enterprise report", "", "## Grand totals", _md_table(["Metric", "Value"], _summary(r))]
    parts += ["", "## Busiest paths", _md_table(*_busy_table(r)), "", f"_{_risk_note(r)}_"]
    parts += ["", "### Queries to view these paths", ""]
    parts += [f"{i}. `{p.query}`" for i, p in enumerate(r.busiest, 1)]
    parts += ["", "## The weakest links", _md_table(*_weak_table(r)), "", f"_{_weak_note(r)}_"]
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
            "actions": p.path.actions,
            "cost": p.path.cost,
            "path_probability": round(p.path.probability, 6),
            "reach_probability": round(p.reach, 6),
            "visible_paths": p.paths,
            "reach_exact": p.exact,
            "risk": p.risk,
            "path": p.path.text,
            "edges": [
                {
                    "source": h.source.objectid,
                    "kind": h.kind,
                    "target": h.target.objectid,
                    "target_name": h.target.display,
                    "probability": round(h.probability, 6),
                    "last_seen": h.last_seen,
                }
                for h in p.path.hops
            ],
            "query": p.query,
        }

    doc = {
        "tenant": r.tenant,
        "generated_at": r.generated_at.isoformat(),
        "summary": dict(_summary(r)),
        "risk_model": r.settings.risk_model,
        "exposure": r.exposure,
        "exposure_is_estimate": r.exposure_is_estimate,
        "skipped_start_nodes": r.skipped_start_nodes,
        "opengraph": r.opengraph,
        "dual_control_platforms": r.dual_control_platforms,
        "single_path_fallbacks": r.single_path_fallbacks,
        "possibly_truncated": r.possibly_truncated,
        "resumed_queries": r.resumed_queries,
        "settings_fingerprint": r.settings.fingerprint(),
        "settings": {
            "target_label": r.settings.target_label,
            "target_objectid": r.settings.target_objectid,
            "max_hops": r.settings.max_hops,
            "domain_sid": r.settings.domain_sid,
            "max_path_cost": r.settings.max_path_cost,
            "per_action_detection": r.settings.per_action_detection,
            "session_half_life_days": r.settings.session_half_life_days,
            "all_shortest_paths": r.settings.all_shortest_paths,
            "reuse_suffixes": r.settings.reuse_suffixes,
            "opengraph": r.settings.opengraph,
            "dual_control_probability": r.settings.dual_control_probability,
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
                "exposure_removed": w.risk_reduction,
                "estimate": w.estimate,
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
    kpi = []
    if _probability_model(r) and r.exposure is not None:
        kpi.append((f"{r.exposure}%", "probability-weighted exposure (expected share of users who reach Tier Zero)"))
    kpi += [
        (str(r.users_with_path if r.users_with_path is not None else "n/a"), "non-Tier Zero users with a path"),
        (f"{r.percentage_with_path}%", "of enabled non-Tier Zero users"),
        (str(r.total_paths), "start nodes with a path"),
    ]
    if r.history and r.history.get("previous_run_at"):
        prev = r.history.get("previous_exposure")
        if _probability_model(r) and prev is not None and r.exposure is not None:
            kpi.append((f"{r.exposure - float(prev):+.2f} pts", "exposure change since last run"))
        kpi.append((str(r.history.get("new_paths", 0)), "new paths since last run"))
        kpi.append((str(r.history.get("resolved_paths", 0)), "paths no longer seen"))
    kpis = "".join(f"<div class='kpi'><b>{e(v)}</b><span>{e(label)}</span></div>" for v, label in kpi)

    busy_cols = _busy_columns(r)
    busy_head = "".join(f"<th>{e(c[0])}</th>" for c in busy_cols)
    busy = []
    for i, p in enumerate(r.busiest, 1):
        cells = "".join(f"<td class='n'>{e(c[2](p))}</td>" if c[1] else f"<td>{e(c[2](p))}</td>" for c in busy_cols)
        busy.append(
            f"<tr><td class='n'>{i}</td>{cells}<td class='path'>{_html_path(p.path)}"
            f"<details><summary>Cypher</summary><code>{e(p.query)}</code></details></td></tr>"
        )
    weak_cols = _weak_columns(r)
    weak_head = "".join(f"<th>{e(c[0])}</th>" for c in weak_cols)
    weak = []
    for i, w in enumerate(r.weakest, 1):
        cells = "".join(f"<td class='n'>{e(c[2](w))}</td>" if c[1] else f"<td>{e(c[2](w))}</td>" for c in weak_cols)
        weak.append(
            f"<tr><td class='n'>{i}</td><td class='path'><strong>{e(w.hop.source.display)}</strong>"
            f"<span class='edge'>{e(w.hop.kind)}</span>{e(w.hop.target.display)}"
            f"<details><summary>Cypher</summary><code>{e(w.query)}</code></details></td>{cells}</tr>"
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
    busy_span, weak_span = len(busy_cols) + 2, len(weak_cols) + 2
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GoodHound Enterprise Report</title><style>{_CSS}</style></head>
<body><main>
<h1>GoodHound Enterprise attack path report</h1>
<p class="sub">{e(r.tenant)} · generated {e(r.generated_at.strftime("%Y-%m-%d %H:%M"))} UTC · targets: {e(r.target.display if r.target else r.settings.target_label)} · max {r.settings.max_hops} hops · risk model: {e(r.settings.risk_model)}</p>
<div class="kpis">{kpis}</div>
<h2>Busiest paths</h2>
<div class="card"><table><tr><th>#</th>{busy_head}<th>Path</th></tr>
{"".join(busy) or f"<tr><td colspan='{busy_span}'>No paths to Tier Zero.</td></tr>"}</table></div>
<p class="note">{e(_risk_note(r))}</p>
<h2>The weakest links</h2>
<div class="card"><table><tr><th>#</th><th>Relationship</th>{weak_head}</tr>
{"".join(weak) or f"<tr><td colspan='{weak_span}'>None.</td></tr>"}</table></div>
<p class="note">{e(_weak_note(r))}</p>
{resolved_html}
<h2>Summary</h2><div class="card"><table class="summary">{summary}</table></div>
</main></body></html>
"""


# --------------------------------------------------------------------------


def _csv_cell(value: object) -> str:
    """Stop spreadsheets running a cell as a formula: object names come from the directory,
    and whoever can rename an object controls them."""
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        try:
            float(text)  # a plain negative number is harmless
        except ValueError:
            return "'" + text
    return text


def write_csv(r: AnalysisResult, out_dir: Path, stem: str) -> list[Path]:
    files = []
    tables = {
        "summary": (["Metric", "Value"], [list(x) for x in _summary(r)]),
        "busiestpaths": (
            _busy_table(r)[0] + ["Cypher"],
            [row + [p.query] for row, p in zip(_busy_table(r)[1], r.busiest, strict=True)],
        ),
        "weakestlinks": (
            _weak_table(r)[0] + ["Cypher"],
            [row + [w.query] for row, w in zip(_weak_table(r)[1], r.weakest, strict=True)],
        ),
    }
    for name, (headers, rows) in tables.items():
        path = out_dir / f"{stem}_{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            writer.writerows([_csv_cell(c) for c in row] for row in rows)
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
