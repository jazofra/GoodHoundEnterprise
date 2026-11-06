"""Remediation-plan outputs for a fleet run: markdown, json and html."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from ..report import _CSS
from .orchestrator import FleetResult

VERDICT_LABEL = {
    "fix_now": "Fix now",
    "fix_with_care": "Fix with care",
    "likely_false_positive": "Likely false positive",
    "already_fixed": "Already fixed",
    "needs_human_review": "Needs human review",
}


def _verification(card) -> str:
    if card.verified is None:
        return "not checked"
    return ("✔ " if card.verified else "✘ ") + card.verification_note


def _usage_lines(fr: FleetResult) -> list[str]:
    lines = []
    for model, u in fr.budget.by_model.items():
        lines.append(
            f"{model}: {u['input']:,} input, {u['output']:,} output, "
            f"{u['cache_read']:,} cache-read, {u['cache_write']:,} cache-write tokens"
        )
    calls = Counter(a.tool for a in fr.gateway.audit)
    errors = sum(1 for a in fr.gateway.audit if not a.ok)
    lines.append(
        f"Gateway tool calls: {len(fr.gateway.audit)} ({errors} failed); "
        + ", ".join(f"{k} {v}" for k, v in calls.most_common())
    )
    return lines


def to_json(fr: FleetResult) -> str:
    doc = {
        "tenant": fr.analysis.tenant,
        "generated_at": fr.analysis.generated_at.isoformat(),
        "config": fr.config.__dict__,
        "plan": fr.plan,
        "plan_error": fr.plan_error,
        "cards": [
            {
                "item": c.task.item,
                "kind": c.task.kind,
                "subject": c.task.title,
                "hops": c.task.hops,
                "card": c.run.output,
                "error": c.run.error,
                "turns": c.run.turns,
                "tool_calls": c.run.tool_calls,
                "verified": c.verified,
                "verification_note": c.verification_note,
            }
            for c in fr.cards
        ],
        "skipped": fr.skipped,
        "usage": fr.budget.by_model,
        "audit": [a.__dict__ for a in fr.gateway.audit],
    }
    return json.dumps(doc, indent=2, default=str)


def _md(s: object) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(fr: FleetResult) -> str:
    a = fr.analysis
    out = [
        "# GoodHound Enterprise remediation plan",
        "",
        f"{a.tenant} · {a.generated_at:%Y-%m-%d %H:%M} UTC · {a.users_with_path} of {a.total_enabled_users} "
        f"enabled non-Tier Zero users ({a.percentage_with_path}%) have a path to Tier Zero.",
        "",
    ]
    if fr.plan:
        out += ["## Executive summary", "", fr.plan.get("executive_summary", ""), "", "## Actions", ""]
        out += [
            "| # | Action | Change | Owner | Impact | Operational risk | Based on |",
            "|---|---|---|---|---|---|---|",
        ]
        for act in sorted(fr.plan.get("actions", []), key=lambda x: x.get("priority", 99)):
            out.append(
                f"| {act.get('priority')} | {_md(act.get('title'))} | {_md(act.get('change'))} | "
                f"{_md(act.get('owner'))} | {_md(act.get('impact'))} | {_md(act.get('operational_risk'))} | "
                f"{_md(', '.join(act.get('based_on', [])))} |"
            )
        if fr.plan.get("caveats"):
            out += ["", "### Caveats", ""] + [f"- {_md(c)}" for c in fr.plan["caveats"]]
    else:
        out += [f"_No plan: {fr.plan_error}_"]
    out += ["", "## Analyst cards", ""]
    for c in fr.cards:
        d = c.data
        out += [f"### {c.task.item}: {_md(c.task.title)}", ""]
        if c.run.error:
            out += [f"_Agent failed: {_md(c.run.error)}_", ""]
            continue
        out += [
            f"**{VERDICT_LABEL.get(d.get('verdict'), d.get('verdict'))}** ({d.get('confidence')} confidence) · "
            f"verification: {_md(_verification(c))}",
            "",
            _md(d.get("headline", "")),
            "",
            f"- **Recommended change:** {_md(d.get('recommended_change'))}",
            f"- **Likely owner:** {_md(d.get('likely_owner'))}",
            f"- **Change risk:** {_md(d.get('change_risk'))}",
            f"- **Residual risk:** {_md(d.get('residual_risk'))}",
        ]
        if d.get("bhe_finding"):
            out.append(f"- **BloodHound Enterprise finding:** {_md(d['bhe_finding'])}")
        out += ["- **Evidence:**"] + [f"  - {_md(e)}" for e in d.get("evidence", [])] + [""]
    if fr.skipped:
        out += [f"_Skipped because the token budget ran out: {', '.join(fr.skipped)}_", ""]
    out += ["## Run details", ""] + [f"- {line}" for line in _usage_lines(fr)]
    return "\n".join(out) + "\n"


def to_html(fr: FleetResult) -> str:
    e = html.escape
    a = fr.analysis
    actions = ""
    if fr.plan:
        rows = "".join(
            f"<tr><td class='n'>{e(str(x.get('priority')))}</td><td><b>{e(x.get('title', ''))}</b><br>"
            f"{e(x.get('change', ''))}</td><td>{e(x.get('owner', ''))}</td><td>{e(x.get('impact', ''))}</td>"
            f"<td>{e(x.get('operational_risk', ''))}</td><td>{e(', '.join(x.get('based_on', [])))}</td></tr>"
            for x in sorted(fr.plan.get("actions", []), key=lambda x: x.get("priority", 99))
        )
        caveats = "".join(f"<li>{e(c)}</li>" for c in fr.plan.get("caveats", []))
        actions = (
            f"<h2>Executive summary</h2><div class='card' style='padding:14px'>{e(fr.plan.get('executive_summary', ''))}</div>"
            "<h2>Actions</h2><div class='card'><table><tr><th>#</th><th>Action</th><th>Owner</th><th>Impact</th>"
            f"<th>Operational risk</th><th>Based on</th></tr>{rows}</table></div>"
            + (f"<h2>Caveats</h2><ul>{caveats}</ul>" if caveats else "")
        )
    else:
        actions = f"<p class='note'>No plan: {e(str(fr.plan_error))}</p>"
    cards = []
    for c in fr.cards:
        d = c.data
        if c.run.error:
            body = f"<p class='note'>Agent failed: {e(c.run.error)}</p>"
        else:
            evidence = "".join(f"<li>{e(x)}</li>" for x in d.get("evidence", []))
            body = (
                f"<p><span class='edge'>{e(VERDICT_LABEL.get(d.get('verdict'), str(d.get('verdict'))))}</span> "
                f"{e(str(d.get('confidence')))} confidence · {e(_verification(c))}</p>"
                f"<p><b>{e(d.get('headline', ''))}</b></p><p>{e(d.get('analysis', ''))}</p>"
                f"<table class='summary'><tr><th>Recommended change</th><td>{e(d.get('recommended_change', ''))}</td></tr>"
                f"<tr><th>Likely owner</th><td>{e(d.get('likely_owner', ''))}</td></tr>"
                f"<tr><th>Change risk</th><td>{e(d.get('change_risk', ''))}</td></tr>"
                f"<tr><th>Residual risk</th><td>{e(d.get('residual_risk', ''))}</td></tr>"
                f"<tr><th>BloodHound finding</th><td>{e(d.get('bhe_finding', '') or '—')}</td></tr></table>"
                f"<details><summary>Evidence ({len(d.get('evidence', []))})</summary><ul>{evidence}</ul></details>"
            )
        cards.append(
            f"<div class='card' style='padding:14px;margin-bottom:12px'><div class='path'><b>{e(c.task.item)}</b> · "
            f"{e(c.task.title)}</div>{body}</div>"
        )
    usage = "".join(f"<li>{e(line)}</li>" for line in _usage_lines(fr))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GoodHound Remediation Plan</title><style>{_CSS}</style></head><body><main>
<h1>Attack path remediation plan</h1>
<p class="sub">{e(a.tenant)} · {a.generated_at:%Y-%m-%d %H:%M} UTC · {a.users_with_path} of {a.total_enabled_users} enabled non-Tier Zero users ({a.percentage_with_path}%) have a path to Tier Zero</p>
{actions}
<h2>Analyst cards</h2>{"".join(cards)}
<h2>Run details</h2><ul class="note">{usage}</ul>
<p class="note">Cards are written by AI agents from read-only BloodHound lookups; existence claims are re-checked in code. Review before changing production.</p>
</main></body></html>
"""


def write(fr: FleetResult, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{fr.analysis.generated_at:%Y-%m-%d_%H%M}_GoodHoundEnterprise_fleet"
    files = []
    for ext, render in (("md", to_markdown), ("json", to_json), ("html", to_html)):
        path = out_dir / f"{stem}.{ext}"
        path.write_text(render(fr), encoding="utf-8")
        files.append(path)
    return files
