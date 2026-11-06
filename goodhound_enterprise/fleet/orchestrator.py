"""Fan-out orchestration: deterministic analysis -> N analyst agents -> code checks -> one synthesizer.

The fan-out shape is known before any model runs (one agent per weakest link
and per busiest path), so it is plain asyncio rather than an LLM coordinator.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import cypher
from ..analysis import AnalysisResult, PathResult, WeakLink
from .agent import AgentConfig, AgentRun, TokenBudget, run_agent
from .gateway import Gateway
from .prompts import CARD_SCHEMA, LINK_INVESTIGATOR, PATH_VALIDATOR, PLAN_SCHEMA, SYNTHESIZER


@dataclass
class FleetConfig:
    links: int = 5
    paths: int = 3
    worker_model: str = "claude-sonnet-5-5"
    worker_effort: str = "medium"
    lead_model: str = "claude-opus-5-5"
    lead_effort: str = "high"
    concurrency: int = 4
    max_turns: int = 16
    token_budget: int = 3_000_000
    fallbacks: bool = True


@dataclass
class Task:
    kind: str  # "link" | "path"
    item: str
    title: str
    prompt: str
    hops: list[tuple[str, str, str]]  # (source objectid, kind, target objectid)


@dataclass
class Card:
    task: Task
    run: AgentRun
    verified: bool | None = None
    verification_note: str = ""

    @property
    def data(self) -> dict[str, Any]:
        return self.run.output or {}


@dataclass
class FleetResult:
    analysis: AnalysisResult
    config: FleetConfig
    cards: list[Card]
    plan: dict[str, Any] | None
    plan_error: str | None
    budget: TokenBudget
    gateway: Gateway
    skipped: list[str] = field(default_factory=list)


def _edge_line(src_name: str, src: str, kind: str, dst_name: str, dst: str) -> str:
    return f"- {src_name} [{src}] -{kind}-> {dst_name} [{dst}]"


def link_task(index: int, link: WeakLink, result: AnalysisResult) -> Task:
    h = link.hop
    item = f"link-{index}"
    prompt = f"""Item: {item}
Relationship to investigate:
{_edge_line(h.source.display, h.source.objectid, h.kind, h.target.display, h.target.objectid)}
Source kind: {h.source.kind}. Target kind: {h.target.kind}. Target is Tier Zero: {h.target.tier_zero}.

From the analysis run on {result.generated_at:%Y-%m-%d}: this relationship appears in {link.paths} of
{result.total_paths} attack paths to Tier Zero ({link.percentage}%), whose start groups have
{link.users_exposed} enabled non-Tier Zero members in total (users in several groups counted more than once).
Cypher that renders it: {link.query}

Produce the remediation card for this relationship."""
    return Task("link", item, link.text, prompt, [(h.source.objectid, h.kind, h.target.objectid)])


def path_task(index: int, row: PathResult, result: AnalysisResult) -> Task:
    item = f"path-{index}"
    hops = [(h.source.objectid, h.kind, h.target.objectid) for h in row.path.hops]
    lines = "\n".join(
        _edge_line(h.source.display, h.source.objectid, h.kind, h.target.display, h.target.objectid)
        for h in row.path.hops
    )
    prompt = f"""Item: {item}
Attack path to validate, starting at {row.path.start.display} [{row.path.start.objectid}] ({row.start_label}):
{lines}

From the analysis run on {result.generated_at:%Y-%m-%d}: {row.members} enabled non-Tier Zero users
({row.percentage}% of {result.total_enabled_users}) can walk this path. Hops: {row.path.length},
exploit cost: {row.path.cost}, risk score: {row.risk} (rank #{index} by risk).
Cypher that renders it: {row.query}

Produce the remediation card for this path."""
    return Task("path", item, row.path.text, prompt, hops)


def plan_tasks(result: AnalysisResult, cfg: FleetConfig) -> list[Task]:
    tasks = [link_task(i, w, result) for i, w in enumerate(result.weakest[: cfg.links], 1)]
    tasks += [path_task(i, p, result) for i, p in enumerate(result.busiest[: cfg.paths], 1)]
    return tasks


async def verify(card: Card, gateway: Gateway) -> None:
    """Re-check in code what the agent claimed about existence; flag disagreements."""
    if card.run.output is None:
        return
    graph = await gateway.source.query(cypher.view_path(card.task.hops))
    exists = len(graph.edges) >= len(card.task.hops)
    claimed = bool(card.data.get("still_exists"))
    if card.data.get("verdict") == "already_fixed" and exists:
        card.verified, card.verification_note = False, "agent says already fixed, but it is still in BloodHound"
    elif claimed != exists:
        card.verified = False
        card.verification_note = f"agent says still_exists={claimed}, BloodHound says {exists}"
    else:
        card.verified, card.verification_note = True, "existence confirmed in code"


def synthesis_input(result: AnalysisResult, cards: list[Card]) -> str:
    doc = {
        "analysis": {
            "tenant": result.tenant,
            "generated_at": result.generated_at.isoformat(timespec="minutes"),
            "enabled_non_tier_zero_users": result.total_enabled_users,
            "users_with_a_path": result.users_with_path,
            "percent_with_a_path": result.percentage_with_path,
            "paths": result.total_paths,
            "busiest_paths": [
                {"start": p.path.start.display, "users": p.members, "risk": p.risk, "path": p.path.text}
                for p in result.busiest
            ],
            "weakest_links": [
                {"link": w.text, "paths": w.paths, "percent_of_paths": w.percentage, "users_exposed": w.users_exposed}
                for w in result.weakest
            ],
        },
        "cards": [
            {
                "item": c.task.item,
                "subject": c.task.title,
                "verified": c.verified,
                "verification_note": c.verification_note,
                **({"card": c.data} if c.run.output else {}),
                **({"error": c.run.error} if c.run.error else {}),
            }
            for c in cards
        ],
    }
    return "Write the remediation plan from this input:\n\n" + json.dumps(doc, indent=1, default=str)


async def run_fleet(
    gateway: Gateway,
    client: Any,
    cfg: FleetConfig,
    progress: Callable[[str], None] = lambda _m: None,
) -> FleetResult:
    result = gateway.result
    budget = TokenBudget(cfg.token_budget)
    worker = AgentConfig(cfg.worker_model, cfg.worker_effort, cfg.max_turns, fallbacks=cfg.fallbacks)
    lead = AgentConfig(cfg.lead_model, cfg.lead_effort, 1, fallbacks=cfg.fallbacks)
    tasks = plan_tasks(result, cfg)
    sem = asyncio.Semaphore(cfg.concurrency)
    skipped: list[str] = []

    async def work(task: Task) -> Card | None:
        async with sem:
            if budget.exhausted:
                skipped.append(task.item)
                return None
            progress(f"Agent {task.item} started: {task.title[:80]}")
            system = LINK_INVESTIGATOR if task.kind == "link" else PATH_VALIDATOR
            run = await run_agent(
                client,
                gateway,
                name=task.item,
                system=system,
                task=task.prompt,
                schema=CARD_SCHEMA,
                cfg=worker,
                budget=budget,
            )
            card = Card(task, run)
            await verify(card, gateway)
            status = run.error or f"{card.data.get('verdict')} ({card.verification_note})"
            progress(f"Agent {task.item} finished after {run.turns} turns, {run.tool_calls} tool calls: {status}")
            return card

    progress(f"Launching {len(tasks)} analyst agents on {cfg.worker_model} (max {cfg.concurrency} at a time)")
    cards = [c for c in await asyncio.gather(*(work(t) for t in tasks)) if c is not None]

    plan = plan_error = None
    if any(c.run.output for c in cards):
        progress(f"Synthesizing the remediation plan on {cfg.lead_model}")
        lead_run = await run_agent(
            client,
            None,
            name="lead",
            system=SYNTHESIZER,
            task=synthesis_input(result, cards),
            schema=PLAN_SCHEMA,
            cfg=lead,
            budget=budget,
        )
        plan, plan_error = lead_run.output, lead_run.error
    else:
        plan_error = "no analyst card was produced"
    return FleetResult(result, cfg, cards, plan, plan_error, budget, gateway, skipped)
