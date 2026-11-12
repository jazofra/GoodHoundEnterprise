"""One agent = one Claude tool-use loop over the gateway's tools.

A plain Messages API loop (not the beta tool runner): it is easy to bound
(turn cap, shared token budget), to audit, and to test with a fake client.
The loop is append-only - every assistant turn goes back exactly as received,
thinking blocks included - which current Claude models require.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .gateway import Gateway

log = logging.getLogger(__name__)

FALLBACK_BETA = "server-side-fallback-2026-07-01"
#: Models that accept ``fallbacks: "default"`` (server-side retry on a classifier decline).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1"}


@dataclass
class AgentConfig:
    model: str
    effort: str = "medium"
    max_turns: int = 16
    max_tokens: int = 16000
    fallbacks: bool = True


@dataclass
class TokenBudget:
    """Shared across the fleet; agents stop starting new turns once it is spent."""

    limit: int
    used: int = 0
    by_model: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, model: str, usage: Any) -> None:
        counts = {
            "input": getattr(usage, "input_tokens", 0) or 0,
            "output": getattr(usage, "output_tokens", 0) or 0,
            "cache_read": getattr(usage, "cache_read_input_tokens", 0) or 0,
            "cache_write": getattr(usage, "cache_creation_input_tokens", 0) or 0,
        }
        bucket = self.by_model.setdefault(model, dict.fromkeys(counts, 0))
        for key, value in counts.items():
            bucket[key] += value
        self.used += sum(counts.values())

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit


@dataclass
class AgentRun:
    name: str
    model: str
    output: dict[str, Any] | None = None
    error: str | None = None
    turns: int = 0
    tool_calls: int = 0


def _request(cfg: AgentConfig, system: str, messages: list, tools: list, schema: dict) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "system": system,
        "messages": messages,
        "output_config": {"effort": cfg.effort, "format": {"type": "json_schema", "schema": schema}},
        "cache_control": {"type": "ephemeral"},  # caches the growing conversation turn to turn
    }
    if tools:
        kwargs["tools"] = tools
    if cfg.fallbacks and cfg.model in FALLBACK_MODELS:
        kwargs["betas"] = [FALLBACK_BETA]
        kwargs["fallbacks"] = "default"
    return kwargs


async def run_agent(
    client: Any,
    gateway: Gateway | None,
    *,
    name: str,
    system: str,
    task: str,
    schema: dict,
    cfg: AgentConfig,
    budget: TokenBudget,
) -> AgentRun:
    run = AgentRun(name=name, model=cfg.model)
    tools = gateway.tool_params() if gateway else []
    messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
    while run.turns <= cfg.max_turns:
        if budget.exhausted:
            run.error = "token budget exhausted"
            return run
        run.turns += 1
        response = await client.beta.messages.create(**_request(cfg, system, messages, tools, schema))
        budget.add(cfg.model, response.usage)

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            run.error = f"declined by the model (category: {getattr(details, 'category', None)})"
            return run
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "pause_turn":
            continue
        if response.stop_reason == "tool_use":
            calls = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            if gateway is None:
                run.error = "the model asked for a tool but this agent has none"
                return run
            run.tool_calls += len(calls)
            results = await asyncio.gather(*(gateway.call(name, c.name, c.input) for c in calls))
            content: list[dict[str, Any]] = [
                {"type": "tool_result", "tool_use_id": c.id, "content": text, "is_error": is_error}
                for c, (text, is_error) in zip(calls, results, strict=True)
            ]
            if run.turns >= cfg.max_turns:
                content.append({"type": "text", "text": "Tool budget reached. Reply now with the JSON object."})
            messages.append({"role": "user", "content": content})
            continue
        if response.stop_reason == "max_tokens":
            run.error = "response hit max_tokens"
            return run

        text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), "")
        try:
            run.output = json.loads(text)
        except ValueError:
            run.error = f"final answer was not JSON: {text[:200]!r}"
        return run
    run.error = f"no answer after {cfg.max_turns} turns"
    return run
