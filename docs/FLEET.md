# Agent fleet

`goodhound-enterprise fleet` adds a team of Claude agents on top of the deterministic analysis. The
engine still finds and counts the paths. The agents then investigate the handful of items worth acting
on, and one lead agent turns their findings into a remediation plan.

```
Hunter MCP / BHE API ◀── gateway: one connection, rate limiter, read-only guard-rails, audit log
                            ▲ 10 read-only tools
engine (code) ─► analysis ─► fan-out (asyncio) ─► 1 agent per weakest link ─┐
                                                 1 agent per busiest path ──┴► cards ─► checks in code ─► lead agent ─► plan
```

## What the agents do, and what they don't

**Agents don't count.** Splitting the thousands of bounded shortest-path queries across agents would
not be faster, because Hunter's rate limit is per client IP and the engine already runs at a safe
share of it. Every result would also pass through a model's context, and the counts would stop being
reproducible, which breaks run-to-run trends.

**Agents investigate.** Each item gets its own agent with a fresh context window.

| Agent | One per | It checks | Default model |
|---|---|---|---|
| Link investigator | Top-N weakest link (`--links`, default 5) | Does the relationship still exist? What are both ends for? What would the fix break, and who owns it? What path remains afterwards? Is there a matching BHE finding? | `claude-sonnet-5-5`, effort `medium` |
| Path validator | Top-N busiest path (`--paths`, default 3) | Does every hop still exist, and is it fresh? Is the path realistic? Which single hop is the best cut? What remains afterwards? | `claude-sonnet-5-5`, effort `medium` |
| Lead | Run | Merges the cards into at most 8 actions ordered by the exposure each removes, an executive summary and caveats | `claude-opus-5-5`, effort `high` |

Each analyst returns a **remediation card**, a JSON object enforced with structured outputs:

- `still_exists`, `verdict` (fix now / fix with care / likely false positive / already fixed / needs human review)
- `headline`, `analysis`, `evidence[]` (each item names the tool result it came from)
- `likely_owner`, `recommended_change`, `change_risk`, `residual_risk`, `bhe_finding`, `confidence`

**Claims are checked in code, not by more agents.** After each card, the orchestrator re-runs the item's
Cypher. If the agent's `still_exists` disagrees with BloodHound, or the agent says "already fixed" while
the relationship is still there, the card is marked unverified and the lead must list it as a caveat.

## The gateway: the agents' only access to BloodHound

Agents never connect to Hunter themselves. The fleet process owns the single Hunter connection (one OAuth
approval) or the REST connection, and exposes these tools:

| Tool | What it answers |
|---|---|
| `get_object` | Properties of one object (description, enabled, timestamps…) |
| `relationship_exists` | Whether one relationship exists right now, and when it was last seen |
| `inbound_control` | Who holds attack rights over an object |
| `group_members` | Direct members (sample) and the nested enabled non-Tier Zero user count |
| `outbound_rights` | Attack rights an object holds |
| `paths_using_link` | Which start nodes depend on a relationship, with their reach probability now and without it (from this run, no query) |
| `path_without_link` | Reach probability before and after removing one relationship, and the most likely path that remains |
| `run_cypher` | One read-only, bounded Cypher query (checked by `assert_hunter_safe`) |
| `list_bloodhound_tools` / `call_bloodhound_tool` | Pass-through to Hunter's own typed tools (findings, remediation guidance). Hunter backend only |

Every call goes through the same rate limiter as the engine and is written to the audit log in the
fleet JSON. Results are trimmed to 12,000 characters before a model sees them.

## Running it

```bash
pip install -e ".[fleet]"          # adds the anthropic SDK
export ANTHROPIC_API_KEY=...        # or `ant auth login`
```

Preview the agent tasks without calling a model:

```bash
goodhound-enterprise fleet --backend demo --dry-run
```

Run the fleet against a tenant:

```bash
goodhound-enterprise fleet --url https://YOUR-TENANT.bloodhoundenterprise.io --links 5 --paths 3
```

The command writes the normal analysis report, plus `*_GoodHoundEnterprise_fleet.html`, `.md` and
`.json`. The JSON holds every card, the token usage per model, and the gateway audit log.

### Cost and safety controls

| Control | Flag | Default |
|---|---|---|
| Number of agents | `--links`, `--paths` | 5 + 3, plus 1 lead |
| Agents at the same time | `--agents` | 4 |
| Model turns per analyst | `--max-turns` | 16 |
| Shared token budget: no new turns start once it is spent | `--token-budget` | 3,000,000 |
| Models and effort | `--worker-model`, `--worker-effort`, `--lead-model`, `--lead-effort` | see the agent table above |
| Server-side retry on a classifier decline | `--no-fallbacks` to disable | on, for models that support it |

Each agent loop also uses prompt caching for its growing conversation.

The analysis of attack paths is defensive security work, but a safety classifier can still decline a
request. With fallbacks on, the API retries a declined request on the model it recommends for that
category. A request that is still declined becomes a failed card, the rest of the run continues, and the
failure shows in the report.

### Safety

- **Read-only end to end.** Hunter is read-only, the gateway exposes no write tool, and every query passes
  the same guard-rails as the engine.
- **Prompt injection.** Anyone who can edit an AD object controls its name and description. Tool results
  are returned as JSON data, and every prompt tells the model never to follow instructions found in them.
  Agents cannot act on such instructions anyway, because they have no write tools. Do not add ticketing
  or change tools without a human approval step.
- **Data handling.** Agents send attack-path data to the Claude API. Apply your organisation's
  data-retention policy, and Hunter's requirement that the MCP client is approved for your BloodHound data.

## Claude Code subagents (interactive)

For analysts working in Claude Code with Hunter connected (see `.mcp.json.example`), there are two
subagents:

- `.claude/agents/ghe-link-investigator.md`
- `.claude/agents/ghe-path-validator.md`

Both use read-only tools plus `mcp__bloodhound-hunter__*`, so they share the session's single Hunter
connection. The `goodhound-enterprise` skill (§5) tells the main session to start them in parallel,
re-check their cards, and write the plan. Nothing to install, and no API key needed beyond Claude Code
itself.

## Claude Managed Agents (not built here)

The same design maps onto Managed Agents for fully hosted, scheduled runs:

- **Agents:** a lead agent with the investigator as a roster member.
- **Hunter connection:** declared as an MCP server, with its OAuth token in a vault `mcp_oauth`
  credential that Anthropic refreshes automatically.
- **Schedule:** a scheduled deployment, with a session budget.

Check these before building it:

- Hunter must issue refresh tokens.
- The vault needs its own approved client, because a rotating refresh token cannot be shared with the
  CLI.
- Graph data then passes through Anthropic's MCP proxy.
- MCP tools ask for approval by default, so an unattended run needs an explicit allowlist of Hunter's
  read-only tools.
- The deterministic engine needs its own Hunter access. The simplest option is a custom tool executed by
  your host.

## Limitations

- **Untested against a real tenant.** The fleet has only run against the demo tenant with a scripted test
  model. Its tests also check the real Anthropic SDK's request bodies over a mocked HTTP transport.
- **Hunter's typed tools are unknown.** How useful `bhe_finding` is depends on what they offer. Run
  `goodhound-enterprise discover` on a beta tenant first.
- **`path_without_link` only searches shortest paths.** It uses `allShortestPaths`, falling back to
  `shortestPath` if the backend rejects it, so a longer remaining path is not shown.
