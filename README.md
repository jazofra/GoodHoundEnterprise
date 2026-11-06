# GoodHound Enterprise

GoodHound Enterprise brings [GoodHound](https://github.com/idnahacks/GoodHound)'s
"busiest paths" prioritisation to **BloodHound Enterprise**. It runs through the
[BloodHound Hunter MCP server](https://bloodhound.specterops.io/integrations/hunter-mcp-beta),
with the BHE REST API as a fallback.

> **Status: exploration / prototype.** The full pipeline works against a simulated
> Hunter server, over both in-process MCP and streamable HTTP. It has not been run
> against a live tenant yet: Hunter is in closed beta and its tool catalogue is not
> public. Start with [docs/FEASIBILITY.md](docs/FEASIBILITY.md), which covers the
> analysis, the design decisions and what still needs checking on a real tenant.

It answers GoodHound's questions:

- **Busiest paths.** Which non-Tier Zero groups expose the most enabled users to a
  path to Tier Zero, and how cheap is that path to exploit? Each path gets a risk
  score.
- **Weakest links.** Which single relationships appear in the most paths? Removing
  one breaks every path that uses it.
- **Trend.** What is new since the last run, and which paths are no longer seen?

## How it works with Hunter

Hunter is a remote, read-only MCP server at `https://<tenant>/api/v2/hunter/mcp`.
It authenticates with OAuth 2.0 + PKCE: no API key, and the user approves the
client in BloodHound. Its raw-Cypher fallback must end in `LIMIT` ≤ 100 and cap
traversals at 10 hops, and it allows no writes. GoodHound's queries break all of
those rules, so this tool runs many small, bounded queries instead:

1. Page through every non-Tier Zero group (100 per query).
2. Run one bounded shortest-path query per group to `Tag_Tier_Zero`, and pick the
   fewest hops, then the lowest exploit cost. Intermediate groups reuse the suffix
   of the path, so they are not queried again.
3. Count enabled non-Tier Zero members (nested) per group.
4. Score, rank, count the weakest links, record the run in SQLite, and write the
   reports.

Every query is checked against Hunter's rules before it is sent.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Try it on the built-in demo tenant, with no BloodHound needed:

```bash
goodhound-enterprise run --backend demo -o stdout -o html
```

Against a tenant with the Hunter beta enabled, first list Hunter's tools and
check the connection. This opens the browser to approve access, and the tokens
are cached under `~/.config/goodhound-enterprise/`:

```bash
goodhound-enterprise discover --url https://YOUR-TENANT.bloodhoundenterprise.io
```

Then run the analysis:

```bash
goodhound-enterprise run --url https://YOUR-TENANT.bloodhoundenterprise.io -o stdout -o html -o json
```

For unattended or scheduled runs, use a BHE API token through the REST API
instead. The queries are the same:

```bash
BHE_TOKEN_ID=... BHE_TOKEN_KEY=... goodhound-enterprise run --backend rest --url https://YOUR-TENANT.bloodhoundenterprise.io
```

On a headless host, add `--no-browser --manual-callback`. You then open the URL
yourself and paste back the address the browser was redirected to. If
auto-discovery picks the wrong Hunter tool, override it with `--cypher-tool`,
`--cypher-arg` and `--tool-arg key=value`.

Sample reports from the demo tenant are in [`examples/demo-report/`](examples/demo-report/):
`1-baseline.*` is the first run, and `2-after-fix.*` is a second run after removing
Domain Users' RDP right. The second shows the trend section, with the fixed path
listed as no longer seen and the share of exposed users dropping from 100% to
38%.

## Options (mapped from GoodHound)

| GoodHound | GoodHound Enterprise |
|---|---|
| `-s/-u/-p` Neo4j connection | `--url` + OAuth (Hunter), or `--backend rest` + `BHE_TOKEN_ID`/`BHE_TOKEN_KEY` |
| `-o stdout\|csv\|md` | `-o stdout\|csv\|md\|html\|json` (repeatable) |
| `-d`, `-r`, `--sort risk\|users\|hops`, `-q/-v/--debug` | Same |
| `-sch` schema file (Cypher writes) | `-c config.toml`: edge costs, target label, limits (read-only) |
| `--db-skip`, `-sqlpath` | `--db-skip`, `--db` |
| — | `--domain-sid`, `--max-hops` (≤10), `--target-label`, `--include-users`, `--concurrency`, `--rate-limit` |

See [`examples/config.example.toml`](examples/config.example.toml) for the
edge-cost model.

## Agent fleet

`goodhound-enterprise fleet` runs the analysis first and then puts Claude agents to work on its results:

- one agent per top weakest link and per busiest path,
- each agent investigates through read-only tools, all of which share the tool's single Hunter connection,
- each returns a remediation card: whether the item still exists, the fix and its likely owner, what the
  fix could break, what remains afterwards, and any matching BloodHound Enterprise finding,
- the agents' claims are re-checked in code,
- a lead agent writes the prioritised remediation plan.

Preview the agent tasks without calling a model:

```bash
pip install -e ".[fleet]"
goodhound-enterprise fleet --backend demo --dry-run
```

Run the fleet against a tenant:

```bash
goodhound-enterprise fleet --url https://YOUR-TENANT.bloodhoundenterprise.io
```

The agents investigate rather than count: paths and members are still counted by the deterministic
engine, so the numbers stay reproducible. [docs/FLEET.md](docs/FLEET.md) covers the design, cost and
safety controls, and the Claude Code subagent alternative.

## Agentic mode

[`.claude/skills/goodhound-enterprise/SKILL.md`](.claude/skills/goodhound-enterprise/SKILL.md)
teaches an MCP client the same method. It is meant for Claude Code connected to
Hunter (see `.mcp.json.example`). The agent turns the CLI's JSON into a
remediation plan, digs into individual paths with Hunter's typed tools, and falls
back to doing the analysis by hand when the CLI is not available. Two subagents,
`ghe-link-investigator` and `ghe-path-validator` in `.claude/agents/`, let Claude
Code fan the investigation out in parallel over the session's single Hunter
connection.

## Layout

```
goodhound_enterprise/
  cli.py          run / fleet / discover / logout
  analysis.py     busiest paths, risk score, weakest links (the GoodHound logic)
  source.py       high-level graph questions → bounded Cypher, retries, rate limit
  cypher.py       query builders + assert_hunter_safe()
  graph.py        BloodHound unified-graph parsing, local cheapest-shortest path
  history.py      SQLite runs / paths / observations
  report.py       stdout, md, csv, html, json
  backends/       hunter (MCP + OAuth), rest (HMAC API token), demo (synthetic AD)
  fleet/          gateway (agents' read-only tools), agent loop, orchestrator, prompts, plan report
tests/            unit tests + fake Hunter server (in-process and over HTTP) + scripted fake model
docs/FEASIBILITY.md, docs/FLEET.md
```

Run the tests with `pytest`.

## Credits

The concept, cost model and risk formula come from
[GoodHound](https://github.com/idnahacks/GoodHound) by idnahacks. BloodHound and
Hunter are products of SpecterOps. This project is not affiliated with either.
