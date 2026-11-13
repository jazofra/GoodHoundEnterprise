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

- **Busiest paths.** Which non-Tier Zero groups put the most users within reach of Tier
  Zero? Each start node gets its most likely path, a reach probability over all its
  visible paths, and a risk score. The risk is the expected share of users whose
  compromise reaches Tier Zero through that node.
- **Weakest links.** Which single relationships remove the most exposure when deleted?
  This is counted with distinct users, so users who keep another route don't inflate it.
- **Exposure and trend.** What share of users can reach Tier Zero, weighted by
  probability and with each user counted once? What changed since the last run, and
  which paths are no longer seen?

The risk model weighs hops (every attacker action multiplies the odds), alternative
paths (more routes, higher reach), each relationship's likelihood, and how recently a
session was seen. [docs/RISK_MODEL.md](docs/RISK_MODEL.md) gives the formulas, the
defaults and the assumptions. `--risk-model goodhound` keeps GoodHound's original formula.

Paths that leave AD and come back can be included with `--opengraph CyberArk,MSSQL`. For example, an AD
group synced into CyberArk retrieves the vaulted password of a Tier Zero admin. CyberArk dual control
is modelled as a shared approval per safe that the attacker must also win. See
[docs/RISK_MODEL.md](docs/RISK_MODEL.md#opengraph-extensions-cyberark-mssql).

Paths longer than Hunter's 10-hop limit are stitched: a start node with no path inside the limit is
joined to the groups it reaches that have one, so a long chain of admin rights and sessions that ends
in such a group is still reported. Start nodes whose search stopped at the limit without finding
anything are counted in the report. `--no-stitch` turns this off. See
[docs/RISK_MODEL.md](docs/RISK_MODEL.md#paths-longer-than-10-hops-stitching).

### Exposure of one object

GoodHound looks *outwards* from each group: how many users it puts within reach of Tier Zero. A group with few
members but powerful rights, such as one that can retrieve vaulted Tier Zero passwords, therefore scores
low. BloodHound Enterprise's exposure looks *inwards*: who can get into that group. `--target-objectid
<objectid>` answers that question. Every non-Tier Zero group (and, with `--include-users`, user) is scored
on its chance of reaching that one object, and the weakest links show which relationship to cut. The
report's grand totals list the target and the users who are already its members. History is kept
separately for each target.

## How it works with Hunter

Hunter is a remote, read-only MCP server at `https://<tenant>/api/v2/hunter/mcp`.
It authenticates with OAuth 2.0 + PKCE: no API key, and the user approves the
client in BloodHound. Its raw-Cypher fallback must end in `LIMIT` ≤ 100 and cap
traversals at 10 hops, and it allows no writes. GoodHound's queries break all of
those rules, so this tool runs many small, bounded queries instead:

1. Page through every non-Tier Zero group (100 per query).
2. Run one bounded `allShortestPaths` query per group to `Tag_Tier_Zero`. The result
   is that group's attack graph, with a success probability on every relationship.
3. Count enabled non-Tier Zero members (nested) per group.
4. Compute each group's most likely path, reach and risk. Then compute exposure with
   distinct-user counts, and the exposure each relationship's removal would cut.
5. Record the run in SQLite and write the reports.

Every query is checked against Hunter's rules before it is sent.

### Interrupted runs

A large tenant needs one query per group, so a run can take hours. Every answer is kept in
`goodhound-enterprise.checkpoint.db` while the run is in progress. If the run is interrupted, repeat
the same command with `--resume`: answers less than 24 hours old are reused and only the remaining
queries are sent. The file holds tenant data, so it is created with mode 0600 and removed when the
run completes. `--checkpoint PATH` moves it and `--no-checkpoint` keeps nothing on disk.

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

Sample reports from the demo tenant are in [`examples/demo-report/`](examples/demo-report/).
`python examples/make_demo_reports.py` regenerates them with a fixed clock, so the numbers do not drift.
`1-baseline.*` is the first run. `2-after-fix.*` is a second run after removing Domain Users'
RDP right. In the baseline, the two links behind that path top the weakest links at 12.85
points of exposure each. After the fix, exposure drops from 35.84% to 22.99%, exactly as
predicted, and SQL01's session becomes the new top link because its users no longer have
a fallback route.

## Options (mapped from GoodHound)

| GoodHound | GoodHound Enterprise |
|---|---|
| `-s/-u/-p` Neo4j connection | `--url` + OAuth (Hunter), or `--backend rest` + `BHE_TOKEN_ID`/`BHE_TOKEN_KEY` |
| `-o stdout\|csv\|md` | `-o stdout\|csv\|md\|html\|json` (repeatable) |
| `-d`, `-r`, `--sort risk\|users\|hops`, `-q/-v/--debug` | Same |
| `-sch` schema file (Cypher writes) | `-c config.toml`: edge costs, target label, limits (read-only) |
| `--db-skip`, `-sqlpath` | `--db-skip`, `--db` |
| — | `--risk-model probability\|goodhound`, `--detection`, `--session-half-life`, `--sort probability` |
| — | `--domain-sid`, `--max-hops` (≤10), `--target-label`, `--include-users`, `--reuse-suffixes`, `--no-stitch`, `--one-path-per-target`, `--concurrency`, `--rate-limit` |
| — | `--opengraph CyberArk,MSSQL` (also traverse OpenGraph extension edges), `--dual-control-probability` |
| — | `--target-objectid` (who can reach one object, instead of Tier Zero) |
| — | `--resume`, `--checkpoint`, `--no-checkpoint` (continue an interrupted run) |

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
  analysis.py     busiest paths, exposure, weakest links
  risk.py         attack graphs, path/reach probabilities, distinct-user exposure
  source.py       high-level graph questions → bounded Cypher, retries, rate limit
  cypher.py       query builders + assert_hunter_safe()
  graph.py        BloodHound unified-graph parsing, local cheapest-shortest path
  history.py      SQLite runs / paths / observations
  checkpoint.py   answers of the run in progress, for --resume
  report.py       stdout, md, csv, html, json
  backends/       hunter (MCP + OAuth), rest (HMAC API token), demo (synthetic AD)
  fleet/          gateway (agents' read-only tools), agent loop, orchestrator, prompts, plan report
tests/            unit tests + fake Hunter server (in-process and over HTTP) + scripted fake model
docs/FEASIBILITY.md, docs/RISK_MODEL.md, docs/FLEET.md
```

Run the checks that CI runs (`.github/workflows/ci.yml`) with:

```bash
ruff check . && ruff format --check . && mypy && pytest
```

## Credits

The concept, cost model and risk formula come from
[GoodHound](https://github.com/idnahacks/GoodHound) by idnahacks. BloodHound and
Hunter are products of SpecterOps. This project is not affiliated with either.

## Licence

GNU General Public License v3.0, the same licence as GoodHound. See [LICENSE](LICENSE).
