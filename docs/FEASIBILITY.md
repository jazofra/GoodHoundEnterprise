# Feasibility: GoodHound for BloodHound Enterprise through Hunter MCP

*Exploration notes, November 2026. Sources: the
[GoodHound source](https://github.com/idnahacks/GoodHound) and the
[Hunter MCP (beta) documentation](https://bloodhound.specterops.io/integrations/hunter-mcp-beta).*

## Verdict

**It is feasible, but not as a port.** GoodHound's three outputs can all be
reproduced on a BloodHound Enterprise (BHE) tenant through Hunter's Cypher
fallback:

- the busiest paths to Tier Zero,
- the weakest links,
- the run-to-run history.

GoodHound's own queries cannot be reused, though. They write to the graph, run
unbounded traversals, return unbounded result sets and depend on APOC. Hunter
forbids or lacks every one of those.

The design in this repository breaks the analysis into many small, bounded,
read-only queries and does all aggregation on the client. It runs end to end
against a simulated Hunter server, over both in-process MCP and real streamable
HTTP. It has **not** been run against a real tenant yet: Hunter is in closed
beta and its tool catalogue is not published. The
[open questions](#open-questions-to-settle-on-a-beta-tenant) below list exactly
what a beta tenant needs to confirm.

## What GoodHound does

GoodHound is a Python CLI that runs against the Neo4j database behind BloodHound
CE/Legacy:

1. **Mutates the graph.** It writes an `r.cost` onto every relationship
   (MemberOf/Contains/GpLink/CanRDP = 0, ACL abuse and AdminTo = 1,
   AddKeyCredentialLink and DCSync rights = 2, HasSession = 3). It also marks
   DCSync-capable principals `highvalue = true`.
2. **Runs one big query:** `shortestpath((g:Group {highvalue:false})-[...*1..]->(n {highvalue:true}))`.
   It sums the edge costs per path and keeps `min(cost)` per start group. If no
   group has a path, it falls back to enabled users, without `MemberOf`.
3. **Counts reach.** It counts each start group's enabled non-high-value
   members, walking nested groups with one query per group visited.
4. **Scores** each path:
   `risk = (maxcost − cost) / maxcost × % of enabled non-admins`, where
   `maxcost = max(hops in this dataset) × 3 + 1`.
5. **Finds the weakest links** by splitting every path into
   (node, relationship, node) triples and counting the most common. It
   generates an APOC-based Cypher query to view each one.
6. **Keeps history** in SQLite: a `paths` table keyed by an md5 of the path
   text, with first/last seen. It uses this to report "new paths" and "% seen
   before".
7. **Writes reports** as stdout, csv, md or html, including a query to paste
   into BloodHound.

## What Hunter MCP offers (as documented)

| Aspect | Documented behaviour |
|---|---|
| Edition | BloodHound Enterprise only. Closed beta, enabled per tenant |
| Transport | Remote **streamable HTTP** at `https://<tenant>/api/v2/hunter/mcp`. Nothing to install |
| Auth | **OAuth 2.0 Authorization Code + PKCE** with dynamic client registration and no client secret. The user approves each client in BloodHound, and connections expire after **90 days** |
| Roles | User, Power User or Administrator |
| Access | **Read-only** |
| Tools | **Typed tools first**, raw Cypher as a fallback. Only `bloodhound_status` and the `bloodhound-top-findings` prompt are named. The rest of the catalogue is not published |
| Cypher rules | The query must end in a literal `LIMIT` from 1 to 100. Variable-length traversals are capped at **10 hops**. No mutations and no collection-producing result functions. **Not available to ETAC-restricted users** |
| Limits | 55 req/s per client IP (shared). 2 MiB request bodies. About a **30 s** deadline for graph work, so broad queries fail. Large results may be paginated or summarised |

## Mapping, component by component

| GoodHound | Why it breaks on Hunter | What this prototype does |
|---|---|---|
| Neo4j bolt + password | — | Hunter MCP client using the MCP Python SDK 2.x: OAuth/PKCE, a token cache, and refresh of expired tokens. A **REST backend** (HMAC API token) runs the same queries for unattended jobs |
| `SET r.cost` | Read-only | A client-side cost table that keeps GoodHound's weights and adds BHE edges (ADCS ESC*, DCSync, NTLM relay, …). Costs can depend on the target kind (e.g. `GenericAll->Domain = 2`). Override it in TOML |
| `SET highvalue` on DCSyncers | Read-only | Not needed. BHE's Tier Zero (`Tag_Tier_Zero`) is curated, and DCSync is already a post-processed edge. The target label is configurable, for example to a Privilege Zone |
| One unbounded all-groups `shortestpath` | `*1..` is not allowed, `LIMIT` ≤ 100, 30 s deadline | Keyset-paginate the non-Tier Zero groups 100 at a time. Then run **one bounded shortest-path query per group**: `*1..10`, one path per reachable Tier Zero target, `LIMIT 100`. The client picks fewest hops, then lowest cost |
| — | Many queries | **Suffix reuse:** every intermediate group on a shortest path inherits its suffix and is never queried |
| Recursive membership walk | — | One `count(DISTINCT u)` per group with `MemberOf*1..10`, plus one `IN [...]` query for the distinct total |
| User fallback without `MemberOf` | It hid paths such as *user → ForceChangePassword → svc → MemberOf → admins* | Fetch each user's first **non-membership** hops, then join them to the neighbour's memoised shortest tail. Users share neighbours, so tails are cached |
| `maxcost = max(hops)*3+1` | Scores change whenever the dataset changes | Fixed ceiling `max_hops × max edge cost + 1` (31 by default), so scores are **comparable between runs** |
| Weakest-link query via `apoc.path.combine` | No APOC | Counted on the client, with a plain one-edge view query per link |
| "BloodHound query" matched by `name` | — | Matched by `objectid` and ending in `LIMIT 1`, so it works in Explore **and** through Hunter |
| SQLite `paths` table | It only knew "new" | `runs` + `paths` + `observations` tables add **paths no longer seen** (fixed or re-routed) and trend data. The uid uses object ids, so renames do not create "new" paths |
| Scan date from a DC's `lastlogontimestamp` | — | Run timestamp, since BHE collects continuously |
| stdout / csv / md / html | The `-o markdown` branch was broken | stdout / csv / md / html / **json**. The HTML escapes AD-controlled strings |

Every generated query passes through `assert_hunter_safe()` before it is sent.
The fake Hunter server in the tests enforces the same rules.

## Query budget

Roughly `3 + ⌈G/100⌉ + G′ + P` queries, where:

- `G` is the number of non-Tier Zero groups,
- `G′ ≤ G` is the number of groups actually queried after suffix reuse,
- `P` is the number of groups with a path.

A tenant with 5,000 groups therefore needs about 5,000–10,000 small queries. At
the default 10 queries/s that is about 10–17 minutes. That is fine for a weekly
or nightly job but slow for interactive use. `--include-users` adds one
first-hop query per enabled user, plus one per distinct neighbour.

## Two ways to use Hunter, and why both

**A. Deterministic client (the `goodhound-enterprise` CLI).** MCP is used purely
as an authenticated transport for Cypher.

- **Pros:** repeatable numbers, history and trends, no LLM tokens, safe to
  schedule.
- **Cons:** it depends on the Cypher fallback, which ETAC-restricted users
  cannot use and which may change during the beta. It also sends thousands of
  calls.

**B. Agentic: an MCP client such as Claude Code plus Hunter plus the bundled
skill** (`.claude/skills/goodhound-enterprise`).

- **Pros:** it can use Hunter's typed tools, BHE's own remediation text and
  Explore links. It can explain the findings and investigate follow-up
  questions.
- **Cons:** it is non-deterministic, and thousands of Cypher calls through an
  LLM are slow and expensive. Its counts should not be trusted for trend
  reporting.

**Recommended:** use both. The CLI produces the numbers (JSON/HTML), and the
agent reads that JSON to write the remediation narrative and dig into specific
paths. The skill tells the agent to work this way.

## Overlap with BHE's built-in features

BHE already prioritises **Attack Path findings**, with exposure and impact, and
trends them on the Posture page. Those findings are per edge class (for example,
"non-Tier Zero principals with GenericAll on Tier Zero"), not end-to-end chains.
A GoodHound-style view adds:

- chain-level ranking by the share of users who can walk a full path to Tier
  Zero,
- choke points that are not findings themselves (a `HasSession`, a `MemberOf`,
  an `AdminTo` in the middle of many chains),
- a management-ready report and delta.

The natural next step is to map each weakest link to the matching BHE finding
through Hunter's typed tools, so the report quotes BHE's own remediation
guidance.

## Open questions to settle on a beta tenant

Run `goodhound-enterprise discover --url <tenant>` first. It dumps the tool
catalogue and the result of `bloodhound_status`.

1. **Cypher tool name and arguments.** Auto-discovery picks any tool with
   "cypher" in its name. `--cypher-tool`, `--cypher-arg` and `--tool-arg`
   override it.
2. **Result envelope.** Is the `structuredContent` BHE's unified graph
   (`nodes` / `edges` / `literals`)? The parser is tolerant, but this needs
   confirming.
3. **Validator acceptance** of `ORDER BY … LIMIT` keyset paging,
   `count(DISTINCT u)`, `NOT u:Tag_Tier_Zero`, and `IN [...]` lists of a few
   thousand SIDs (bodies under 2 MiB).
4. **Performance:** does a shortest path to `(t:Tag_Tier_Zero)` from a large
   group finish inside the 30 s deadline? Does a `MemberOf*1..10` count on
   Domain Users?
5. **Refresh tokens:** are they issued? This decides whether Hunter can drive
   unattended runs, or whether the REST backend should.
6. **ETAC-restricted users:** they get no Cypher. Can the typed tools alone
   answer "shortest path from X to Tier Zero" and "member count of X"?
7. **Edge kinds:** does the tenant reject relationship kinds it does not know?
   The default list contains only current BHE AD edges, and the TOML can trim
   it.

## Known limitations

- **Paths longer than 10 hops are invisible.** This is a Hunter cap, and rare in
  practice. GoodHound was unbounded.
- **Up to 100 targets per start node.** At most 100 shortest paths (one per
  Tier Zero target) are fetched per start node. If a node reaches more than 100
  Tier Zero objects, the cheapest path may be missed.
- **"Users exposed" double-counts.** On the weakest links it is a sum over start
  groups, so users in several groups are counted more than once. It is labelled
  as such.
- **AD only.** Azure/Entra (AZ edges, AZ Tier Zero) would need its own edge and
  cost table.
- **Reports are sensitive.** They are a map of how to own the domain, so store
  them accordingly. In agentic mode, graph data reaches the LLM provider, and
  Hunter's docs require an MCP client approved for your BloodHound data.

## Suggested next steps

1. Enable the Hunter beta on a test tenant, run `discover`, fix any tool or
   argument mismatch, then run the analysis.
2. Cross-check the numbers for two or three groups against the BHE UI
   (pathfinding plus group membership counts).
3. Decide on scheduling: use Hunter if refresh tokens work, otherwise the REST
   backend with an API token.
4. Enrich the weakest links with BHE finding IDs and remediation text through
   the typed tools, and add Explore links.
5. Extend to Azure/Entra.
