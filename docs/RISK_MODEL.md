# Risk model

GoodHound Enterprise scores attack paths with a probabilistic model. Hops, alternative paths and
per-relationship likelihood all shape the score, and every user counts exactly once. GoodHound's
original formula is still available with `--risk-model goodhound`.

## Why not keep GoodHound's formula

GoodHound computes `risk = (1 − cost / max_cost) × % of users in the start group`. On the demo tenant
that formula, and the ranking built on it, have these problems:

| Problem | Effect on the demo tenant |
|---|---|
| Exploit cost barely moves the score | The multiplier only ranges from 0.68 (a 10-hop chain) to 1.0, so risk is effectively the % of users. Hops hardly matter. |
| The shown path is the one with the fewest hops | A 2-hop path through a privileged session beats a reliable 3-hop ACL path, however unlikely the session theft is. |
| One path per start node | A group with two independent routes to Tier Zero scores the same as a group with one. A choke point shared by every route isn't modelled. |
| Weakest links ranked by how many paths contain them | The two links behind the Domain Users path, which exposes **100%** of users, ranked **#7 and #8** and were missing from the top 5. A session link used by four small groups ranked #1. |
| "Users exposed" adds up group sizes | Nested groups (CONTRACTORS inside DEVELOPERS) are counted twice. Users who keep another route through a different group are counted as if fixing the link protected them. |
| Edge weights ignore context | `CanRDP` costs 0, although harvesting a session after RDP needs a local privilege escalation. A session seen months ago costs the same as one seen today. |

## The model

**1. Every relationship gets a success probability**, the chance that an attacker who controls the
source can take control of the target:

```
p(edge) = technique probability                         (table below, configurable)
        × 0.5 ^ (session age / half-life)               HasSession only, from BloodHound's lastSeen
        × (1 − per_action_detection)                    every hop except MemberOf, Contains, GPLink
```

`MemberOf`, `Contains` and `GPLink` are structural: they need no attacker action, so they cost nothing.
Every other hop is an attacker action. It multiplies the odds by its technique probability and by the
chance of not being caught (`per_action_detection`, default 5%). **Hops matter through this product:**
each extra action makes a path less likely.

**2. Path probability** = the product of its hops' probabilities. The path shown for each start node is
the **most likely** one, not the one with the fewest hops. Ties go to fewer hops, then lower cost.

**3. Reach probability** = the chance that **at least one** visible path from the start node works,
treating each relationship as an independent event:

- **Alternatives raise it.** Two independent routes of 0.49 each give 1 − (1 − 0.49)² = 0.74.
- **Shared choke points cap it.** If every route goes through one hop, reach can't exceed that hop's
  probability.
- **Exact or estimated.** With up to 12 paths it is computed exactly, by inclusion–exclusion over the
  paths. Above that, a seeded Monte Carlo estimate (4,000 samples) is used, so reruns give identical
  numbers.

The visible paths come from `allShortestPaths` (bounded to 10 hops and 100 paths by Hunter). If Hunter
rejects that query, the tool falls back to `shortestPath`, which returns one path per target.

**4. Risk of a start node** = `100 × reach × members / enabled non-Tier Zero users`. It is the expected
percentage of all users whose compromise reaches Tier Zero **through this start node**.

**5. Exposure (tenant headline)** = the expected percentage of enabled non-Tier Zero users whose
compromise leads to Tier Zero. Each user counts **once**, at the best reach among the groups they belong
to, including nested membership:

```
exposure = 100/N × Σ over users of  max over their groups g of reach(g)
         = 100/N × Σ over levels L of  |users whose best reach ≥ L| × (L − next level)
```

The second form needs one distinct-user count per distinct reach level: a single `count(DISTINCT u)`
query over the groups at or above that level. So nested and overlapping groups are never double counted.
If there are more than 25 distinct levels, they are rounded down to a grid. The result is then a lower
bound and is flagged as an estimate.

**6. Weakest links** are ranked by **exposure removed**: exposure now minus exposure with that one
relationship deleted, recomputed with distinct users. A user who still has another route keeps it, so
fixing a link only counts for the users it actually protects.

To keep the ranking cheap and exact, candidates are scored in order of an upper bound (summed group-level
reductions; `max(before) − max(after) ≤ Σ(before − after)`). Scoring stops once the k-th exact score
beats the next candidate's bound.

## Worked example (demo tenant, sessions treated as fresh)

| Start node | Most likely path | Path prob. | Visible paths | Reach | Users | Risk |
|---|---|---|---|---|---|---|
| DOMAIN USERS | CanRDP → HasSession | 0.38 × 0.57 = **0.217** | 1 | 0.217 | 386 | 21.7 |
| FINANCE | ADCSESC1 | **0.855** | 1 | 0.855 | 38 | 8.4 |
| IT SUPPORT | MemberOf → AdminTo → HasSession | 1 × 0.855 × 0.57 = **0.487** | 2 | 1 − (1 − 0.487)² = **0.737** | 40 | 7.6 |
| DEVELOPERS | GenericWrite → AdminTo → HasSession | **0.417** | 1 | 0.417 | 68 | 7.3 |

- **Exposure** = (38 × 0.855 + 40 × 0.737 + 68 × 0.417 + 1 × 0.487 + 239 × 0.217) / 386 ≈ **36.9%**.
  239 users have only the Domain Users route.
- **Domain Users' links rank first** among the weakest links. Removing either one takes 239 users from
  0.217 to 0, which is 13.4 points of exposure.
- **SQL01's session ranks lower,** even though six start nodes' graphs contain it. Its users mostly keep
  another route.

## Default technique probabilities

These are calibration defaults that reflect common attacker tradecraft, not measurements. Tune them to
your environment, for example to pentest or red-team success rates, Credential Guard coverage, or LAPS
rollout.

| Probability | Relationships | Reasoning |
|---|---|---|
| 1.0 | MemberOf, Contains | Structural, automatic |
| 0.95 | GPLink, AddMember, AddSelf, ForceChangePassword, ReadLAPSPassword, ReadGMSAPassword, DCSync | Direct, reliable |
| 0.9 | GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, AllExtendedRights, AdminTo, HasSIDHistory, SyncLAPSPassword, DumpSMSAPassword, GoldenCert, ADCSESC1 | Well-documented abuse with public tooling |
| 0.85 | AllowedToDelegate, AllowedToAct, OwnsLimitedRights, WriteOwnerLimitedRights, ADCSESC3/4/13 | Reliable, more steps |
| 0.8 | SQLAdmin, AddAllowedToAct, AddKeyCredentialLink, WriteGPLink, WriteAccountRestrictions, ADCSESC6a/6b | Need extra preconditions (PKINIT, machine account, GPO refresh…) |
| 0.7 | ADCSESC9a/9b/10a/10b; any kind not listed (`default_probability`) | Depend on mapping/registry settings |
| 0.6 | HasSession (before ageing), CoerceToTGT, CoerceAndRelayNTLMToADCS | The session must be present at the time; Credential Guard / Protected Users may block it |
| 0.5 | WriteSPN, CoerceAndRelayNTLMToSMB/LDAP/LDAPS | The hash has to crack; relay conditions vary |
| 0.4 | CanRDP, CanPSRemote, ExecuteDCOM | Non-admin access: still needs local privilege escalation to harvest sessions |

Override any of these in the TOML file (see `examples/config.example.toml`):

```toml
per_action_detection = 0.10     # stronger SOC
session_half_life_days = 7      # sessions go stale faster here

[edge_probability]
HasSession = 0.3                # Credential Guard everywhere
CanRDP = 0.6                    # unpatched hosts, privesc is easy

[targeted_edge_probability]
"GenericAll->Domain" = 0.8      # cost depends on the target kind
```

## OpenGraph extensions (CyberArk, MSSQL)

AD paths often continue through other systems. An AD group is synced into a CyberArk group, that group
can retrieve a vaulted password, and the vaulted account *is* a Tier Zero AD user. With
`--opengraph CyberArk,MSSQL` (or `opengraph = ["CyberArk", "MSSQL"]` in the TOML) those relationships
are traversed too.

- **Which kinds.** The tool reads the tenant's Hunter capability catalog (`hunter://graph/capabilities`)
  and adds every relationship kind marked traversable whose name starts with the prefix (`CyberArk_`,
  `MSSQL_`, or any other extension). Hunter rejects queries that name kinds it does not know, so kinds
  are never guessed. Backends without the catalog fall back to the built-in tables.
- **Probabilities.** Identity links are structural, with probability 1 and no detection: `SyncsToUser`,
  `SyncsToGroup`, `SyncsToADUser`, `MemberOf`, `Contains` and `MSSQL_HasLogin`. Retrieving a vaulted
  password (`CyberArk_HasAccessTo`) is 0.9, and granting yourself access (`CyberArk_CanGrantAccessTo`) is
  0.8. The full table is `OPENGRAPH_EDGE_PROBABILITY` in `config.py`, and `[edge_probability]` overrides
  it. Kinds without a default use `default_probability`.

### Dual control is an AND, shared per safe

When an account's CyberArk platform has `requireDualControlPasswordAccessApproval`, access alone does
not release the password: someone else must approve it. The attacker therefore also needs an approver,
by compromising one or by talking one into approving. That chance is `dual_control_probability`
(default 0.25, `--dual-control-probability`).

Approvers are configured per safe, so every dual-control account in one safe depends on the **same**
approval event. The model adds one shared event per (safe, CyberArk instance), next to the
per-relationship events, and computes reach exactly over all of them:

- 12 dual-control accounts in one safe, each 90% accessible: reach ≈ 0.25 × (1 − 0.1¹²) ≈ 0.25, not
  1 − (1 − 0.9 × 0.25)¹² ≈ 0.95.
- Accounts in two different safes: two independent approvals, 1 − (1 − 0.9 × 0.25)².

The gate applies to `CyberArk_HasAccessTo`, `CyberArk_CanGrantAccessTo` and `CyberArk_Contains` into
a dual-control account. CCP retrieval by applications (`CyberArk_CanRetrieveViaCCP`) is not gated,
because dual control does not apply to it. The approver is not traced as a separate path: if the
attacker already controls an approver, the real chance is higher than modelled.

## Target-object mode

With `--target-objectid`, the target set is that single object instead of the Tier Zero label. Tier Zero
nodes on the way become ordinary hops, because whoever reaches Tier Zero can reach the target anyway.
Reach, risk, exposure and weakest links keep their meaning, applied to "reaching this object". The
target's current members are reported separately and are not start nodes.

## Assumptions and limits

- **Independence.** Relationships succeed or fail independently. Correlated defences, such as one EDR
  policy covering every host, make real alternatives less independent than modelled.
- **Visible paths only.** Paths must be shortest per target, at most 10 hops and at most 100 per start
  node. Longer detours are not counted, so reach is a lower bound in that sense.
- **Users take their best group.** A user's probability is the best reach among their groups. Combining
  routes from different groups would push it slightly higher, so this too is a lower bound.
- **User start nodes are estimates.** With `--include-users`, user rows are added on top of the
  group-based counts and may overlap them, so exposure is then flagged as an estimate.
- **Sampling error.** Monte Carlo reach (start nodes with more than 12 visible paths) carries about
  ±1.5 points of sampling error at the default 4,000 samples, but it is deterministic between runs.
- **Comparing runs.** Exposure is comparable between runs only with the same settings. History stores
  the risk model next to each run and compares exposure only between runs of the same model.
- **Query cost.** The model adds queries: one distinct-user count per reach level, plus a few per scored
  link. The demo tenant needs 53 queries instead of 23, and a real tenant adds tens to a few hundred to
  its thousands of path queries.

## Legacy mode

`--risk-model goodhound` reproduces GoodHound:

- the path with the fewest hops, then the lowest cost, is shown,
- risk = `(1 − cost/31) × % users`,
- weakest links are ranked by path count,
- users exposed are summed per group.

Use it to compare with GoodHound output. The probabilities are still computed and shown in the JSON.
