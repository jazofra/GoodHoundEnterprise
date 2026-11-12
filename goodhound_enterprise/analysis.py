"""GoodHound's prioritisation, re-implemented on BloodHound Enterprise with a probabilistic risk model.

Pipeline:

1. Count enabled, non-Tier Zero users (the population at risk).
2. Page through every non-Tier Zero group and fetch the shortest paths from
   each one to Tier Zero (one bounded query per group). They form that group's
   *attack graph*: every visible path, each relationship with a success
   probability.
3. Optionally find paths users hold in their own right (first hop is not
   ``MemberOf``): each user's first hops joined to the neighbour's attack graph.
4. Count the enabled non-Tier Zero members (nested) of every start group.
5. Per start node: the most likely path (shown), the reach probability over
   all visible paths, and risk = reach x share of users ("busiest paths").
6. Exposure for the whole tenant, counting each user once at their best group.
7. Weakest links: the single relationships whose removal lowers that exposure
   the most, computed with distinct users.

``risk_model = "goodhound"`` restores GoodHound's original formula
(fewest-hop path, ``(1 - cost/max_cost) x % users``, links ranked by path count).
See docs/RISK_MODEL.md.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import cypher
from .backends.base import QueryError, RetryableQueryError
from .config import DUAL_CONTROL_GATED_EDGES, REMEDIATION_HINTS, Settings
from .graph import AttackPath, Hop, Node
from .risk import AttackGraph, CountUsers, EdgeKey, GEdge, Reach, RiskContext, distinct_exposure
from .source import CypherGraphSource

log = logging.getLogger(__name__)

# Abort the group scan when more start nodes than this fail (absolute floor, fraction of scanned).
MAX_SKIPPED_START_NODES = 25
MAX_SKIPPED_FRACTION = 0.02

ProgressFn = Callable[[str], None]


def _check_skipped(skipped: list[str], scanned: int) -> None:
    """A few slow start nodes are expected; many failures mean an outage, and a run that
    silently dropped most of them would record a misleading baseline."""
    if len(skipped) > max(MAX_SKIPPED_START_NODES, scanned * MAX_SKIPPED_FRACTION):
        raise QueryError(
            f"{len(skipped)} of {scanned} start nodes failed; aborting rather than reporting partial results"
        )


@dataclass
class PathResult:
    path: AttackPath  # the most likely path (GoodHound model: fewest hops, then cheapest)
    start_label: str
    members: int
    percentage: float
    risk: float
    reach: float = 1.0  # probability that at least one visible path works
    paths: int = 1  # visible paths (capped at exact_path_limit + 1)
    exact: bool = True  # reach computed exactly (False: Monte Carlo)
    graph: AttackGraph | None = field(default=None, repr=False, compare=False)

    @property
    def query(self) -> str:
        return cypher.view_path([(h.source.objectid, h.kind, h.target.objectid) for h in self.path.hops])

    @property
    def paths_label(self) -> str:
        return str(self.paths) if self.exact else f"{self.paths - 1}+"


@dataclass
class WeakLink:
    hop: Hop
    paths: int  # start nodes whose risk depends on it
    percentage: float  # ... as a share of all start nodes with a path
    users_exposed: int  # distinct users in those start nodes
    risk_reduction: float | None = None  # exposure points removed by deleting it (probability model)
    estimate: bool = False

    @property
    def text(self) -> str:
        return f"{self.hop.source.display} - {self.hop.kind} -> {self.hop.target.display}"

    @property
    def hint(self) -> str:
        return REMEDIATION_HINTS.get(self.hop.kind, "Review and remove this relationship if it is not required.")

    @property
    def query(self) -> str:
        return cypher.view_path([(self.hop.source.objectid, self.hop.kind, self.hop.target.objectid)])


@dataclass
class AnalysisResult:
    tenant: str
    generated_at: datetime
    domains: list[Node]
    total_enabled_users: int
    users_with_path: int | None
    users_with_path_is_estimate: bool
    all_paths: list[PathResult]
    busiest: list[PathResult]
    weakest: list[WeakLink]
    queries_sent: int
    settings: Settings
    exposure: float | None = None  # expected % of users whose compromise reaches Tier Zero
    exposure_is_estimate: bool = False
    history: dict[str, Any] = field(default_factory=dict)
    # Start nodes whose path query failed after retries: results are a lower bound.
    skipped_start_nodes: list[str] = field(default_factory=list)
    # Start nodes analysed with shortestPath because allShortestPaths timed out: reach may be low.
    single_path_fallbacks: list[str] = field(default_factory=list)
    # OpenGraph extension prefix -> relationship kinds traversed in this run.
    opengraph: dict[str, list[str]] = field(default_factory=dict)
    dual_control_platforms: int = 0
    #: The (platformId, instance) keys behind that count, for code that rebuilds attack graphs.
    dual_control_keys: frozenset[tuple[str, str]] = field(default_factory=frozenset, repr=False)
    # Start nodes whose result reached Hunter's row limit: paths may be missing, reach may be low.
    possibly_truncated: list[str] = field(default_factory=list)
    # Queries answered from the checkpoint of an interrupted run (--resume).
    resumed_queries: int = 0
    # Target-object mode: the target and how many enabled users already hold it as members.
    target: Node | None = None
    target_members: int | None = None

    @property
    def total_paths(self) -> int:
        return len(self.all_paths)

    @property
    def percentage_with_path(self) -> float:
        if not self.total_enabled_users or self.users_with_path is None:
            return 0.0
        return round(self.users_with_path / self.total_enabled_users * 100, 1)


def risk_score(cost: int, percentage: float, max_cost: int) -> float:
    """GoodHound's formula: share of users exposed, discounted by exploit cost."""
    return round(max(0.0, (max_cost - cost) / max_cost) * percentage, 1)


def probability_risk(reach: float, members: int, total_users: int) -> float:
    """Expected % of all enabled non-Tier Zero users who reach Tier Zero through this start node."""
    return round(100.0 * reach * members / total_users, 2) if total_users else 0.0


SORT_KEYS: dict[str, Callable[[PathResult], tuple]] = {
    "risk": lambda r: (-r.risk, -r.reach, r.path.length, r.path.cost, r.path.start.display),
    "users": lambda r: (-r.members, -r.risk, r.path.start.display),
    "hops": lambda r: (r.path.length, -r.risk, r.path.start.display),
    "probability": lambda r: (-r.reach, -r.risk, r.path.start.display),
}


def _in_scope(node: Node, label: str, settings: Settings) -> bool:
    if node.kind != label or node.tier_zero or not node.objectid:
        return False
    if settings.domain_sid and node.properties.get("domainsid") not in (None, settings.domain_sid):
        return False
    return not (label == "User" and node.properties.get("enabled") is False)


async def _discover_groups(
    source: CypherGraphSource, ctx: RiskContext, progress: ProgressFn, skipped: list[str]
) -> dict[str, AttackGraph]:
    """Attack graph to Tier Zero for every non-Tier Zero group that has one.

    Groups whose path query still fails after retries are appended to ``skipped``
    instead of aborting the run.
    """
    settings = source.settings
    found: dict[str, AttackGraph] = {}
    no_path: set[str] = set()
    sem = asyncio.Semaphore(settings.concurrency)
    scanned = 0

    async def resolve(node: Node) -> None:
        async with sem:
            # Checked after acquiring the slot so suffixes found meanwhile are reused.
            if node.objectid in found or node.objectid in no_path:
                return
            try:
                graph = await source.shortest_paths(node, "Group")
            except QueryError as exc:
                if not isinstance(exc, RetryableQueryError):
                    raise  # a rejected query is a bug or a policy change, not a slow group
                skipped.append(node.objectid)
                log.warning("Skipping %s: its path query failed (%s)", node.name or node.objectid, str(exc)[:200])
                return
            except Exception as exc:  # transport failures that outlived retries and reconnects
                skipped.append(node.objectid)
                log.warning("Skipping %s: its path query failed (%s)", node.name or node.objectid, str(exc)[:200])
                return
        attack_graph = ctx.build(graph, node.objectid)
        if attack_graph is None:
            no_path.add(node.objectid)
            return
        found.setdefault(node.objectid, attack_graph)
        if settings.reuse_suffixes:
            # An intermediate group's part of this graph is a subset of its own: fewer queries,
            # but its reach may be underestimated. Off by default.
            for hop in attack_graph.best_path(ctx.objective).hops[1:]:
                if _in_scope(hop.source, "Group", settings) and hop.source.objectid not in found:
                    sub = attack_graph.sub(hop.source.objectid)
                    if sub is not None:
                        found[hop.source.objectid] = sub

    async for page in source.iter_start_pages("Group"):
        await asyncio.gather(*(resolve(n) for n in page))
        scanned += len(page)
        _check_skipped(skipped, scanned)
        progress(f"Groups scanned: {scanned}, with a path to {settings.target_description}: {len(found)}")
    return found


async def _discover_users(
    source: CypherGraphSource,
    ctx: RiskContext,
    known: dict[str, AttackGraph],
    progress: ProgressFn,
    skipped: list[str],
) -> dict[str, AttackGraph]:
    """Attack graphs for paths users hold *in their own right* (first hop is not MemberOf).

    GoodHound dropped MemberOf from user searches entirely, which hid paths such as
    user -ForceChangePassword-> svc -MemberOf-> admins. Here each user's first
    non-membership hops are joined to the neighbour's attack graph, which is memoised
    (many users share neighbours).
    """
    settings = source.settings
    sem = asyncio.Semaphore(settings.concurrency)
    tails: dict[str, asyncio.Future[AttackGraph | None]] = {}
    found: dict[str, AttackGraph] = {}
    skipped_users: list[str] = []
    scanned = 0

    async def fetch_tail(node: Node) -> AttackGraph | None:
        if node.objectid in known:
            return known[node.objectid]
        graph = await source.shortest_paths(node, node.kind, max_hops=settings.max_hops - 1)
        return ctx.build(graph, node.objectid)

    def tail(node: Node) -> asyncio.Future[AttackGraph | None]:
        if node.objectid not in tails:
            tails[node.objectid] = asyncio.ensure_future(fetch_tail(node))
        return tails[node.objectid]

    async def resolve(user: Node) -> None:
        # Like groups: a user whose queries keep failing is skipped, not fatal for the run.
        try:
            await explore(user)
        except QueryError as exc:
            if not isinstance(exc, RetryableQueryError):
                raise  # a rejected query is a bug or a policy change, not a slow user
            skip(user, exc)
        except Exception as exc:  # transport failures that outlived retries and reconnects
            skip(user, exc)

    def skip(user: Node, exc: BaseException) -> None:
        skipped_users.append(user.objectid)
        skipped.append(user.objectid)
        log.warning("Skipping %s: its path query failed (%s)", user.name or user.objectid, str(exc)[:200])

    async def explore(user: Node) -> None:
        async with sem:
            first = await source.first_hops(user)
        nodes: dict[str, Node] = {user.objectid: user}
        edges: list[GEdge] = []
        for edge, neighbour in first:
            if not neighbour.objectid or not neighbour.kind:
                continue
            p = ctx.edge_probability(edge, neighbour)
            gate = ctx.approval_gate(edge, neighbour) or (None, 1.0)
            nodes[neighbour.objectid] = neighbour
            edges.append(
                GEdge(
                    user.objectid,
                    neighbour.objectid,
                    edge.kind,
                    p,
                    settings.cost(edge.kind, neighbour.kind),
                    None,
                    *gate,
                )
            )
            if neighbour.tier_zero or settings.max_hops <= 1:
                continue
            rest = await tail(neighbour)
            if rest is None:
                continue
            nodes.update(rest.nodes)
            # Drop anything that loops back through the user (its own memberships belong to the groups).
            edges.extend(e for e in rest.edges if user.objectid not in (e.src, e.dst))
        attack_graph = AttackGraph.from_edges(user, nodes, edges)
        if attack_graph is not None:
            found[user.objectid] = attack_graph

    async for page in source.iter_start_pages("User"):
        await asyncio.gather(*(resolve(n) for n in page))
        scanned += len(page)
        _check_skipped(skipped_users, scanned)
        progress(f"Users scanned: {scanned}, with a direct path to {settings.target_description}: {len(found)}")
    return found


# --------------------------------------------------------------------------
# Weakest links
# --------------------------------------------------------------------------


def goodhound_weakest_links(rows: list[PathResult], limit: int) -> list[WeakLink]:
    """GoodHound's ranking: how many (shown) paths each relationship appears in."""
    counts: Counter[EdgeKey] = Counter()
    exposure: defaultdict[EdgeKey, int] = defaultdict(int)
    sample: dict[EdgeKey, Hop] = {}
    for row in rows:
        for hop in dict.fromkeys(row.path.hops):
            key = (hop.source.objectid, hop.kind, hop.target.objectid)
            counts[key] += 1
            exposure[key] += row.members
            sample.setdefault(key, hop)
    total = len(rows) or 1
    limit = max(0, limit)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], -exposure[kv[0]], kv[0]))
    return [
        WeakLink(sample[key], n, round(n / total * 100, 1), exposure[key], estimate=True) for key, n in ranked[:limit]
    ]


async def probability_weakest_links(
    rows: list[PathResult],
    limit: int,
    settings: Settings,
    total_users: int,
    exposure: float | None,
    count_users: CountUsers,
    max_exact_links: int = 60,
) -> list[WeakLink]:
    """Rank single relationships by how much tenant exposure disappears when they are removed.

    Candidates are the relationships on the shown paths. Each is scored exactly with distinct
    users (each user at their best remaining group), which accounts for users who keep another
    path through a different group. A cheap upper bound decides which candidates need scoring.
    """
    if limit <= 0:
        return []
    sample: dict[EdgeKey, Hop] = {}
    for row in rows:
        for hop in row.path.hops:
            sample.setdefault((hop.source.objectid, hop.kind, hop.target.objectid), hop)

    # Reach of every start node without each candidate (only where the candidate is in its graph).
    without: dict[EdgeKey, dict[int, float]] = defaultdict(dict)
    rough: dict[EdgeKey, float] = defaultdict(float)
    for idx, row in enumerate(rows):
        if row.graph is None:
            continue
        for key in row.graph.keys & sample.keys():
            reduced = row.graph.reach(settings, exclude=[key]).probability
            if reduced < row.reach - 1e-12:
                without[key][idx] = reduced
                rough[key] += (row.reach - reduced) * row.members

    # The group-level sum is an upper bound of the exact (distinct-user) reduction, because
    # max(before) - max(after) <= sum(before - after). Evaluating candidates in order of that bound and
    # stopping once the limit-th exact score beats the next bound gives the exact top list.
    ordered = sorted(rough, key=lambda k: (-rough[k], k))
    groups = {idx: row for idx, row in enumerate(rows) if row.start_label == "Group"}
    users = {idx: row for idx, row in enumerate(rows) if row.start_label == "User"}
    scored: list[WeakLink] = []
    truncated = False
    for n_done, key in enumerate(ordered):
        bound = 100.0 * rough[key] / total_users if total_users else 0.0
        best = sorted((w.risk_reduction or 0.0 for w in scored), reverse=True)
        if len(best) >= limit and best[limit - 1] >= bound:
            break
        if n_done >= max_exact_links:
            truncated = True
            break
        affected = without[key]
        reduction: float | None = None
        estimate = False
        if exposure is not None:
            after, est = await distinct_exposure(
                {rows[i].path.start.objectid: affected.get(i, rows[i].reach) for i in groups},
                {rows[i].path.start.objectid: affected.get(i, rows[i].reach) for i in users},
                total_users,
                count_users,
                settings.exposure_levels,
            )
            if after is not None:
                reduction, estimate = max(0.0, exposure - after), est
        if reduction is None:  # fall back to the upper bound
            reduction, estimate = bound, True
        affected_groups = frozenset(rows[i].path.start.objectid for i in affected if i in groups)
        distinct = await count_users(affected_groups) if affected_groups else 0
        if distinct is None:
            distinct, estimate = sum(rows[i].members for i in affected if i in groups), True
        distinct += sum(1 for i in affected if i in users)
        scored.append(
            WeakLink(
                sample[key],
                len(affected),
                round(len(affected) / (len(rows) or 1) * 100, 1),
                min(distinct, total_users) if total_users else distinct,
                round(reduction, 2),
                estimate or bool(users),
            )
        )
    if truncated:
        log.warning("Weakest links: stopped after %d exact evaluations; ranking may be approximate", max_exact_links)
        for w in scored:
            w.estimate = True
    scored.sort(key=lambda w: (-(w.risk_reduction or 0.0), -w.paths, w.text))
    return scored[:limit]


# --------------------------------------------------------------------------


async def analyse(
    source: CypherGraphSource,
    *,
    tenant: str,
    results: int = 5,
    sort: str = "risk",
    progress: ProgressFn | None = None,
) -> AnalysisResult:
    settings = source.settings
    progress = progress or (lambda msg: log.info(msg))
    started = datetime.now(UTC)
    opengraph: dict[str, list[str]] = {}
    dual_control: frozenset[tuple[str, str]] = frozenset()
    if settings.opengraph:
        progress(f"Resolving OpenGraph relationship kinds for {', '.join(settings.opengraph)}")
        opengraph = await source.enable_opengraph()
        if any(k in DUAL_CONTROL_GATED_EDGES for kinds in opengraph.values() for k in kinds):
            dual_control = frozenset(await source.dual_control_platforms())
            progress(f"CyberArk platforms requiring dual control: {len(dual_control)}")
    ctx = RiskContext(settings, started, dual_control)

    target: Node | None = None
    target_members: int | None = None
    if settings.target_objectid:
        found_target = (await source.query(cypher.node_by_objectid(settings.target_objectid))).by_objectid(
            settings.target_objectid
        )
        if found_target is None:
            raise QueryError(f"Target object {settings.target_objectid} was not found")
        target = found_target
        if target.kind == "Group":
            target_members = await source.member_count(target)
        progress(f"Target: {target.display} ({target.kind})")

    progress("Counting enabled non-Tier Zero users")
    total_users, domains = await asyncio.gather(source.count_enabled_users(), source.domains())

    progress("Finding paths from groups to Tier Zero")
    skipped: list[str] = []
    group_graphs = await _discover_groups(source, ctx, progress, skipped)
    found: dict[str, tuple[AttackGraph, str]] = {oid: (g, "Group") for oid, g in group_graphs.items()}
    if settings.include_users or not found:
        progress("Finding paths users hold in their own right (not via group membership)")
        user_graphs = await _discover_users(source, ctx, group_graphs, progress, skipped)
        found.update({oid: (g, "User") for oid, g in user_graphs.items()})

    group_ids = [oid for oid, (_, label) in found.items() if label == "Group"]
    progress(f"Counting members of {len(group_ids)} groups with a path")
    counts = await asyncio.gather(*(source.member_count(found[oid][0].start) for oid in group_ids))
    members = dict(zip(group_ids, counts, strict=True))

    progress("Scoring paths")
    probability_model = settings.risk_model == "probability"
    rows: list[PathResult] = []
    for oid, (attack_graph, label) in found.items():
        n = members.get(oid, 1) if label == "Group" else 1
        pct = round(n / total_users * 100, 1) if total_users else 0.0
        path = attack_graph.best_path(ctx.objective)
        reach: Reach = attack_graph.reach(settings)
        risk = (
            probability_risk(reach.probability, n, total_users)
            if probability_model
            else risk_score(path.cost, pct, settings.max_path_cost)
        )
        rows.append(PathResult(path, label, n, pct, risk, reach.probability, reach.paths, reach.exact, attack_graph))

    # Distinct-user counts, memoised: the same group sets come up for many levels and links.
    cache: dict[frozenset[str], int | None] = {}

    async def count_users(groups: frozenset[str]) -> int | None:
        if groups not in cache:
            cache[groups] = await source.unique_members(sorted(groups))
        return cache[groups]

    user_rows = [r for r in rows if r.start_label == "User"]
    via_groups = await count_users(frozenset(group_ids))
    estimate = via_groups is None or bool(user_rows)
    if via_groups is None:
        via_groups = sum(members.values())
    users_with_path = via_groups + len(user_rows)
    if total_users:
        users_with_path = min(users_with_path, total_users)

    exposure: float | None = None
    exposure_estimate = False
    if probability_model:
        progress("Computing exposure with distinct users")
        exposure, exposure_estimate = await distinct_exposure(
            {r.path.start.objectid: r.reach for r in rows if r.start_label == "Group"},
            {r.path.start.objectid: r.reach for r in user_rows},
            total_users,
            count_users,
            settings.exposure_levels,
        )
        progress("Ranking weakest links by exposure removed")
        weakest = await probability_weakest_links(rows, results, settings, total_users, exposure, count_users)
    else:
        weakest = goodhound_weakest_links(rows, results)

    ranked = sorted(rows, key=SORT_KEYS.get(sort, SORT_KEYS["risk"]))
    results = max(0, results)
    return AnalysisResult(
        tenant=tenant,
        generated_at=started,
        domains=domains,
        total_enabled_users=total_users,
        users_with_path=users_with_path,
        users_with_path_is_estimate=estimate,
        all_paths=ranked,
        busiest=ranked[:results],
        weakest=weakest,
        queries_sent=source.queries_sent,
        settings=settings,
        exposure=None if exposure is None else round(exposure, 2),
        exposure_is_estimate=exposure_estimate,
        skipped_start_nodes=sorted(skipped),
        single_path_fallbacks=sorted(set(source.single_path_fallbacks) - set(skipped)),
        opengraph=opengraph,
        dual_control_platforms=len(dual_control),
        dual_control_keys=dual_control,
        possibly_truncated=sorted(set(source.possibly_truncated) - set(skipped)),
        resumed_queries=source.checkpoint.hits if source.checkpoint is not None else 0,
        target=target,
        target_members=target_members,
    )
