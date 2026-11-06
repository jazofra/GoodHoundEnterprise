"""GoodHound's prioritisation logic, re-implemented on top of ``CypherGraphSource``.

Pipeline (mirrors GoodHound, adapted to Hunter's constraints):

1. Count enabled, non-Tier Zero users (the population at risk).
2. Page through every non-Tier Zero group (100 per query) and fetch the
   shortest paths from each one to Tier Zero (one bounded query per group).
   The cheapest of the shortest paths is kept.  Because any sub-path of a
   shortest path is itself shortest, intermediate groups on a path inherit
   their suffix and are not queried again.
3. Optionally find paths users hold in their own right (first hop is not
   ``MemberOf``), joining each user's first hop to the neighbour's memoised
   shortest path (GoodHound's user fallback, without its blind spot).
4. Count the enabled non-Tier Zero members (nested) of every start group.
5. Score, rank and de-duplicate ("busiest paths").
6. Count how many paths every single relationship appears in ("weakest links").
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import cypher
from .config import REMEDIATION_HINTS, Settings
from .graph import AttackPath, Hop, Node
from .source import CypherGraphSource

log = logging.getLogger(__name__)

ProgressFn = Callable[[str], None]


@dataclass
class PathResult:
    path: AttackPath
    start_label: str
    members: int
    percentage: float
    risk: float

    @property
    def query(self) -> str:
        return cypher.view_path([(h.source.objectid, h.kind, h.target.objectid) for h in self.path.hops])


@dataclass
class WeakLink:
    hop: Hop
    paths: int
    percentage: float
    users_exposed: int

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
    history: dict[str, object] = field(default_factory=dict)

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


SORT_KEYS: dict[str, Callable[[PathResult], tuple]] = {
    "risk": lambda r: (-r.risk, r.path.cost, r.path.length, r.path.start.display),
    "users": lambda r: (-r.members, -r.risk, r.path.start.display),
    "hops": lambda r: (r.path.length, -r.risk, r.path.start.display),
}


def _in_scope(node: Node, label: str, settings: Settings) -> bool:
    if node.kind != label or node.tier_zero or not node.objectid:
        return False
    if settings.domain_sid and node.properties.get("domainsid") not in (None, settings.domain_sid):
        return False
    return not (label == "User" and node.properties.get("enabled") is False)


async def _discover_groups(source: CypherGraphSource, progress: ProgressFn) -> dict[str, AttackPath]:
    """Shortest (then cheapest) path to Tier Zero from every non-Tier Zero group."""
    settings = source.settings
    found: dict[str, AttackPath] = {}
    no_path: set[str] = set()
    sem = asyncio.Semaphore(settings.concurrency)
    scanned = 0

    async def resolve(node: Node) -> None:
        async with sem:
            # Checked after acquiring the slot so suffixes found meanwhile are reused.
            if node.objectid in found or node.objectid in no_path:
                return
            path = await source.shortest_path(node, "Group")
        if path is None:
            no_path.add(node.objectid)
            return
        found.setdefault(node.objectid, path)
        # Sub-paths of a shortest path are shortest paths: reuse them.
        for i, hop in enumerate(path.hops[1:], start=1):
            if _in_scope(hop.source, "Group", settings) and hop.source.objectid not in found:
                found[hop.source.objectid] = path.suffix(i, settings.cost)

    async for page in source.iter_start_pages("Group"):
        await asyncio.gather(*(resolve(n) for n in page))
        scanned += len(page)
        progress(f"Groups scanned: {scanned}, with a path to {settings.target_label}: {len(found)}")
    return found


async def _discover_users(
    source: CypherGraphSource, known: dict[str, AttackPath], progress: ProgressFn
) -> dict[str, AttackPath]:
    """Paths users have *in their own right* (first hop is not MemberOf).

    GoodHound dropped MemberOf from user searches entirely, which hid paths
    such as user -ForceChangePassword-> svc -MemberOf-> admins.  Here each
    user's first non-membership hops are fetched and joined to the neighbour's
    shortest tail, which is memoised (many users share neighbours).
    """
    settings = source.settings
    sem = asyncio.Semaphore(settings.concurrency)
    tails: dict[str, asyncio.Task[AttackPath | None]] = {}
    found: dict[str, AttackPath] = {}
    scanned = 0

    async def fetch_tail(node: Node) -> AttackPath | None:
        if node.objectid in known:
            return known[node.objectid]
        return await source.shortest_path(node, node.kind, max_hops=settings.max_hops - 1)

    def tail(node: Node) -> asyncio.Task[AttackPath | None]:
        if node.objectid not in tails:
            tails[node.objectid] = asyncio.ensure_future(fetch_tail(node))
        return tails[node.objectid]

    async def resolve(user: Node) -> None:
        async with sem:
            first = await source.first_hops(user)
        best: AttackPath | None = None
        for kind, neighbour in first:
            hop = Hop(user, kind, neighbour)
            step = settings.cost(kind, neighbour.kind)
            if neighbour.tier_zero:
                candidate = AttackPath(user, (hop,), step)
            elif settings.max_hops > 1 and neighbour.kind:
                rest = await tail(neighbour)
                if rest is None or any(h.target.objectid == user.objectid for h in rest.hops):
                    continue  # no path, or it loops back through this user
                candidate = AttackPath(user, (hop, *rest.hops), step + rest.cost)
            else:
                continue
            if best is None or (candidate.length, candidate.cost) < (best.length, best.cost):
                best = candidate
        if best is not None:
            found[user.objectid] = best

    async for page in source.iter_start_pages("User"):
        await asyncio.gather(*(resolve(n) for n in page))
        scanned += len(page)
        progress(f"Users scanned: {scanned}, with a direct path to {settings.target_label}: {len(found)}")
    return found


def weakest_links(results: list[PathResult], limit: int) -> list[WeakLink]:
    counts: Counter[tuple[str, str, str]] = Counter()
    exposure: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    sample: dict[tuple[str, str, str], Hop] = {}
    for result in results:
        seen: set[tuple[str, str, str]] = set()
        for hop in result.path.hops:
            key = (hop.source.objectid, hop.kind, hop.target.objectid)
            if key in seen:
                continue
            seen.add(key)
            counts[key] += 1
            exposure[key] += result.members
            sample.setdefault(key, hop)
    total = len(results) or 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], -exposure[kv[0]], kv[0]))
    return [WeakLink(sample[key], n, round(n / total * 100, 1), exposure[key]) for key, n in ranked[:limit]]


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

    progress("Counting enabled non-Tier Zero users")
    total_users, domains = await asyncio.gather(source.count_enabled_users(), source.domains())

    progress("Finding shortest paths from groups to Tier Zero")
    group_paths = await _discover_groups(source, progress)
    found: dict[str, tuple[AttackPath, str]] = {oid: (p, "Group") for oid, p in group_paths.items()}
    if settings.include_users or not found:
        progress("Finding paths users hold in their own right (not via group membership)")
        user_paths = await _discover_users(source, group_paths, progress)
        found.update({oid: (p, "User") for oid, p in user_paths.items()})

    group_ids = [oid for oid, (_, label) in found.items() if label == "Group"]
    progress(f"Counting members of {len(group_ids)} groups with a path")
    counts = await asyncio.gather(*(source.member_count(found[oid][0].start) for oid in group_ids))
    members = dict(zip(group_ids, counts, strict=True))

    max_cost = settings.max_path_cost
    rows: list[PathResult] = []
    for oid, (path, label) in found.items():
        n = members.get(oid, 1) if label == "Group" else 1
        pct = round(n / total_users * 100, 1) if total_users else 0.0
        rows.append(PathResult(path, label, n, pct, risk_score(path.cost, pct, max_cost)))

    user_ids = [oid for oid, (_, label) in found.items() if label == "User"]
    via_groups = await source.unique_members(group_ids)
    estimate = via_groups is None or bool(user_ids)
    if via_groups is None:
        via_groups = sum(members.values())
    users_with_path = min(via_groups + len(user_ids), total_users) if total_users else via_groups + len(user_ids)

    key = SORT_KEYS.get(sort, SORT_KEYS["risk"])
    ranked = sorted(rows, key=key)
    return AnalysisResult(
        tenant=tenant,
        generated_at=started,
        domains=domains,
        total_enabled_users=total_users,
        users_with_path=users_with_path,
        users_with_path_is_estimate=estimate,
        all_paths=ranked,
        busiest=ranked[:results],
        weakest=weakest_links(rows, results),
        queries_sent=source.queries_sent,
        settings=settings,
    )
