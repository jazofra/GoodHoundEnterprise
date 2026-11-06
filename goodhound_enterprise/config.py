"""Settings, traversable edge kinds and the exploit-cost model.

GoodHound wrote an ``r.cost`` property onto every relationship in Neo4j before
querying.  Hunter MCP is read-only, so the same cost model is applied on the
client instead.  The defaults reproduce GoodHound's weights for the edges it
knew about and add weights for edges BloodHound Enterprise has introduced since
(ADCS, DCSync post-processing, NTLM relay, ...).  Every value can be overridden
from a TOML file (see ``examples/config.example.toml``).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

#: Hunter rejects variable-length traversals longer than this.
HUNTER_MAX_HOPS = 10
#: Hunter requires a terminal literal ``LIMIT`` between 1 and this value.
HUNTER_MAX_LIMIT = 100

# Cost per edge kind.  0 = "free" (structural), 1 = direct abuse,
# 2 = needs extra tooling or tradecraft, 3 = needs to wait for / steal a session.
DEFAULT_EDGE_COSTS: dict[str, int] = {
    # --- GoodHound's original model -------------------------------------
    "MemberOf": 0,
    "Contains": 0,
    "GPLink": 0,
    "CanRDP": 0,
    "HasSession": 3,
    "AdminTo": 1,
    "ForceChangePassword": 1,
    "AllowedToDelegate": 1,
    "AllowedToAct": 1,
    "AddAllowedToAct": 1,
    "ReadLAPSPassword": 1,
    "ReadGMSAPassword": 1,
    "HasSIDHistory": 1,
    "CanPSRemote": 1,
    "ExecuteDCOM": 1,
    "SQLAdmin": 1,
    "AddMember": 1,
    "AddSelf": 1,
    "GenericAll": 1,
    "GenericWrite": 1,
    "WriteDacl": 1,
    "WriteOwner": 1,
    "Owns": 1,
    "AllExtendedRights": 1,
    "WriteSPN": 1,
    "AddKeyCredentialLink": 2,
    # --- BloodHound Enterprise additions ---------------------------------
    "DCSync": 2,
    "SyncLAPSPassword": 1,
    "DumpSMSAPassword": 1,
    "WriteAccountRestrictions": 1,
    "WriteGPLink": 1,
    "OwnsLimitedRights": 1,
    "WriteOwnerLimitedRights": 1,
    "CoerceToTGT": 2,
    "GoldenCert": 2,
    "ADCSESC1": 2,
    "ADCSESC3": 2,
    "ADCSESC4": 2,
    "ADCSESC6a": 2,
    "ADCSESC6b": 2,
    "ADCSESC9a": 2,
    "ADCSESC9b": 2,
    "ADCSESC10a": 2,
    "ADCSESC10b": 2,
    "ADCSESC13": 2,
    "CoerceAndRelayNTLMToSMB": 3,
    "CoerceAndRelayNTLMToADCS": 3,
    "CoerceAndRelayNTLMToLDAP": 3,
    "CoerceAndRelayNTLMToLDAPS": 3,
}

# GoodHound priced some rights higher when the target is a Domain object.
# Keys are "EdgeKind->TargetKind".
DEFAULT_TARGETED_COSTS: dict[str, int] = {
    "GenericAll->Domain": 2,
    "WriteDacl->Domain": 2,
    "WriteOwner->Domain": 2,
    "Owns->Domain": 2,
    "AllExtendedRights->Domain": 2,
}

# Short, generic remediation pointers for the weakest-links table.  The
# authoritative remediation text lives in BloodHound Enterprise findings.
REMEDIATION_HINTS: dict[str, str] = {
    "MemberOf": "Review the group nesting / membership; remove it if not required.",
    "HasSession": "Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions).",
    "AdminTo": "Remove local admin rights; use LAPS and least privilege.",
    "CanRDP": "Restrict Remote Desktop Users / RDP logon rights.",
    "CanPSRemote": "Restrict Remote Management Users / WinRM access.",
    "ExecuteDCOM": "Restrict Distributed COM Users membership.",
    "GenericAll": "Remove the over-permissive ACE.",
    "GenericWrite": "Remove the write ACE.",
    "WriteDacl": "Remove the WriteDacl ACE.",
    "WriteOwner": "Remove the WriteOwner ACE.",
    "Owns": "Change the object owner to a Tier Zero principal.",
    "AllExtendedRights": "Remove the AllExtendedRights ACE.",
    "ForceChangePassword": "Remove the reset-password right.",
    "AddMember": "Remove the right to modify group membership.",
    "AddSelf": "Remove the self-membership right.",
    "AddKeyCredentialLink": "Remove write access to msDS-KeyCredentialLink.",
    "ReadLAPSPassword": "Restrict who can read LAPS passwords.",
    "ReadGMSAPassword": "Restrict PrincipalsAllowedToRetrieveManagedPassword.",
    "AllowedToDelegate": "Remove or constrain the delegation configuration.",
    "AllowedToAct": "Clear msDS-AllowedToActOnBehalfOfOtherIdentity.",
    "DCSync": "Remove replication rights from non-Tier Zero principals.",
    "GPLink": "Review who can edit the linked GPO.",
    "Contains": "Review who controls the parent OU/container.",
    "ADCSESC1": "Fix the vulnerable certificate template (ESC1).",
}


@dataclass
class Settings:
    """Run-time options for the analysis."""

    edge_costs: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_EDGE_COSTS))
    targeted_costs: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_TARGETED_COSTS))
    default_cost: int = 1
    max_hops: int = HUNTER_MAX_HOPS
    #: Node label that marks the targets (BloodHound Enterprise Tier Zero).
    target_label: str = "Tag_Tier_Zero"
    #: Restrict start nodes to one domain (``domainsid`` property).
    domain_sid: str | None = None
    #: Also compute paths that start from individual users (GoodHound only did
    #: this when no group had a path).
    include_users: bool = False
    page_size: int = HUNTER_MAX_LIMIT
    #: Max shortest paths fetched per start node (one per reachable target).
    paths_per_start: int = HUNTER_MAX_LIMIT
    concurrency: int = 4
    #: Client-side request rate cap.  Hunter's documented shared limit is
    #: 55 req/s per client IP, so stay well below it.
    rate_limit: float = 10.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_hops <= HUNTER_MAX_HOPS:
            raise ValueError(f"max_hops must be between 1 and {HUNTER_MAX_HOPS} (Hunter limit)")
        for name in ("page_size", "paths_per_start"):
            value = getattr(self, name)
            if not 1 <= value <= HUNTER_MAX_LIMIT:
                raise ValueError(f"{name} must be between 1 and {HUNTER_MAX_LIMIT} (Hunter limit)")

    @property
    def traversable_edges(self) -> list[str]:
        return list(self.edge_costs)

    def cost(self, edge_kind: str, target_kind: str | None = None) -> int:
        if target_kind:
            targeted = self.targeted_costs.get(f"{edge_kind}->{target_kind}")
            if targeted is not None:
                return targeted
        return self.edge_costs.get(edge_kind, self.default_cost)

    @property
    def max_path_cost(self) -> int:
        """Upper bound used to normalise the risk score.

        GoodHound used ``max(hops_in_this_dataset) * 3 + 1``, which makes
        scores incomparable between runs.  Hunter caps traversals at a fixed
        hop count, so a fixed ceiling is used instead.
        """
        worst_edge = max([self.default_cost, *self.edge_costs.values(), *self.targeted_costs.values()])
        return self.max_hops * worst_edge + 1


def load_settings(path: str | Path | None, **overrides: object) -> Settings:
    """Build settings from an optional TOML file plus CLI overrides (non-None only)."""
    data: dict[str, object] = {}
    if path:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        edges = raw.pop("edges", None)
        targeted = raw.pop("targeted_edges", None)
        replace = bool(raw.pop("replace_default_edges", False))
        data.update(raw)
        if edges is not None:
            base = {} if replace else dict(DEFAULT_EDGE_COSTS)
            base.update({str(k): int(v) for k, v in edges.items()})
            data["edge_costs"] = base
        if targeted is not None:
            base_t = dict(DEFAULT_TARGETED_COSTS)
            base_t.update({str(k): int(v) for k, v in targeted.items()})
            data["targeted_costs"] = base_t
    data.update({k: v for k, v in overrides.items() if v is not None})
    known = set(Settings.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown setting(s): {', '.join(sorted(unknown))}")
    return Settings(**data)  # type: ignore[arg-type]
