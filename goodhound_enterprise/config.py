"""Settings, traversable edge kinds and the exploit-cost model.

GoodHound wrote an ``r.cost`` property onto every relationship in Neo4j before
querying.  Hunter MCP is read-only, so the same cost model is applied on the
client instead.  The defaults reproduce GoodHound's weights for the edges it
knew about and add weights for edges BloodHound Enterprise has introduced since
(ADCS, DCSync post-processing, NTLM relay, ...).  Every value can be overridden
from a TOML file (see ``examples/config.example.toml``).
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

#: Hunter rejects variable-length traversals longer than this.
HUNTER_MAX_HOPS = 10
#: Hunter requires a terminal literal ``LIMIT`` between 1 and this value.
HUNTER_MAX_LIMIT = 100
#: Hunter rejects list literals with more items than this ("can materialize an unbounded collection").
HUNTER_MAX_LIST = 100

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

# --------------------------------------------------------------------------
# Probability model
# --------------------------------------------------------------------------
# Chance that an attacker who controls the source of a relationship can use it
# to take control of the target, with public tooling and without special luck.
# These are calibration defaults (see docs/RISK_MODEL.md), not measurements:
# override them per environment in the TOML file under [edge_probability].
DEFAULT_EDGE_PROBABILITY: dict[str, float] = {
    # Structural: no attacker action needed.
    "MemberOf": 1.0,
    "Contains": 1.0,
    "GPLink": 0.95,  # the modified GPO still has to apply (refresh, filtering)
    # Direct control: reliable, well-documented abuse.
    "GenericAll": 0.9,
    "GenericWrite": 0.9,
    "WriteDacl": 0.9,
    "WriteOwner": 0.9,
    "Owns": 0.9,
    "AllExtendedRights": 0.9,
    "AddMember": 0.95,
    "AddSelf": 0.95,
    "ForceChangePassword": 0.95,
    "ReadLAPSPassword": 0.95,
    "ReadGMSAPassword": 0.95,
    "SyncLAPSPassword": 0.9,
    "DumpSMSAPassword": 0.9,
    "DCSync": 0.95,
    "HasSIDHistory": 0.9,
    "AdminTo": 0.9,
    "SQLAdmin": 0.8,
    "OwnsLimitedRights": 0.85,
    "WriteOwnerLimitedRights": 0.85,
    "WriteGPLink": 0.8,
    "WriteAccountRestrictions": 0.8,
    # Need extra conditions or tooling.
    "AllowedToDelegate": 0.85,
    "AllowedToAct": 0.85,
    "AddAllowedToAct": 0.8,
    "AddKeyCredentialLink": 0.8,  # needs PKINIT support on a DC
    "WriteSPN": 0.5,  # targeted Kerberoast: the password still has to crack
    "GoldenCert": 0.9,
    "ADCSESC1": 0.9,
    "ADCSESC3": 0.85,
    "ADCSESC4": 0.85,
    "ADCSESC6a": 0.8,
    "ADCSESC6b": 0.8,
    "ADCSESC9a": 0.7,
    "ADCSESC9b": 0.7,
    "ADCSESC10a": 0.7,
    "ADCSESC10b": 0.7,
    "ADCSESC13": 0.85,
    "CoerceToTGT": 0.6,
    # Non-admin interactive access: harvesting a session still needs local
    # privilege escalation on the host.
    "CanRDP": 0.4,
    "CanPSRemote": 0.4,
    "ExecuteDCOM": 0.4,
    # The privileged session must be present when the attacker acts, and
    # Credential Guard / Protected Users may stop the theft. Decays with age.
    "HasSession": 0.6,
    "CoerceAndRelayNTLMToSMB": 0.5,
    "CoerceAndRelayNTLMToADCS": 0.6,
    "CoerceAndRelayNTLMToLDAP": 0.5,
    "CoerceAndRelayNTLMToLDAPS": 0.5,
}

DEFAULT_TARGETED_PROBABILITY: dict[str, float] = {}

#: Relationships that need no attacker action; they never count as an action
#: hop and are not exposed to per-action detection.
STRUCTURAL_EDGES = frozenset({"MemberOf", "Contains", "GPLink"})

# --------------------------------------------------------------------------
# OpenGraph extensions (opt-in with ``opengraph = ["CyberArk", "MSSQL"]``)
# --------------------------------------------------------------------------
# Which relationship kinds are traversable comes from the tenant at run time
# (Hunter's graph capability catalog); these tables only supply calibration
# defaults. Kinds without an entry use ``default_probability``.
OPENGRAPH_EDGE_PROBABILITY: dict[str, float] = {
    # CyberArk (CyberArkHound): identity sync and containment are structural.
    "CyberArk_SyncsToUser": 1.0,
    "CyberArk_SyncsToGroup": 1.0,
    "CyberArk_MemberOf": 1.0,
    "CyberArk_Contains": 1.0,
    "CyberArk_SyncsToADUser": 1.0,  # holding the vaulted credential is being that AD user
    "CyberArk_HasAccessTo": 0.9,  # retrieve/use the password; OTP or exclusive access may slow it down
    "CyberArk_CanRetrieveViaCCP": 0.85,  # needs code execution on an allowed application host
    "CyberArk_CanGrantAccessTo": 0.8,  # grant yourself access first; audited
    "CyberArk_ManagedBy": 0.8,
    "CyberArk_CanHijackViaReconcile": 0.7,
    "CyberArk_CanConnect": 0.6,  # PSM session: isolated and monitored, no password disclosed
    # MSSQL (MSSQLHound)
    "MSSQL_MemberOf": 1.0,
    "MSSQL_Contains": 1.0,
    "MSSQL_HasLogin": 1.0,  # an AD principal acting through its own login
    "MSSQL_ControlServer": 0.9,
    "MSSQL_ControlDB": 0.9,
    "MSSQL_Owns": 0.9,
    "MSSQL_AddMember": 0.9,
    "MSSQL_ChangePassword": 0.9,
    "MSSQL_ExecuteAs": 0.9,
    "MSSQL_ExecuteAsOwner": 0.85,
    "MSSQL_GrantAnyPermission": 0.85,
    "MSSQL_GrantAnyDBPermission": 0.85,
    "MSSQL_ServiceAccountFor": 0.9,
    "MSSQL_HostFor": 0.85,
    "MSSQL_ExecuteOnHost": 0.8,
    "MSSQL_LinkedAsAdmin": 0.8,
    "MSSQL_GetAdminTGS": 0.7,
    "MSSQL_GetTGS": 0.6,
    "MSSQL_HasDBScopedCred": 0.6,  # the stored credential may not be usable
    "MSSQL_HasMappedCred": 0.6,
    "MSSQL_HasProxyCred": 0.6,
    "MSSQL_CoerceAndRelayToMSSQL": 0.5,
}

OPENGRAPH_STRUCTURAL_EDGES = frozenset(
    {
        "CyberArk_SyncsToUser",
        "CyberArk_SyncsToGroup",
        "CyberArk_MemberOf",
        "CyberArk_Contains",
        "CyberArk_SyncsToADUser",
        "MSSQL_MemberOf",
        "MSSQL_Contains",
        "MSSQL_HasLogin",
    }
)

#: Relationships into a CyberArk account that are gated by the account platform's
#: dual-control setting (CCP retrieval by applications is not).
DUAL_CONTROL_GATED_EDGES = frozenset({"CyberArk_HasAccessTo", "CyberArk_CanGrantAccessTo", "CyberArk_Contains"})

RISK_MODELS = ("probability", "goodhound")

# Simple settings by type, so a wrong type in the TOML file is reported by name.
_INT_SETTINGS = (
    "default_cost",
    "max_hops",
    "page_size",
    "paths_per_start",
    "concurrency",
    "exact_path_limit",
    "monte_carlo_samples",
    "exposure_levels",
)
_NUMBER_SETTINGS = (
    "rate_limit",
    "default_probability",
    "per_action_detection",
    "session_half_life_days",
    "dual_control_probability",
)
_BOOL_SETTINGS = ("include_users", "all_shortest_paths", "reuse_suffixes", "stitch")
_TEXT_SETTINGS = ("target_label", "target_objectid", "domain_sid", "risk_model")
#: Settings that change how fast a run goes but not what it finds.
_THROUGHPUT_SETTINGS = frozenset({"concurrency", "rate_limit", "page_size"})

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
    "CyberArk_HasAccessTo": "Remove the safe/account permission, or move the account to a dual-control platform.",
    "CyberArk_CanGrantAccessTo": "Remove Manage Safe Members from non-Tier Zero identities.",
    "CyberArk_SyncsToGroup": "Review which AD group is mapped to this CyberArk group.",
    "CyberArk_SyncsToADUser": "Keep Tier Zero credentials in dedicated, dual-control safes.",
    "MSSQL_HasLogin": "Remove the SQL login or reduce its server privileges.",
    "MSSQL_ExecuteOnHost": "Disable xp_cmdshell/agent jobs or run SQL Server as a low-privilege account.",
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
    #: Measure who can reach this one object instead of the Tier Zero label (its
    #: inbound exposure), e.g. a sensitive group that is not Tier Zero itself.
    target_objectid: str | None = None
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

    # --- risk model -------------------------------------------------------
    #: "probability" (default) or "goodhound" (the original cost formula).
    risk_model: str = "probability"
    edge_probability: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_EDGE_PROBABILITY))
    targeted_probability: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_TARGETED_PROBABILITY))
    default_probability: float = 0.7
    #: Chance that each attacker *action* (non-structural hop) is detected and
    #: stopped. Makes every extra action hop cost something.
    per_action_detection: float = 0.05
    #: HasSession probability halves every N days since the session was last
    #: seen (0 disables the decay).
    session_half_life_days: float = 14.0
    #: Paths enumerated per start node for the exact reach probability; above
    #: this a seeded Monte Carlo estimate is used.
    exact_path_limit: int = 12
    monte_carlo_samples: int = 4000
    #: Distinct probability levels used for distinct-user exposure queries.
    exposure_levels: int = 25
    #: Fetch every equally short path (allShortestPaths) rather than one per target,
    #: so alternative routes count in the reach probability. Falls back automatically.
    all_shortest_paths: bool = True
    #: Reuse an intermediate group's suffix of another group's path instead of
    #: querying it (fewer queries, but its reach can be underestimated).
    reuse_suffixes: bool = False
    #: Join paths longer than ``max_hops``: a start node with no path inside the limit is
    #: connected to the groups it reaches that have a path of their own. Costs one extra
    #: query per start node without a path.
    stitch: bool = True
    #: OpenGraph extensions to traverse, by relationship-kind prefix (e.g. "CyberArk",
    #: "MSSQL"). The traversable kinds are resolved from the tenant when the run starts.
    opengraph: list[str] = field(default_factory=list)
    #: Chance of getting a password release approved when the account's CyberArk platform
    #: requires dual control: the attacker must also compromise or deceive an approver.
    dual_control_probability: float = 0.25

    def _check_types(self) -> None:
        def is_number(value: object) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        for name in _INT_SETTINGS:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be a whole number, got {value!r}")
        for name in _NUMBER_SETTINGS:
            if not is_number(getattr(self, name)):
                raise ValueError(f"{name} must be a number, got {getattr(self, name)!r}")
        for name in _BOOL_SETTINGS:
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false, got {getattr(self, name)!r}")
        for name in _TEXT_SETTINGS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be text, got {value!r}")
        if not isinstance(self.opengraph, list) or not all(isinstance(p, str) for p in self.opengraph):
            raise ValueError(f"opengraph must be a list of names, got {self.opengraph!r}")
        tables = {
            "edges": self.edge_costs,
            "targeted_edges": self.targeted_costs,
            "edge_probability": self.edge_probability,
            "targeted_edge_probability": self.targeted_probability,
        }
        for table, values in tables.items():
            if not isinstance(values, dict):
                raise ValueError(f"[{table}] must be a table of relationship kind = value")
            whole = table in ("edges", "targeted_edges")  # costs
            for kind, value in values.items():
                if not is_number(value) or (whole and not isinstance(value, int)):
                    kind_of = "a whole number" if whole else "a number"
                    raise ValueError(f"[{table}] {kind} must be {kind_of}, got {value!r}")

    def __post_init__(self) -> None:
        self._check_types()
        if not 1 <= self.max_hops <= HUNTER_MAX_HOPS:
            raise ValueError(f"max_hops must be between 1 and {HUNTER_MAX_HOPS} (Hunter limit)")
        for name in ("page_size", "paths_per_start"):
            value = getattr(self, name)
            if not 1 <= value <= HUNTER_MAX_LIMIT:
                raise ValueError(f"{name} must be between 1 and {HUNTER_MAX_LIMIT} (Hunter limit)")
        if self.risk_model not in RISK_MODELS:
            raise ValueError(f"risk_model must be one of {', '.join(RISK_MODELS)}")
        probabilities = {
            **self.edge_probability,
            **self.targeted_probability,
            "default_probability": self.default_probability,
            "per_action_detection": self.per_action_detection,
            "dual_control_probability": self.dual_control_probability,
        }
        for name, value in probabilities.items():
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"Probability for {name} must be between 0 and 1, got {value}")
        if self.session_half_life_days < 0:
            raise ValueError("session_half_life_days must be >= 0")
        if not 1 <= self.exact_path_limit <= 16:
            raise ValueError("exact_path_limit must be between 1 and 16")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.rate_limit < 0:
            raise ValueError("rate_limit must be 0 (no limit) or more")
        for name in ("monte_carlo_samples", "exposure_levels"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")

    def fingerprint(self) -> str:
        """Hash of every setting that changes what a run finds or how it is scored.

        Two runs are only comparable (trend, new and resolved paths) when it matches.
        """
        relevant = {
            name: getattr(self, name) for name in sorted(self.__dataclass_fields__) if name not in _THROUGHPUT_SETTINGS
        }
        return hashlib.sha256(json.dumps(relevant, sort_keys=True, default=str).encode()).hexdigest()[:16]

    @property
    def traversable_edges(self) -> list[str]:
        return list(dict.fromkeys([*self.edge_costs, *self.edge_probability]))

    @property
    def target_description(self) -> str:
        return f"object {self.target_objectid}" if self.target_objectid else self.target_label

    @property
    def structural_edges(self) -> frozenset[str]:
        return STRUCTURAL_EDGES | OPENGRAPH_STRUCTURAL_EDGES

    def add_edges(self, kinds: Iterable[str]) -> list[str]:
        """Make extra (OpenGraph) relationship kinds traversable; values already set (TOML) win."""
        added = []
        for kind in kinds:
            if kind not in self.edge_probability:
                self.edge_probability[kind] = OPENGRAPH_EDGE_PROBABILITY.get(kind, self.default_probability)
            if kind not in self.edge_costs:
                self.edge_costs[kind] = 0 if kind in self.structural_edges else self.default_cost
            added.append(kind)
        return added

    def probability(
        self,
        edge_kind: str,
        target_kind: str | None = None,
        last_seen: str | None = None,
        now: datetime | None = None,
    ) -> float:
        """Effective chance that an attacker gets across one relationship.

        technique probability x session freshness (HasSession only)
        x (1 - per-action detection) for every non-structural hop.
        """
        p = None
        if target_kind:
            p = self.targeted_probability.get(f"{edge_kind}->{target_kind}")
        if p is None:
            p = self.edge_probability.get(edge_kind, self.default_probability)
        if edge_kind == "HasSession" and self.session_half_life_days and last_seen and now:
            age = _age_days(last_seen, now)
            if age is not None and age > 0:
                p *= 0.5 ** (age / self.session_half_life_days)
        if edge_kind not in self.structural_edges:
            p *= 1.0 - self.per_action_detection
        return max(0.0, min(1.0, p))

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
        try:
            with open(path, "rb") as fh:
                raw = tomllib.load(fh)
        except OSError as exc:
            raise ValueError(f"Cannot read the config file {path}: {exc.strerror or exc}") from None
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"The config file {path} is not valid TOML: {exc}") from None
        for table in ("edges", "targeted_edges", "edge_probability", "targeted_edge_probability"):
            if table in raw and not isinstance(raw[table], dict):
                raise ValueError(f"[{table}] must be a table of relationship kind = value")
        edges = raw.pop("edges", None)
        targeted = raw.pop("targeted_edges", None)
        replace = bool(raw.pop("replace_default_edges", False))
        probabilities = raw.pop("edge_probability", None)
        targeted_p = raw.pop("targeted_edge_probability", None)
        data.update(raw)
        if probabilities is not None:
            base_p = {} if replace else dict(DEFAULT_EDGE_PROBABILITY)
            base_p.update({str(k): v for k, v in probabilities.items()})
            data["edge_probability"] = base_p
        elif replace:
            data["edge_probability"] = {}
        if targeted_p is not None:
            base_tp = dict(DEFAULT_TARGETED_PROBABILITY)
            base_tp.update({str(k): v for k, v in targeted_p.items()})
            data["targeted_probability"] = base_tp
        if edges is not None:
            base = {} if replace else dict(DEFAULT_EDGE_COSTS)
            base.update({str(k): v for k, v in edges.items()})
            data["edge_costs"] = base
        if targeted is not None:
            base_t = dict(DEFAULT_TARGETED_COSTS)
            base_t.update({str(k): v for k, v in targeted.items()})
            data["targeted_costs"] = base_t
    data.update({k: v for k, v in overrides.items() if v is not None})
    known = set(Settings.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown setting(s): {', '.join(sorted(unknown))}")
    return Settings(**data)  # type: ignore[arg-type]


def _age_days(last_seen: str, now: datetime) -> float | None:
    try:
        seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return None
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return (now - seen).total_seconds() / 86400
