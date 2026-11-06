"""Agent fleet: deterministic analysis first, then one Claude agent per weakest link / busiest path,
code verification of their claims, and a synthesizer that writes the remediation plan."""

from .orchestrator import FleetConfig, FleetResult, run_fleet

__all__ = ["FleetConfig", "FleetResult", "run_fleet"]
