"""Command-line interface.

goodhound-enterprise run --backend demo
goodhound-enterprise discover --url https://acme.bloodhoundenterprise.io
goodhound-enterprise run --url https://acme.bloodhoundenterprise.io -o stdout -o html
goodhound-enterprise run --backend rest --url https://acme.bloodhoundenterprise.io   # BHE_TOKEN_ID / BHE_TOKEN_KEY
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__, history, report
from .analysis import analyse
from .backends.base import QueryError
from .config import HUNTER_MAX_HOPS, load_settings
from .cypher import UnsafeQueryError
from .source import CypherGraphSource

EPILOG = "Attackers think in graphs, defenders think in actions, management think in charts."


def _kv(value: str) -> tuple[str, Any]:
    key, sep, raw = value.partition("=")
    if not sep:
        raise argparse.ArgumentTypeError("expected key=value")
    try:
        return key, json.loads(raw)
    except ValueError:
        return key, raw


def _add_connection(p: argparse.ArgumentParser, *, backends: bool = True) -> None:
    g = p.add_argument_group("Connection")
    if backends:
        g.add_argument(
            "-b",
            "--backend",
            choices=("hunter", "rest", "demo"),
            default="hunter",
            help="hunter = Hunter MCP (default); rest = BHE API token; demo = built-in sample data",
        )
    g.add_argument(
        "-u",
        "--url",
        default=os.environ.get("BHE_URL"),
        help="BloodHound Enterprise tenant URL (or the full Hunter MCP URL). Env: BHE_URL",
    )
    h = p.add_argument_group("Hunter MCP")
    h.add_argument("--cypher-tool", help="Name of Hunter's Cypher tool (auto-discovered by default)")
    h.add_argument("--cypher-arg", help="Argument of the Cypher tool that takes the query (auto by default)")
    h.add_argument(
        "--tool-arg",
        action="append",
        type=_kv,
        default=[],
        metavar="KEY=VALUE",
        help="Extra fixed argument for the Cypher tool (repeatable), e.g. info_type=run",
    )
    h.add_argument("--callback-port", type=int, default=8765, help="Loopback port for the OAuth redirect")
    h.add_argument("--no-browser", action="store_true", help="Print the authorization URL instead of opening it")
    h.add_argument(
        "--manual-callback",
        action="store_true",
        help="Paste the redirect URL instead of running a loopback listener (headless hosts)",
    )
    h.add_argument(
        "--token-dir", type=Path, help="Where OAuth tokens are cached (default ~/.config/goodhound-enterprise)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goodhound-enterprise",
        description="GoodHound-style busiest attack paths and weakest links for BloodHound Enterprise.",
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Analyse the tenant and write the reports", epilog=EPILOG)
    _add_run_args(run, default_formats="stdout + html")

    fleet = sub.add_parser(
        "fleet",
        help="Analyse, then send AI agents to investigate the weakest links and busiest paths",
        epilog="Needs the 'fleet' extra (pip install 'goodhound-enterprise[fleet]') and Claude API credentials.",
    )
    _add_run_args(fleet, default_formats="html")
    f = fleet.add_argument_group("Agent fleet")
    f.add_argument("--links", type=int, default=5, help="Weakest links to investigate (one agent each)")
    f.add_argument("--paths", type=int, default=3, help="Busiest paths to validate (one agent each)")
    f.add_argument("--worker-model", default="claude-sonnet-5-5", help="Model for the analyst agents")
    f.add_argument("--worker-effort", default="medium", choices=("low", "medium", "high", "xhigh", "max"))
    f.add_argument("--lead-model", default="claude-opus-5-5", help="Model that writes the remediation plan")
    f.add_argument("--lead-effort", default="high", choices=("low", "medium", "high", "xhigh", "max"))
    f.add_argument("--agents", type=int, default=4, help="Agents running at the same time")
    f.add_argument("--max-turns", type=int, default=16, help="Model turns per analyst agent")
    f.add_argument(
        "--token-budget",
        type=int,
        default=3_000_000,
        help="Total tokens (input+output+cache) after which no new agent turns start",
    )
    f.add_argument(
        "--no-fallbacks",
        action="store_true",
        help="Do not let the API retry a declined request on its recommended fallback model",
    )
    f.add_argument("--dry-run", action="store_true", help="Run the analysis and print the agent tasks; call no model")

    disc = sub.add_parser("discover", help="Connect to Hunter MCP and list its tools, prompts and status")
    _add_connection(disc, backends=False)
    disc.add_argument("--json", type=Path, help="Also write the catalogue to this file")

    logout = sub.add_parser("logout", help="Forget cached Hunter OAuth tokens for a tenant")
    logout.add_argument("-u", "--url", default=os.environ.get("BHE_URL"), required=os.environ.get("BHE_URL") is None)
    logout.add_argument("--token-dir", type=Path)
    return parser


def _add_run_args(run: argparse.ArgumentParser, *, default_formats: str) -> None:
    _add_connection(run)
    o = run.add_argument_group("Output")
    o.add_argument(
        "-o", "--output-format", action="append", choices=report.FORMATS, help=f"Repeatable. Default: {default_formats}"
    )
    o.add_argument("-d", "--output-dir", type=Path, default=Path("ghe-reports"))
    o.add_argument("-r", "--results", type=int, default=5, help="Rows in the busiest paths / weakest links tables")
    o.add_argument("--sort", choices=("risk", "users", "hops", "probability"), default="risk")
    q = run.add_argument_group("Analysis")
    q.add_argument("-c", "--config", type=Path, help="TOML file with edge costs and settings")
    q.add_argument("--max-hops", type=int, help=f"Max path length (1-{HUNTER_MAX_HOPS}, Hunter limit)")
    q.add_argument("--target-label", help="Label of the target zone (default Tag_Tier_Zero)")
    q.add_argument(
        "--target-objectid",
        help="Measure who can reach this one object (its inbound exposure) instead of the target zone",
    )
    q.add_argument("--domain-sid", help="Only consider start nodes from this domain")
    q.add_argument(
        "--include-users",
        action="store_true",
        default=None,
        help="Also search from every enabled user (slow on large tenants)",
    )
    q.add_argument(
        "--risk-model",
        choices=("probability", "goodhound"),
        help="probability (default): reach probability x users, links ranked by exposure removed; "
        "goodhound: the original cost formula",
    )
    q.add_argument(
        "--detection",
        type=float,
        dest="per_action_detection",
        help="Chance (0-1) that each attacker action is detected and stopped (default 0.05)",
    )
    q.add_argument(
        "--session-half-life",
        type=float,
        dest="session_half_life_days",
        help="Days after which a session's probability halves (default 14, 0 = no decay)",
    )
    q.add_argument(
        "--reuse-suffixes",
        action="store_true",
        default=None,
        help="Fewer queries: intermediate groups reuse another group's path (reach may be underestimated)",
    )
    q.add_argument(
        "--one-path-per-target",
        action="store_false",
        default=None,
        dest="all_shortest_paths",
        help="Use shortestPath instead of allShortestPaths (fewer alternatives counted)",
    )
    q.add_argument(
        "--opengraph",
        action="append",
        metavar="PREFIX[,PREFIX]",
        help="Also traverse OpenGraph extension edges by kind prefix, e.g. --opengraph CyberArk,MSSQL "
        "(traversable kinds come from the tenant's Hunter capability catalog)",
    )
    q.add_argument(
        "--dual-control-probability",
        type=float,
        dest="dual_control_probability",
        help="Chance (0-1) of getting a CyberArk dual-control password release approved (default 0.25)",
    )
    q.add_argument("--concurrency", type=int, help="Parallel queries (default 4)")
    q.add_argument("--rate-limit", type=float, help="Max queries per second (default 10)")
    d = run.add_argument_group("History")
    d.add_argument("--db", type=Path, default=Path("goodhound-enterprise.db"), help="SQLite history file")
    d.add_argument("--db-skip", action="store_true", help="Do not read or write history")
    lg = run.add_argument_group("Logging")
    lg.add_argument("-q", "--quiet", action="store_true")
    lg.add_argument("-v", "--verbose", action="store_true")
    lg.add_argument("--debug", action="store_true")


@asynccontextmanager
async def open_executor(args: argparse.Namespace):
    backend = getattr(args, "backend", "hunter")
    if backend == "demo":
        from .backends.demo import DemoExecutor

        yield DemoExecutor()
        return
    if not args.url:
        raise SystemExit("--url (or BHE_URL) is required for the hunter and rest backends")
    if backend == "rest":
        from .backends.rest import RestExecutor

        token_id, token_key = os.environ.get("BHE_TOKEN_ID"), os.environ.get("BHE_TOKEN_KEY")
        if not token_id or not token_key:
            raise SystemExit("Set BHE_TOKEN_ID and BHE_TOKEN_KEY for the rest backend")
        executor = RestExecutor(args.url, token_id, token_key)
        try:
            yield executor
        finally:
            await executor.aclose()
        return
    from .backends.hunter import HunterExecutor

    async with HunterExecutor.connect(
        args.url,
        token_dir=args.token_dir,
        callback_port=args.callback_port,
        open_browser=not args.no_browser,
        manual_callback=args.manual_callback,
        cypher_tool=args.cypher_tool,
        cypher_arg=args.cypher_arg,
        extra_args=dict(args.tool_arg),
    ) as executor:
        await executor.setup()
        yield executor


def _tenant_name(args: argparse.Namespace) -> str:
    if getattr(args, "backend", None) == "demo":
        name = "demo (CONTOSO.LOCAL)"
    else:
        url = args.url if "://" in args.url else f"https://{args.url}"
        name = urlparse(url).hostname or args.url
    # History is keyed by tenant: keep target-object runs apart from Tier Zero runs.
    target = getattr(args, "target_objectid", None)
    return f"{name} [target {target}]" if target else name


def _settings(args: argparse.Namespace):
    return load_settings(
        args.config,
        max_hops=args.max_hops,
        target_label=args.target_label,
        target_objectid=args.target_objectid,
        domain_sid=args.domain_sid,
        include_users=args.include_users,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        risk_model=args.risk_model,
        per_action_detection=args.per_action_detection,
        session_half_life_days=args.session_half_life_days,
        reuse_suffixes=args.reuse_suffixes,
        opengraph=[p.strip() for v in args.opengraph for p in v.split(",") if p.strip()] if args.opengraph else None,
        dual_control_probability=args.dual_control_probability,
        all_shortest_paths=args.all_shortest_paths,
    )


def _progress(args: argparse.Namespace):
    return (lambda msg: None) if args.quiet else (lambda msg: print(f"[*] {msg}", file=sys.stderr))


def _finish_analysis(args: argparse.Namespace, result, formats: list[str], progress) -> None:
    if not args.db_skip:
        delta = history.record(result, args.db)
        result.history = delta.as_dict(result.total_paths)
    if args.quiet:
        formats = [f for f in formats if f != "stdout"]
    for path in report.emit(result, formats, args.output_dir):
        progress(f"Wrote {path}")
    if not result.all_paths:
        progress(f"No paths to {result.settings.target_description}. Congratulations!")


async def cmd_run(args: argparse.Namespace) -> int:
    settings = _settings(args)
    progress = _progress(args)
    async with open_executor(args) as executor:
        source = CypherGraphSource(executor, settings)
        result = await analyse(
            source, tenant=_tenant_name(args), results=args.results, sort=args.sort, progress=progress
        )
    _finish_analysis(args, result, args.output_format or ["stdout", "html"], progress)
    return 0


async def cmd_fleet(args: argparse.Namespace) -> int:
    from .fleet import FleetConfig, run_fleet
    from .fleet import report as fleet_report
    from .fleet.gateway import Gateway
    from .fleet.orchestrator import plan_tasks

    settings = _settings(args)
    progress = _progress(args)
    cfg = FleetConfig(
        links=args.links,
        paths=args.paths,
        worker_model=args.worker_model,
        worker_effort=args.worker_effort,
        lead_model=args.lead_model,
        lead_effort=args.lead_effort,
        concurrency=args.agents,
        max_turns=args.max_turns,
        token_budget=args.token_budget,
        fallbacks=not args.no_fallbacks,
    )
    if not args.dry_run:
        try:  # fail before the (long) analysis, not after it
            from anthropic import AsyncAnthropic
        except ImportError:
            raise SystemExit("The fleet needs the Anthropic SDK: pip install 'goodhound-enterprise[fleet]'") from None
    async with open_executor(args) as executor:
        source = CypherGraphSource(executor, settings)
        results = max(args.results, args.links, args.paths)
        result = await analyse(source, tenant=_tenant_name(args), results=results, sort=args.sort, progress=progress)
        _finish_analysis(args, result, args.output_format or ["html"], progress)
        tasks = plan_tasks(result, cfg)
        if args.dry_run:
            for task in tasks:
                print(f"--- {task.item} ({task.kind}) ---\n{task.prompt}\n")
            progress(f"Dry run: {len(tasks)} agents would be launched; no model was called")
            return 0
        if not tasks:
            progress("Nothing for the fleet to investigate")
            return 0
        hunter = executor if getattr(executor, "name", "") == "hunter" else None
        gateway = Gateway(source, result, hunter)
        client = AsyncAnthropic()
        try:
            fleet_result = await run_fleet(gateway, client, cfg, progress)
        finally:
            await client.close()
    for path in fleet_report.write(fleet_result, args.output_dir):
        progress(f"Wrote {path}")
    if fleet_result.plan_error:
        progress(f"No remediation plan: {fleet_result.plan_error}")
        return 1
    return 0


async def cmd_discover(args: argparse.Namespace) -> int:
    args.backend = "hunter"
    from .backends.hunter import HunterExecutor

    if not args.url:
        raise SystemExit("--url (or BHE_URL) is required")
    async with HunterExecutor.connect(
        args.url,
        token_dir=args.token_dir,
        callback_port=args.callback_port,
        open_browser=not args.no_browser,
        manual_callback=args.manual_callback,
        cypher_tool=args.cypher_tool,
        cypher_arg=args.cypher_arg,
        extra_args=dict(args.tool_arg),
    ) as executor:
        catalogue = await executor.describe()
    text = json.dumps(catalogue, indent=2, default=str)
    if args.json:
        args.json.write_text(text)
    for tool in catalogue["tools"]:
        props = ", ".join((tool.get("input_schema") or {}).get("properties", {}) or [])
        print(f"tool    {tool['name']}({props})\n        {(tool.get('description') or '').strip()[:160]}")
    for prompt in catalogue.get("prompts", []):
        print(f"prompt  {prompt['name']}\n        {(prompt.get('description') or '').strip()[:160]}")
    print(f"\nCypher tool selected: {catalogue['selected_cypher_tool']}")
    if "bloodhound_status" in catalogue:
        print(f"bloodhound_status: {json.dumps(catalogue['bloodhound_status'])[:400]}")
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    from .backends.hunter import FileTokenStorage, default_token_dir, hunter_url

    storage = FileTokenStorage(args.token_dir or default_token_dir(), hunter_url(args.url))
    storage.clear()
    print(f"Removed cached tokens for {hunter_url(args.url)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING
    if getattr(args, "debug", False):
        level = logging.DEBUG
    elif getattr(args, "verbose", False):
        level = logging.INFO
    elif getattr(args, "quiet", False):
        level = logging.CRITICAL
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    try:
        if args.command == "run":
            return asyncio.run(cmd_run(args))
        if args.command == "fleet":
            return asyncio.run(cmd_fleet(args))
        if args.command == "discover":
            return asyncio.run(cmd_discover(args))
        return cmd_logout(args)
    except (QueryError, UnsafeQueryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
