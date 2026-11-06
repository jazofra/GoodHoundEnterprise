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
    _add_connection(run)
    o = run.add_argument_group("Output")
    o.add_argument(
        "-o", "--output-format", action="append", choices=report.FORMATS, help="Repeatable. Default: stdout + html"
    )
    o.add_argument("-d", "--output-dir", type=Path, default=Path("ghe-reports"))
    o.add_argument("-r", "--results", type=int, default=5, help="Rows in the busiest paths / weakest links tables")
    o.add_argument("--sort", choices=("risk", "users", "hops"), default="risk")
    q = run.add_argument_group("Analysis")
    q.add_argument("-c", "--config", type=Path, help="TOML file with edge costs and settings")
    q.add_argument("--max-hops", type=int, help=f"Max path length (1-{HUNTER_MAX_HOPS}, Hunter limit)")
    q.add_argument("--target-label", help="Label of the target zone (default Tag_Tier_Zero)")
    q.add_argument("--domain-sid", help="Only consider start nodes from this domain")
    q.add_argument(
        "--include-users",
        action="store_true",
        default=None,
        help="Also search from every enabled user (slow on large tenants)",
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

    disc = sub.add_parser("discover", help="Connect to Hunter MCP and list its tools, prompts and status")
    _add_connection(disc, backends=False)
    disc.add_argument("--json", type=Path, help="Also write the catalogue to this file")

    logout = sub.add_parser("logout", help="Forget cached Hunter OAuth tokens for a tenant")
    logout.add_argument("-u", "--url", default=os.environ.get("BHE_URL"), required=os.environ.get("BHE_URL") is None)
    logout.add_argument("--token-dir", type=Path)
    return parser


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
        return "demo (CONTOSO.LOCAL)"
    url = args.url if "://" in args.url else f"https://{args.url}"
    return urlparse(url).hostname or args.url


async def cmd_run(args: argparse.Namespace) -> int:
    settings = load_settings(
        args.config,
        max_hops=args.max_hops,
        target_label=args.target_label,
        domain_sid=args.domain_sid,
        include_users=args.include_users,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
    )
    formats = args.output_format or ["stdout", "html"]
    progress = (lambda msg: None) if args.quiet else (lambda msg: print(f"[*] {msg}", file=sys.stderr))
    async with open_executor(args) as executor:
        source = CypherGraphSource(executor, settings)
        result = await analyse(
            source, tenant=_tenant_name(args), results=args.results, sort=args.sort, progress=progress
        )
    if not args.db_skip:
        delta = history.record(result, args.db)
        result.history = delta.as_dict(result.total_paths)
    if args.quiet:
        formats = [f for f in formats if f != "stdout"]
    written = report.emit(result, formats, args.output_dir)
    for path in written:
        progress(f"Wrote {path}")
    if not result.all_paths:
        progress(f"No paths to {settings.target_label}. Congratulations!")
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
        if args.command == "discover":
            return asyncio.run(cmd_discover(args))
        return cmd_logout(args)
    except (QueryError, UnsafeQueryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
