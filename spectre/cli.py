"""Command-line interface for Spectre."""

from __future__ import annotations

import argparse
import textwrap
from typing import List

from spectre.config import COMMAND, TOOL_NAME, VERSION
from spectre.logger import log
from spectre.models import EngagementContext
from spectre.modules import (
    CertModule, DNSIntelModule, EmailModule,
    SearchModule, SocialModule, SubdomainModule,
)
from spectre.output import dump_results, print_banner, print_legal

MODULE_REGISTRY = {
    "scan": SubdomainModule,
    "email": EmailModule,
    "dns": DNSIntelModule,
    "cert": CertModule,
    "search": SearchModule,
    "social": SocialModule,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --domain example.com --modules scan
              {COMMAND} --targets domains.txt --modules dns cert
              {COMMAND} --domain example.com --modules all --output recon.json
        """),
    )
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--domain", "-d")
    target_group.add_argument("--targets", "-t", help="File with domains")
    p.add_argument("--modules", "-m", nargs="+",
                   choices=["scan", "email", "dns", "cert", "search", "social", "all"],
                   default=["scan"])
    p.add_argument("--output", "-o")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--stealth", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    if not print_legal(args.yes):
        return 1

    targets: List[str] = []
    if args.domain:
        targets.append(args.domain.strip().lower())
    elif args.targets:
        try:
            with open(args.targets) as f:
                targets = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            log(f"Target file not found: {args.targets}", "ERR")
            return 1

    if not targets:
        log("No targets specified.", "ERR")
        return 1

    if args.stealth:
        args.delay = max(args.delay, 2.0)
        args.threads = min(args.threads, 3)
        log("Stealth mode enabled", "WARN")

    ctx = EngagementContext(
        targets=targets, threads=args.threads, timeout=args.timeout,
        delay=args.delay, stealth=args.stealth, output_file=args.output,
    )

    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        mod_cls = MODULE_REGISTRY.get(mod_name)
        if not mod_cls:
            continue
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            ctx.results.extend(mod.run(ctx))
        except KeyboardInterrupt:
            log("Interrupted", "WARN")
            break
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0
