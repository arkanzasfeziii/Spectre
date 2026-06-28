"""Banner, legal warning, and result formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from spectre.config import AUTHOR, LEGAL_WARNING, TOOL_NAME, VERSION
from spectre.models import EngagementContext

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False


def print_banner() -> None:
    if HAS_PYFIGLET:
        print(f"\033[35m{pyfiglet.figlet_format('Spectre', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  OSINT & Passive Reconnaissance\033[0m\n")


def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False


def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    print(f"\n\033[35m{'═' * 60}\n  RECON RESULTS\n{'═' * 60}\033[0m")
    print(f"  Total: {len(ctx.results)} | Success: \033[32m{success}\033[0m\n")

    for domain in ctx.targets:
        subs = ctx.subdomains.get(domain, set())
        emails = ctx.emails.get(domain, set())
        if subs:
            print(f"  \033[36m[Subdomains] {domain}: {len(subs)} found\033[0m")
        if emails:
            print(f"  \033[36m[Emails] {domain}: {len(emails)} found\033[0m")

    icons = {"SUCCESS": "\033[32m[+]", "FAILED": "\033[31m[x]",
             "PARTIAL": "\033[33m[~]", "INFO": "\033[36m[*]"}
    reset = "\033[0m"
    for r in ctx.results:
        c = icons.get(r.status, "\033[36m[*]")
        print(f"  {c}{reset} [{r.module}] {r.action}")
        if r.notes:
            print(f"        {r.notes}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION, "targets": ctx.targets,
            "subdomains": {d: list(s) for d, s in ctx.subdomains.items()},
            "emails": {d: list(e) for d, e in ctx.emails.items()},
            "dns_records": ctx.dns_records,
            "certificates": ctx.certificates,
            "results": [{"module": r.module, "action": r.action, "status": r.status,
                         "severity": r.severity, "notes": r.notes} for r in ctx.results],
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")
