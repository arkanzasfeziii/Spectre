"""Enumerate subdomains via certificate transparency, DNS brute-force, and resolution."""

from __future__ import annotations

import concurrent.futures
import random
import string
from typing import Dict, List, Optional, Set, Tuple

from spectre.models import AttackResult, EngagementContext
from spectre.logger import log
from spectre.modules.base import BaseModule
from spectre.utils.network import resolve_host

from spectre.data import SUBDOMAIN_WORDLIST

try:
    import requests
    REQUESTS = True
except ImportError:
    REQUESTS = False


class SubdomainModule(BaseModule):
    """Enumerate subdomains via certificate transparency, DNS brute-force, and resolution."""

    name = "subdomain"

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            log(f"[Subdomain] Starting enumeration for {domain}", "INFO")
            found: Set[str] = set()

            # Wildcard detection
            wildcard_ip = self._detect_wildcard(domain)
            if wildcard_ip:
                log(f"[Subdomain] Wildcard DNS detected for *.{domain} -> {wildcard_ip}", "WARN")
                results.append(AttackResult("subdomain", "wildcard_detect", "SUCCESS",
                               target=domain, severity="MEDIUM",
                               notes=f"Wildcard DNS: *.{domain} -> {wildcard_ip}"))

            # Certificate transparency via crt.sh
            ct_subs = self._crtsh_enum(domain, ctx.timeout)
            if ct_subs:
                found.update(ct_subs)
                log(f"[Subdomain] crt.sh returned {len(ct_subs)} subdomains", "OK")
                results.append(AttackResult("subdomain", "crtsh_enum", "SUCCESS",
                               target=domain, data=list(ct_subs), severity="INFO",
                               notes=f"{len(ct_subs)} subdomains from certificate transparency"))
            else:
                log("[Subdomain] crt.sh returned no results", "WARN")

            # DNS brute-force
            brute_subs = self._brute_force(domain, ctx, wildcard_ip)
            if brute_subs:
                found.update(brute_subs)
                log(f"[Subdomain] Brute-force found {len(brute_subs)} live subdomains", "OK")
                results.append(AttackResult("subdomain", "brute_force", "SUCCESS",
                               target=domain, data=list(brute_subs), severity="INFO",
                               notes=f"{len(brute_subs)} subdomains via DNS brute-force"))

            # Resolve all found subdomains
            resolved = self._resolve_all(found, ctx, wildcard_ip)
            ctx.subdomains[domain] = found

            log(f"[Subdomain] Total unique subdomains for {domain}: {len(found)}", "OK")
            for sub, ip in sorted(resolved.items()):
                log(f"  {sub} -> {ip}", "INFO")

            if len(found) > 20:
                results.append(AttackResult("subdomain", "large_surface", "SUCCESS",
                               target=domain, severity="HIGH",
                               notes=f"Large attack surface: {len(found)} subdomains exposed"))

        return results

    def _detect_wildcard(self, domain: str) -> Optional[str]:
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        hostname = f"{random_sub}.{domain}"
        return resolve_host(hostname)

    def _crtsh_enum(self, domain: str, timeout: int) -> Set[str]:
        subdomains: Set[str] = set()
        if not REQUESTS:
            return subdomains
        try:
            resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                                timeout=timeout, verify=True)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(f".{domain}") or name == domain:
                            subdomains.add(name)
        except Exception as exc:
            log(f"[Subdomain] crt.sh error: {exc}", "ERR")
        return subdomains

    def _brute_force(self, domain: str, ctx: EngagementContext,
                     wildcard_ip: Optional[str]) -> Set[str]:
        found: Set[str] = set()

        def check_sub(prefix: str) -> Optional[str]:
            hostname = f"{prefix}.{domain}"
            ip = resolve_host(hostname)
            if ip and ip != wildcard_ip:
                return hostname
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as executor:
            futures = {executor.submit(check_sub, sub): sub for sub in SUBDOMAIN_WORDLIST}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)
        return found

    def _resolve_all(self, subdomains: Set[str], ctx: EngagementContext,
                     wildcard_ip: Optional[str]) -> Dict[str, str]:
        resolved: Dict[str, str] = {}

        def resolve(sub: str) -> Tuple[str, Optional[str]]:
            ip = resolve_host(sub)
            if ip and ip != wildcard_ip:
                return sub, ip
            return sub, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as executor:
            futures = [executor.submit(resolve, sub) for sub in subdomains]
            for future in concurrent.futures.as_completed(futures):
                sub, ip = future.result()
                if ip:
                    resolved[sub] = ip
        return resolved
