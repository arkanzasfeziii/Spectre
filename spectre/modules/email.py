"""Harvest email addresses, verify MX records, and check SMTP verification."""

from __future__ import annotations

import smtplib
from typing import Dict, List, Set

from spectre.models import AttackResult, EngagementContext
from spectre.logger import log
from spectre.modules.base import BaseModule
from spectre.utils.network import dns_query

from spectre.data import ROLE_EMAILS


class EmailModule(BaseModule):
    """Harvest email addresses, verify MX records, and check SMTP verification."""

    name = "email"

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            log(f"[Email] Starting email reconnaissance for {domain}", "INFO")
            harvested: Set[str] = set()

            # MX record lookup
            mx_hosts = self._check_mx(domain)
            if mx_hosts:
                log(f"[Email] MX records found: {', '.join(mx_hosts)}", "OK")
                results.append(AttackResult("email", "mx_lookup", "SUCCESS",
                               target=domain, data=mx_hosts, severity="INFO",
                               notes=f"MX records: {', '.join(mx_hosts)}"))
            else:
                log(f"[Email] No MX records found for {domain}", "WARN")
                results.append(AttackResult("email", "mx_lookup", "FAILED",
                               target=domain, severity="INFO",
                               notes="No MX records — domain may not accept email"))

            # Generate role-based emails
            role_emails = [f"{role}@{domain}" for role in ROLE_EMAILS]
            harvested.update(role_emails)
            log(f"[Email] Generated {len(role_emails)} role-based addresses", "INFO")

            # Generate pattern-based emails (common corporate patterns)
            patterns = self._generate_patterns(domain)
            log(f"[Email] Email pattern templates for {domain}:", "INFO")
            for pattern in patterns:
                log(f"  Pattern: {pattern}", "INFO")
            results.append(AttackResult("email", "pattern_detect", "SUCCESS",
                           target=domain, data=patterns, severity="LOW",
                           notes=f"Detected {len(patterns)} email naming patterns"))

            # SMTP VRFY attempt
            if mx_hosts:
                vrfy_results = self._smtp_vrfy(mx_hosts[0], role_emails[:5], ctx.timeout)
                if vrfy_results:
                    verified = [e for e, v in vrfy_results.items() if v]
                    if verified:
                        log(f"[Email] SMTP VRFY confirmed {len(verified)} addresses", "CRIT")
                        results.append(AttackResult("email", "smtp_vrfy", "SUCCESS",
                                       target=domain, data=verified, severity="HIGH",
                                       notes=f"SMTP VRFY enabled — {len(verified)} addresses verified"))
                    else:
                        log("[Email] SMTP VRFY returned no confirmations (likely disabled)", "INFO")

            # Breach check URL construction
            breach_urls = self._breach_check_urls(domain)
            results.append(AttackResult("email", "breach_urls", "SUCCESS",
                           target=domain, data=breach_urls, severity="INFO",
                           notes="Breach database lookup URLs constructed for manual verification"))

            # Hunter.io pattern detection
            hunter_url = f"https://hunter.io/domain/{domain}"
            log(f"[Email] Hunter.io lookup: {hunter_url}", "INFO")

            ctx.emails[domain] = harvested
            log(f"[Email] Total addresses for {domain}: {len(harvested)}", "OK")

        return results

    def _check_mx(self, domain: str) -> List[str]:
        records = dns_query(domain, "MX")
        mx_hosts = []
        for record in records:
            parts = record.split()
            if len(parts) >= 2:
                mx_hosts.append(parts[1].rstrip("."))
        return sorted(mx_hosts)

    def _generate_patterns(self, domain: str) -> List[str]:
        return [
            f"{{first}}.{{last}}@{domain}",
            f"{{f}}{{last}}@{domain}",
            f"{{first}}_{{last}}@{domain}",
            f"{{first}}{{last}}@{domain}",
            f"{{first}}-{{last}}@{domain}",
            f"{{last}}.{{first}}@{domain}",
            f"{{f}}.{{last}}@{domain}",
            f"{{first}}@{domain}",
        ]

    def _smtp_vrfy(self, mx_host: str, emails: List[str],
                   timeout: int) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("spectre.local")
            for email in emails:
                try:
                    code, _ = smtp.vrfy(email)
                    results[email] = code in (250, 251, 252)
                except smtplib.SMTPServerDisconnected:
                    break
                except Exception:
                    results[email] = False
            smtp.quit()
        except Exception as exc:
            log(f"[Email] SMTP connection to {mx_host}:25 failed: {exc}", "WARN")
        return results

    def _breach_check_urls(self, domain: str) -> List[str]:
        return [
            f"https://haveibeenpwned.com/DomainSearch/{domain}",
            f"https://dehashed.com/search?query=%40{domain}",
            f"https://intelx.io/?s=%40{domain}",
            f"https://leak-lookup.com/search?query=%40{domain}",
        ]
