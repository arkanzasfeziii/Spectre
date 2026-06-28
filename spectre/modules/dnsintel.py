"""DNS intelligence: full record enumeration, SPF/DMARC/DKIM analysis, zone transfer."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from spectre.logger import log
from spectre.models import AttackResult, EngagementContext
from spectre.modules.base import BaseModule
from spectre.utils.network import delay, dns_query

try:
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from spectre.data import DKIM_SELECTORS
except ImportError:
    DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]


class DNSIntelModule(BaseModule):

    name = "dns"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR"]

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        for domain in ctx.targets:
            log(f"[DNS] Starting DNS intelligence for {domain}", "INFO")
            domain_records: Dict[str, List[str]] = {}

            for rtype in self.RECORD_TYPES:
                records = dns_query(domain, rtype)
                if records:
                    domain_records[rtype] = records
                    log(f"[DNS] {rtype}: {', '.join(records)}", "OK")
                delay(ctx)

            ctx.dns_records[domain] = domain_records

            if domain_records:
                results.append(AttackResult(
                    "dns", "record_enum", "SUCCESS", target=domain,
                    data=domain_records, severity="INFO",
                    notes=f"Enumerated {sum(len(v) for v in domain_records.values())} records",
                ))

            spf_result = self._analyze_spf(domain, domain_records.get("TXT", []))
            if spf_result:
                results.append(spf_result)

            dmarc_result = self._check_dmarc(domain)
            if dmarc_result:
                results.append(dmarc_result)

            results.extend(self._brute_dkim(domain, ctx))

            ns_records = domain_records.get("NS", [])
            if ns_records:
                provider = self._identify_dns_provider(ns_records)
                if provider:
                    log(f"[DNS] DNS provider: {provider}", "INFO")
                    results.append(AttackResult(
                        "dns", "provider_id", "SUCCESS", target=domain,
                        data={"provider": provider, "ns": ns_records},
                        severity="INFO", notes=f"DNS provider: {provider}",
                    ))

            axfr_result = self._attempt_axfr(domain, ns_records)
            if axfr_result:
                results.append(axfr_result)

        return results

    def _analyze_spf(self, domain: str, txt_records: List[str]) -> Optional[AttackResult]:
        for record in txt_records:
            if "v=spf1" in record.lower():
                log(f"[DNS] SPF record found: {record}", "OK")
                issues: List[str] = []
                if "+all" in record:
                    issues.append("SPF uses +all (pass all)")
                elif "~all" in record:
                    issues.append("SPF uses ~all (softfail)")
                elif "?all" in record:
                    issues.append("SPF uses ?all (neutral)")

                includes = re.findall(r'include:(\S+)', record)
                ips = re.findall(r'ip4:(\S+)', record)
                severity = "HIGH" if "+all" in record else "MEDIUM" if "~all" in record else "INFO"

                return AttackResult(
                    "dns", "spf_analysis", "SUCCESS", target=domain,
                    severity=severity,
                    data={"spf": record, "includes": includes, "ips": ips, "issues": issues},
                    notes=f"SPF: {record.strip()}" + (f" | Issues: {'; '.join(issues)}" if issues else ""),
                )

        log("[DNS] No SPF record found", "CRIT")
        return AttackResult("dns", "spf_analysis", "SUCCESS", target=domain,
                           severity="CRITICAL", notes="No SPF record")

    def _check_dmarc(self, domain: str) -> Optional[AttackResult]:
        records = dns_query(f"_dmarc.{domain}", "TXT")
        for record in records:
            if "v=dmarc1" in record.lower():
                log(f"[DNS] DMARC record: {record}", "OK")
                policy = "none"
                if "p=reject" in record.lower():
                    policy = "reject"
                elif "p=quarantine" in record.lower():
                    policy = "quarantine"

                severity = "INFO" if policy == "reject" else "MEDIUM" if policy == "quarantine" else "HIGH"
                return AttackResult(
                    "dns", "dmarc_check", "SUCCESS", target=domain,
                    severity=severity, data={"dmarc": record, "policy": policy},
                    notes=f"DMARC policy={policy}",
                )

        log("[DNS] No DMARC record", "CRIT")
        return AttackResult("dns", "dmarc_check", "SUCCESS", target=domain,
                           severity="CRITICAL", notes="No DMARC record")

    def _brute_dkim(self, domain: str, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        found: List[str] = []
        for selector in DKIM_SELECTORS:
            records = dns_query(f"{selector}._domainkey.{domain}", "TXT")
            if records:
                found.append(selector)
                log(f"[DNS] DKIM selector found: {selector}", "OK")
            delay(ctx)

        if found:
            results.append(AttackResult(
                "dns", "dkim_enum", "SUCCESS", target=domain,
                data=found, severity="INFO",
                notes=f"DKIM selectors: {', '.join(found)}",
            ))
        return results

    def _identify_dns_provider(self, ns_records: List[str]) -> Optional[str]:
        providers = {
            "cloudflare": "Cloudflare", "awsdns": "AWS Route 53",
            "azure-dns": "Azure DNS", "googledomains": "Google Domains",
            "google": "Google Cloud DNS", "nsone": "NS1",
            "domaincontrol": "GoDaddy", "registrar-servers": "Namecheap",
            "digitalocean": "DigitalOcean",
        }
        for ns in ns_records:
            ns_lower = ns.lower()
            for pattern, provider in providers.items():
                if pattern in ns_lower:
                    return provider
        return None

    def _attempt_axfr(self, domain: str, ns_records: List[str]) -> Optional[AttackResult]:
        if not HAS_DNSPYTHON:
            return None
        for ns in ns_records:
            ns_host = ns.rstrip(".")
            try:
                log(f"[DNS] Attempting zone transfer from {ns_host}", "INFO")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, lifetime=5))
                names = [str(n) for n in zone.nodes.keys()]
                log(f"[DNS] ZONE TRANSFER SUCCEEDED — {len(names)} records!", "CRIT")
                return AttackResult(
                    "dns", "zone_transfer", "SUCCESS", target=domain,
                    data=names, severity="CRITICAL",
                    notes=f"AXFR from {ns_host} — {len(names)} records exposed",
                )
            except Exception:
                pass
        return None
