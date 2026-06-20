#!/usr/bin/env python3
"""
Spectre Framework
=================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : OSINT & passive reconnaissance framework for authorized red team engagements.
              Covers: subdomain enumeration, email harvesting, DNS intelligence,
              certificate transparency, infrastructure fingerprinting, and organization
              footprinting.

              Aligned with MITRE ATT&CK:
                T1589 Gather Victim Identity | T1590 Gather Victim Network Info
                T1591 Gather Victim Org Info | T1592 Gather Victim Host Info
                T1593 Search Open Websites/Domains | T1596 Search Open Technical Databases

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import re
import smtplib
import socket
import ssl
import string
import struct
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.name
    import dns.rdatatype
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False

try:
    import whois as python_whois
    WHOIS = True
except ImportError:
    WHOIS = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY = True
except ImportError:
    CRYPTOGRAPHY = False

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "Spectre Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "spectre"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SPECTRE — AUTHORIZED RED TEAM USE ONLY   ⚠                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework performs REAL reconnaissance: subdomain enumeration,         ║
║  email harvesting, DNS intelligence gathering, certificate transparency     ║
║  analysis, infrastructure fingerprinting, and organization footprinting.    ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (target domains)                                         ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# Subdomain brute-force wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "vpn", "api", "dev", "staging", "admin", "portal",
    "webmail", "remote", "test", "beta", "demo", "app", "cms", "blog", "shop",
    "store", "cdn", "static", "assets", "media", "img", "images", "files",
    "docs", "wiki", "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "deploy", "monitor", "grafana", "prometheus", "kibana", "elastic", "logs",
    "sentry", "status", "health", "metrics", "internal", "intranet", "corp",
    "sso", "auth", "login", "id", "oauth", "sts", "connect", "gateway",
    "proxy", "edge", "lb", "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap",
    "exchange", "owa", "autodiscover", "lyncdiscover", "sip", "meet",
    "vpn1", "vpn2", "fw", "firewall", "waf", "sec", "security", "backup",
    "db", "database", "mysql", "postgres", "redis", "mongo", "mssql",
    "s3", "storage", "cloud", "aws", "azure", "gcp", "k8s", "kubernetes",
    "docker", "registry", "vault", "consul", "nomad", "terraform",
    "jira", "confluence", "slack", "teams", "zoom", "helpdesk", "support",
    "ticket", "crm", "erp", "hr", "payroll", "finance", "billing",
]

# Common email role addresses
ROLE_EMAILS = [
    "info", "admin", "support", "hr", "careers", "security", "abuse",
    "postmaster", "webmaster", "sales", "contact", "press", "legal",
    "compliance", "privacy", "noc", "ops", "devops", "engineering",
    "marketing", "billing", "accounts", "help", "feedback",
]

# DKIM common selectors
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "dkim", "mail", "email", "smtp", "s1", "s2", "mta", "mx",
    "mandrill", "mailgun", "sendgrid", "amazonses", "ses",
    "cm", "protonmail", "zoho", "everlytickey1", "everlytickey2",
]

# Technology fingerprints in response body
TECH_SIGNATURES: Dict[str, List[str]] = {
    "WordPress":   ["wp-content", "wp-includes", "wordpress"],
    "Drupal":      ["Drupal.settings", "drupal.js", "/sites/default/"],
    "Joomla":      ["/media/jui/", "Joomla!", "/components/com_"],
    "Laravel":     ["laravel_session", "csrf-token", "Laravel"],
    "Django":      ["csrfmiddlewaretoken", "__admin__", "djdt"],
    "React":       ["react-root", "_reactRootContainer", "react.production"],
    "Angular":     ["ng-version", "ng-app", "angular.min.js"],
    "Vue.js":      ["vue-app", "__vue__", "vue.min.js", "vue.runtime"],
    "Next.js":     ["__NEXT_DATA__", "_next/static", "next/dist"],
    "Nuxt.js":     ["__NUXT__", "_nuxt/"],
    "ASP.NET":     ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
    "Spring":      ["whitelabel", "Spring", "Servlet"],
    "Express":     ["X-Powered-By: Express"],
    "Nginx":       ["nginx"],
    "Apache":      ["Apache/", "mod_"],
    "Cloudflare":  ["cf-ray", "cloudflare", "__cfduid"],
    "AWS S3":      ["AmazonS3", "x-amz-request-id"],
    "Varnish":     ["X-Varnish", "via: varnish"],
    "IIS":         ["Microsoft-IIS", "X-AspNet-Version"],
    "Tomcat":      ["Apache Tomcat", "Coyote"],
    "GraphQL":     ["graphql", "/graphql"],
    "Swagger":     ["swagger-ui", "openapi"],
}

# Security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

# Common ports for infrastructure scanning
COMMON_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 8080, 8443]

# Google dork templates
GOOGLE_DORKS = [
    'site:{domain}',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:portal',
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xlsx',
    'site:{domain} filetype:docx',
    'site:{domain} filetype:conf',
    'site:{domain} filetype:env',
    'site:{domain} filetype:log',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:bak',
    'site:{domain} filetype:xml',
    'site:{domain} inurl:api',
    'site:{domain} intitle:"index of"',
    'site:{domain} ext:php inurl:config',
    'site:{domain} intext:"password" filetype:log',
]


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module:    str
    action:    str
    status:    str
    target:    str = ""
    data:      Any = None
    severity:  str = "INFO"
    notes:     str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class EngagementContext:
    targets:     List[str]        = field(default_factory=list)
    threads:     int              = 10
    timeout:     int              = 10
    delay:       float            = 0.3
    stealth:     bool             = False
    results:     List[AttackResult] = field(default_factory=list)
    output_file: Optional[str]   = None
    # Module state
    subdomains:  Dict[str, Set[str]] = field(default_factory=dict)
    emails:      Dict[str, Set[str]] = field(default_factory=dict)
    dns_records: Dict[str, Dict]     = field(default_factory=dict)
    certificates: Dict[str, List]    = field(default_factory=dict)
    technologies: Dict[str, List]    = field(default_factory=dict)
    whois_data:  Dict[str, Dict]     = field(default_factory=dict)


# ── Helpers ───────────────────────────────────────────────────────────────────

console = Console() if RICH else None

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO": "\033[36m", "OK": "\033[32m", "WARN": "\033[33m",
              "ERR": "\033[31m", "CRIT": "\033[35m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level, '')}{ts} [{level}] {msg}{reset}")

def _delay(ctx: EngagementContext) -> None:
    if ctx.delay > 0:
        jitter = ctx.delay * (0.5 + random.random())
        time.sleep(jitter)

def _safe_request(url: str, timeout: int = 10, headers: Optional[Dict] = None,
                  verify: bool = False) -> Optional[requests.Response]:
    if not REQUESTS:
        _log("Install requests: pip install requests", "ERR")
        return None
    try:
        hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        if headers:
            hdrs.update(headers)
        return requests.get(url, headers=hdrs, timeout=timeout, verify=verify,
                           allow_redirects=True)
    except requests.exceptions.RequestException:
        return None

def _resolve_host(hostname: str) -> Optional[str]:
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except (socket.gaierror, socket.herror, OSError):
        pass
    return None

def _dns_query(name: str, rdtype: str) -> List[str]:
    if not DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=5)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


# ── Module 1: Subdomain Enumeration ──────────────────────────────────────────

class SubdomainModule:
    """Enumerate subdomains via certificate transparency, DNS brute-force, and resolution."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[Subdomain] Starting enumeration for {domain}", "INFO")
            found: Set[str] = set()

            # Wildcard detection
            wildcard_ip = self._detect_wildcard(domain)
            if wildcard_ip:
                _log(f"[Subdomain] Wildcard DNS detected for *.{domain} → {wildcard_ip}", "WARN")
                results.append(AttackResult("subdomain", "wildcard_detect", "SUCCESS",
                               target=domain, severity="MEDIUM",
                               notes=f"Wildcard DNS: *.{domain} → {wildcard_ip}"))

            # Certificate transparency via crt.sh
            ct_subs = self._crtsh_enum(domain, ctx.timeout)
            if ct_subs:
                found.update(ct_subs)
                _log(f"[Subdomain] crt.sh returned {len(ct_subs)} subdomains", "OK")
                results.append(AttackResult("subdomain", "crtsh_enum", "SUCCESS",
                               target=domain, data=list(ct_subs), severity="INFO",
                               notes=f"{len(ct_subs)} subdomains from certificate transparency"))
            else:
                _log(f"[Subdomain] crt.sh returned no results", "WARN")

            # DNS brute-force
            brute_subs = self._brute_force(domain, ctx, wildcard_ip)
            if brute_subs:
                found.update(brute_subs)
                _log(f"[Subdomain] Brute-force found {len(brute_subs)} live subdomains", "OK")
                results.append(AttackResult("subdomain", "brute_force", "SUCCESS",
                               target=domain, data=list(brute_subs), severity="INFO",
                               notes=f"{len(brute_subs)} subdomains via DNS brute-force"))

            # Resolve all found subdomains
            resolved = self._resolve_all(found, ctx, wildcard_ip)
            ctx.subdomains[domain] = found

            _log(f"[Subdomain] Total unique subdomains for {domain}: {len(found)}", "OK")
            for sub, ip in sorted(resolved.items()):
                _log(f"  {sub} → {ip}", "INFO")

            if len(found) > 20:
                results.append(AttackResult("subdomain", "large_surface", "SUCCESS",
                               target=domain, severity="HIGH",
                               notes=f"Large attack surface: {len(found)} subdomains exposed"))

        return results

    def _detect_wildcard(self, domain: str) -> Optional[str]:
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        hostname = f"{random_sub}.{domain}"
        return _resolve_host(hostname)

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
            _log(f"[Subdomain] crt.sh error: {exc}", "ERR")
        return subdomains

    def _brute_force(self, domain: str, ctx: EngagementContext,
                     wildcard_ip: Optional[str]) -> Set[str]:
        found: Set[str] = set()

        def check_sub(prefix: str) -> Optional[str]:
            hostname = f"{prefix}.{domain}"
            ip = _resolve_host(hostname)
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
            ip = _resolve_host(sub)
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


# ── Module 2: Email Harvesting ───────────────────────────────────────────────

class EmailModule:
    """Harvest email addresses, verify MX records, and check SMTP verification."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[Email] Starting email reconnaissance for {domain}", "INFO")
            harvested: Set[str] = set()

            # MX record lookup
            mx_hosts = self._check_mx(domain)
            if mx_hosts:
                _log(f"[Email] MX records found: {', '.join(mx_hosts)}", "OK")
                results.append(AttackResult("email", "mx_lookup", "SUCCESS",
                               target=domain, data=mx_hosts, severity="INFO",
                               notes=f"MX records: {', '.join(mx_hosts)}"))
            else:
                _log(f"[Email] No MX records found for {domain}", "WARN")
                results.append(AttackResult("email", "mx_lookup", "FAILED",
                               target=domain, severity="INFO",
                               notes="No MX records — domain may not accept email"))

            # Generate role-based emails
            role_emails = [f"{role}@{domain}" for role in ROLE_EMAILS]
            harvested.update(role_emails)
            _log(f"[Email] Generated {len(role_emails)} role-based addresses", "INFO")

            # Generate pattern-based emails (common corporate patterns)
            patterns = self._generate_patterns(domain)
            _log(f"[Email] Email pattern templates for {domain}:", "INFO")
            for pattern in patterns:
                _log(f"  Pattern: {pattern}", "INFO")
            results.append(AttackResult("email", "pattern_detect", "SUCCESS",
                           target=domain, data=patterns, severity="LOW",
                           notes=f"Detected {len(patterns)} email naming patterns"))

            # SMTP VRFY attempt
            if mx_hosts:
                vrfy_results = self._smtp_vrfy(mx_hosts[0], role_emails[:5], ctx.timeout)
                if vrfy_results:
                    verified = [e for e, v in vrfy_results.items() if v]
                    if verified:
                        _log(f"[Email] SMTP VRFY confirmed {len(verified)} addresses", "CRIT")
                        results.append(AttackResult("email", "smtp_vrfy", "SUCCESS",
                                       target=domain, data=verified, severity="HIGH",
                                       notes=f"SMTP VRFY enabled — {len(verified)} addresses verified"))
                    else:
                        _log(f"[Email] SMTP VRFY returned no confirmations (likely disabled)", "INFO")

            # Breach check URL construction
            breach_urls = self._breach_check_urls(domain)
            results.append(AttackResult("email", "breach_urls", "SUCCESS",
                           target=domain, data=breach_urls, severity="INFO",
                           notes="Breach database lookup URLs constructed for manual verification"))

            # Hunter.io pattern detection
            hunter_url = f"https://hunter.io/domain/{domain}"
            _log(f"[Email] Hunter.io lookup: {hunter_url}", "INFO")

            ctx.emails[domain] = harvested
            _log(f"[Email] Total addresses for {domain}: {len(harvested)}", "OK")

        return results

    def _check_mx(self, domain: str) -> List[str]:
        records = _dns_query(domain, "MX")
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
            _log(f"[Email] SMTP connection to {mx_host}:25 failed: {exc}", "WARN")
        return results

    def _breach_check_urls(self, domain: str) -> List[str]:
        return [
            f"https://haveibeenpwned.com/DomainSearch/{domain}",
            f"https://dehashed.com/search?query=%40{domain}",
            f"https://intelx.io/?s=%40{domain}",
            f"https://leak-lookup.com/search?query=%40{domain}",
        ]


# ── Module 3: DNS Intelligence ──────────────────────────────────────────────

class DNSIntelModule:
    """Full DNS record enumeration, SPF/DMARC/DKIM analysis, and zone transfer attempts."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR"]

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[DNS] Starting DNS intelligence for {domain}", "INFO")
            domain_records: Dict[str, List[str]] = {}

            # Full DNS record enumeration
            for rtype in self.RECORD_TYPES:
                records = _dns_query(domain, rtype)
                if records:
                    domain_records[rtype] = records
                    _log(f"[DNS] {rtype}: {', '.join(records)}", "OK")
                _delay(ctx)

            ctx.dns_records[domain] = domain_records

            if domain_records:
                results.append(AttackResult("dns", "record_enum", "SUCCESS",
                               target=domain, data=domain_records, severity="INFO",
                               notes=f"Enumerated {sum(len(v) for v in domain_records.values())} DNS records across {len(domain_records)} types"))

            # SPF analysis
            spf_result = self._analyze_spf(domain, domain_records.get("TXT", []))
            if spf_result:
                results.append(spf_result)

            # DMARC check
            dmarc_result = self._check_dmarc(domain)
            if dmarc_result:
                results.append(dmarc_result)

            # DKIM selector brute-force
            dkim_results = self._brute_dkim(domain, ctx)
            results.extend(dkim_results)

            # NS delegation — identify DNS provider
            ns_records = domain_records.get("NS", [])
            if ns_records:
                provider = self._identify_dns_provider(ns_records)
                if provider:
                    _log(f"[DNS] DNS provider: {provider}", "INFO")
                    results.append(AttackResult("dns", "provider_id", "SUCCESS",
                                   target=domain, data={"provider": provider, "ns": ns_records},
                                   severity="INFO", notes=f"DNS provider: {provider}"))

            # Zone transfer attempt
            axfr_result = self._attempt_axfr(domain, ns_records)
            if axfr_result:
                results.append(axfr_result)

        return results

    def _analyze_spf(self, domain: str, txt_records: List[str]) -> Optional[AttackResult]:
        for record in txt_records:
            if "v=spf1" in record.lower():
                _log(f"[DNS] SPF record found: {record}", "OK")
                issues = []
                if "+all" in record:
                    issues.append("SPF uses +all (pass all) — any sender permitted")
                elif "~all" in record:
                    issues.append("SPF uses ~all (softfail) — spoofed mail may be delivered")
                elif "?all" in record:
                    issues.append("SPF uses ?all (neutral) — no protection")

                includes = re.findall(r'include:(\S+)', record)
                ips = re.findall(r'ip4:(\S+)', record)

                severity = "HIGH" if "+all" in record else "MEDIUM" if "~all" in record else "INFO"
                notes = f"SPF: {record.strip()}"
                if issues:
                    notes += f" | Issues: {'; '.join(issues)}"
                if includes:
                    notes += f" | Includes: {', '.join(includes)}"

                return AttackResult("dns", "spf_analysis", "SUCCESS",
                                   target=domain, severity=severity,
                                   data={"spf": record, "includes": includes, "ips": ips, "issues": issues},
                                   notes=notes)

        _log(f"[DNS] No SPF record found — domain vulnerable to email spoofing", "CRIT")
        return AttackResult("dns", "spf_analysis", "SUCCESS",
                           target=domain, severity="CRITICAL",
                           notes="No SPF record — domain has no email sender verification")

    def _check_dmarc(self, domain: str) -> Optional[AttackResult]:
        dmarc_domain = f"_dmarc.{domain}"
        records = _dns_query(dmarc_domain, "TXT")
        for record in records:
            if "v=dmarc1" in record.lower():
                _log(f"[DNS] DMARC record: {record}", "OK")
                policy = "none"
                if "p=reject" in record.lower():
                    policy = "reject"
                elif "p=quarantine" in record.lower():
                    policy = "quarantine"
                elif "p=none" in record.lower():
                    policy = "none"

                severity = "INFO" if policy == "reject" else "MEDIUM" if policy == "quarantine" else "HIGH"
                if policy == "none":
                    _log(f"[DNS] DMARC policy=none — spoofed mail will be accepted", "WARN")

                return AttackResult("dns", "dmarc_check", "SUCCESS",
                                   target=domain, severity=severity,
                                   data={"dmarc": record, "policy": policy},
                                   notes=f"DMARC policy={policy} | {record.strip()}")

        _log(f"[DNS] No DMARC record — domain has no spoofing policy", "CRIT")
        return AttackResult("dns", "dmarc_check", "SUCCESS",
                           target=domain, severity="CRITICAL",
                           notes="No DMARC record — no email authentication policy")

    def _brute_dkim(self, domain: str, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        found_selectors = []
        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = _dns_query(dkim_domain, "TXT")
            if records:
                found_selectors.append(selector)
                _log(f"[DNS] DKIM selector found: {selector} → {records[0][:80]}...", "OK")
            _delay(ctx)

        if found_selectors:
            results.append(AttackResult("dns", "dkim_enum", "SUCCESS",
                           target=domain, data=found_selectors, severity="INFO",
                           notes=f"DKIM selectors found: {', '.join(found_selectors)}"))
        else:
            _log(f"[DNS] No DKIM selectors found", "WARN")
        return results

    def _identify_dns_provider(self, ns_records: List[str]) -> Optional[str]:
        providers = {
            "cloudflare": "Cloudflare", "awsdns": "AWS Route 53",
            "azure-dns": "Azure DNS", "googledomains": "Google Domains",
            "google": "Google Cloud DNS", "nsone": "NS1",
            "dnsmadeeasy": "DNS Made Easy", "ultradns": "UltraDNS",
            "domaincontrol": "GoDaddy", "registrar-servers": "Namecheap",
            "hetzner": "Hetzner", "digitalocean": "DigitalOcean",
            "linode": "Linode/Akamai", "dnsimple": "DNSimple",
        }
        for ns in ns_records:
            ns_lower = ns.lower()
            for pattern, provider in providers.items():
                if pattern in ns_lower:
                    return provider
        return None

    def _attempt_axfr(self, domain: str, ns_records: List[str]) -> Optional[AttackResult]:
        if not DNSPYTHON:
            return None
        for ns in ns_records:
            ns_host = ns.rstrip(".")
            try:
                _log(f"[DNS] Attempting zone transfer from {ns_host}", "INFO")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, lifetime=5))
                names = [str(n) for n in zone.nodes.keys()]
                _log(f"[DNS] ZONE TRANSFER SUCCEEDED from {ns_host} — {len(names)} records!", "CRIT")
                return AttackResult("dns", "zone_transfer", "SUCCESS",
                                   target=domain, data=names, severity="CRITICAL",
                                   notes=f"AXFR succeeded from {ns_host} — {len(names)} records exposed")
            except Exception:
                pass
        _log(f"[DNS] Zone transfer denied by all nameservers (expected)", "INFO")
        return None


# ── Module 4: Certificate Transparency & SSL ────────────────────────────────

class CertModule:
    """Certificate transparency analysis, SSL/TLS inspection, and certificate intelligence."""

    TLS_VERSIONS = {
        "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[Cert] Starting certificate analysis for {domain}", "INFO")

            # crt.sh certificate enumeration
            certs = self._crtsh_certs(domain, ctx.timeout)
            if certs:
                _log(f"[Cert] crt.sh returned {len(certs)} certificates", "OK")
                results.append(AttackResult("cert", "crtsh_enum", "SUCCESS",
                               target=domain, data=certs[:50], severity="INFO",
                               notes=f"{len(certs)} certificates found via transparency logs"))
                ctx.certificates[domain] = certs

            # Live SSL certificate inspection
            cert_info = self._inspect_live_cert(domain, ctx.timeout)
            if cert_info:
                results.extend(self._analyze_cert(domain, cert_info))

            # TLS version detection
            tls_results = self._detect_tls_versions(domain, ctx.timeout)
            if tls_results:
                supported = [v for v, s in tls_results.items() if s]
                deprecated = [v for v in supported if v in ("TLSv1.0", "TLSv1.1")]
                _log(f"[Cert] TLS versions supported: {', '.join(supported)}", "OK")
                if deprecated:
                    _log(f"[Cert] Deprecated TLS versions enabled: {', '.join(deprecated)}", "CRIT")
                    results.append(AttackResult("cert", "tls_deprecated", "SUCCESS",
                                   target=domain, severity="HIGH",
                                   data={"supported": supported, "deprecated": deprecated},
                                   notes=f"Deprecated TLS: {', '.join(deprecated)} — downgrade attacks possible"))
                results.append(AttackResult("cert", "tls_versions", "SUCCESS",
                               target=domain, data=tls_results, severity="INFO",
                               notes=f"TLS support: {', '.join(supported)}"))

        return results

    def _crtsh_certs(self, domain: str, timeout: int) -> List[Dict]:
        if not REQUESTS:
            return []
        try:
            resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                               timeout=timeout, verify=True)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            _log(f"[Cert] crt.sh query error: {exc}", "ERR")
        return []

    def _inspect_live_cert(self, domain: str, timeout: int) -> Optional[Dict]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    if CRYPTOGRAPHY and cert_der:
                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                        return {
                            "subject": str(cert_obj.subject),
                            "issuer": str(cert_obj.issuer),
                            "not_before": cert_obj.not_valid_before_utc.isoformat() if hasattr(cert_obj, 'not_valid_before_utc') else str(cert_obj.not_valid_before),
                            "not_after": cert_obj.not_valid_after_utc.isoformat() if hasattr(cert_obj, 'not_valid_after_utc') else str(cert_obj.not_valid_after),
                            "serial": str(cert_obj.serial_number),
                            "sans": self._extract_sans(cert_obj),
                            "raw_dict": cert_dict,
                        }
                    elif cert_dict:
                        return {"raw_dict": cert_dict}
        except Exception as exc:
            _log(f"[Cert] SSL connection to {domain}:443 failed: {exc}", "WARN")
        return None

    def _extract_sans(self, cert_obj) -> List[str]:
        sans = []
        try:
            ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return sans

    def _analyze_cert(self, domain: str, cert_info: Dict) -> List[AttackResult]:
        results = []
        issuer = cert_info.get("issuer", "Unknown")
        not_after = cert_info.get("not_after", "")
        sans = cert_info.get("sans", [])

        _log(f"[Cert] Issuer: {issuer}", "OK")
        _log(f"[Cert] Expires: {not_after}", "INFO")

        # Identify issuer
        issuer_name = "Unknown"
        issuer_lower = issuer.lower()
        for name in ["Let's Encrypt", "DigiCert", "Comodo", "GlobalSign", "Sectigo",
                      "GoDaddy", "Amazon", "Google Trust", "Cloudflare", "ZeroSSL"]:
            if name.lower().replace("'", "") in issuer_lower.replace("'", ""):
                issuer_name = name
                break

        results.append(AttackResult("cert", "issuer_id", "SUCCESS",
                       target=domain, severity="INFO",
                       data={"issuer": issuer, "issuer_name": issuer_name},
                       notes=f"Certificate issuer: {issuer_name}"))

        # Check expiry
        if not_after:
            try:
                expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    _log(f"[Cert] Certificate EXPIRED {abs(days_left)} days ago!", "CRIT")
                    results.append(AttackResult("cert", "expiry_check", "SUCCESS",
                                   target=domain, severity="CRITICAL",
                                   notes=f"Certificate expired {abs(days_left)} days ago"))
                elif days_left < 30:
                    _log(f"[Cert] Certificate expires in {days_left} days", "WARN")
                    results.append(AttackResult("cert", "expiry_check", "SUCCESS",
                                   target=domain, severity="MEDIUM",
                                   notes=f"Certificate expires in {days_left} days"))
            except (ValueError, TypeError):
                pass

        # SANs analysis
        if sans:
            _log(f"[Cert] SANs ({len(sans)}): {', '.join(sans[:10])}", "OK")
            wildcards = [s for s in sans if s.startswith("*.")]
            if wildcards:
                _log(f"[Cert] Wildcard certificates: {', '.join(wildcards)}", "WARN")
                results.append(AttackResult("cert", "wildcard_cert", "SUCCESS",
                               target=domain, severity="MEDIUM",
                               data=wildcards,
                               notes=f"Wildcard certs: {', '.join(wildcards)}"))

            # SANs expose internal subdomains
            internal_indicators = ["internal", "corp", "intranet", "staging", "dev", "test", "uat"]
            internal_sans = [s for s in sans if any(ind in s.lower() for ind in internal_indicators)]
            if internal_sans:
                _log(f"[Cert] Internal subdomains in SANs: {', '.join(internal_sans)}", "CRIT")
                results.append(AttackResult("cert", "internal_sans", "SUCCESS",
                               target=domain, severity="HIGH",
                               data=internal_sans,
                               notes=f"Internal subdomains exposed via certificate SANs: {', '.join(internal_sans)}"))

            results.append(AttackResult("cert", "san_enum", "SUCCESS",
                           target=domain, data=sans, severity="INFO",
                           notes=f"{len(sans)} Subject Alternative Names found"))

        return results

    def _detect_tls_versions(self, domain: str, timeout: int) -> Dict[str, bool]:
        supported: Dict[str, bool] = {}
        for version_name, version_const in self.TLS_VERSIONS.items():
            if version_const is None:
                supported[version_name] = False
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version_const
                context.maximum_version = version_const
                with socket.create_connection((domain, 443), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        supported[version_name] = True
            except Exception:
                supported[version_name] = False
        return supported


# ── Module 5: Infrastructure Fingerprinting ──────────────────────────────────

class SearchModule:
    """HTTP fingerprinting, technology detection, robots/sitemap parsing, security headers."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[Search] Starting infrastructure fingerprinting for {domain}", "INFO")

            # HTTP header fingerprinting
            header_results = self._fingerprint_headers(domain, ctx.timeout)
            results.extend(header_results)

            # Technology detection from response body
            tech_results = self._detect_technologies(domain, ctx.timeout)
            if tech_results:
                ctx.technologies[domain] = tech_results
                results.append(AttackResult("search", "tech_detect", "SUCCESS",
                               target=domain, data=tech_results, severity="INFO",
                               notes=f"Technologies detected: {', '.join(tech_results)}"))

            # robots.txt parsing
            robots_results = self._parse_robots(domain, ctx.timeout)
            if robots_results:
                results.extend(robots_results)

            # sitemap.xml parsing
            sitemap_results = self._parse_sitemap(domain, ctx.timeout)
            if sitemap_results:
                results.extend(sitemap_results)

            # Security headers audit
            sec_results = self._audit_security_headers(domain, ctx.timeout)
            results.extend(sec_results)

            # Favicon hash
            favicon_result = self._favicon_hash(domain, ctx.timeout)
            if favicon_result:
                results.append(favicon_result)

            # Open port check
            port_results = self._check_ports(domain, ctx)
            if port_results:
                results.extend(port_results)

        return results

    def _fingerprint_headers(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        for scheme in ("https", "http"):
            resp = _safe_request(f"{scheme}://{domain}/", timeout=timeout)
            if not resp:
                continue

            fingerprint_headers = ["Server", "X-Powered-By", "X-Generator",
                                   "X-AspNet-Version", "X-Runtime"]
            found = {}
            for header in fingerprint_headers:
                value = resp.headers.get(header)
                if value:
                    found[header] = value
                    _log(f"[Search] {header}: {value}", "OK")

            if found:
                results.append(AttackResult("search", "header_fingerprint", "SUCCESS",
                               target=domain, data=found, severity="LOW",
                               notes=f"Server fingerprint: {', '.join(f'{k}={v}' for k, v in found.items())}"))
            break
        return results

    def _detect_technologies(self, domain: str, timeout: int) -> List[str]:
        detected = []
        resp = _safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = _safe_request(f"http://{domain}/", timeout=timeout)
        if not resp:
            return detected

        body = resp.text.lower()
        headers_str = str(resp.headers).lower()
        combined = body + headers_str

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    detected.append(tech)
                    _log(f"[Search] Technology detected: {tech}", "OK")
                    break
        return detected

    def _parse_robots(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = _safe_request(f"https://{domain}/robots.txt", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = _safe_request(f"http://{domain}/robots.txt", timeout=timeout)
        if not resp or resp.status_code != 200:
            return results

        disallow_paths = []
        interesting_paths = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallow_paths.append(path)
                    sensitive_indicators = ["/admin", "/api", "/config", "/backup",
                                           "/internal", "/private", "/debug", "/test",
                                           "/staging", "/dev", "/wp-admin", "/phpmyadmin",
                                           "/console", "/dashboard", "/panel", "/.env",
                                           "/.git", "/secret", "/cgi-bin"]
                    if any(ind in path.lower() for ind in sensitive_indicators):
                        interesting_paths.append(path)

        if disallow_paths:
            _log(f"[Search] robots.txt: {len(disallow_paths)} disallowed paths", "OK")
            results.append(AttackResult("search", "robots_parse", "SUCCESS",
                           target=domain, data=disallow_paths, severity="INFO",
                           notes=f"robots.txt: {len(disallow_paths)} disallowed paths"))

        if interesting_paths:
            _log(f"[Search] Sensitive paths in robots.txt: {', '.join(interesting_paths)}", "CRIT")
            results.append(AttackResult("search", "robots_sensitive", "SUCCESS",
                           target=domain, data=interesting_paths, severity="HIGH",
                           notes=f"Sensitive paths exposed in robots.txt: {', '.join(interesting_paths)}"))

        return results

    def _parse_sitemap(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = _safe_request(f"https://{domain}/sitemap.xml", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = _safe_request(f"http://{domain}/sitemap.xml", timeout=timeout)
        if not resp or resp.status_code != 200:
            return results

        urls = re.findall(r'<loc>\s*(.*?)\s*</loc>', resp.text, re.IGNORECASE)
        if urls:
            _log(f"[Search] sitemap.xml: {len(urls)} URLs indexed", "OK")
            results.append(AttackResult("search", "sitemap_parse", "SUCCESS",
                           target=domain, data=urls[:100], severity="INFO",
                           notes=f"sitemap.xml: {len(urls)} URLs — reveals site structure"))
        return results

    def _audit_security_headers(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = _safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = _safe_request(f"http://{domain}/", timeout=timeout)
        if not resp:
            return results

        present = []
        missing = []
        for header in SECURITY_HEADERS:
            if resp.headers.get(header):
                present.append(header)
            else:
                missing.append(header)

        if missing:
            _log(f"[Search] Missing security headers ({len(missing)}): {', '.join(missing)}", "WARN")
            severity = "HIGH" if len(missing) > 5 else "MEDIUM"
            results.append(AttackResult("search", "security_headers", "SUCCESS",
                           target=domain, severity=severity,
                           data={"present": present, "missing": missing},
                           notes=f"Missing {len(missing)}/{len(SECURITY_HEADERS)} security headers: {', '.join(missing)}"))

        if present:
            _log(f"[Search] Present security headers: {', '.join(present)}", "OK")

        # Check HSTS specifically
        hsts = resp.headers.get("Strict-Transport-Security")
        if hsts:
            if "includeSubDomains" not in hsts:
                results.append(AttackResult("search", "hsts_partial", "SUCCESS",
                               target=domain, severity="LOW",
                               notes="HSTS present but does not include subdomains"))
        return results

    def _favicon_hash(self, domain: str, timeout: int) -> Optional[AttackResult]:
        resp = _safe_request(f"https://{domain}/favicon.ico", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = _safe_request(f"http://{domain}/favicon.ico", timeout=timeout)
        if not resp or resp.status_code != 200 or len(resp.content) < 10:
            return None

        import base64
        favicon_b64 = base64.encodebytes(resp.content)
        fav_hash = hashlib.md5(favicon_b64).hexdigest()
        # MurmurHash3 approximation for Shodan compatibility
        import struct
        mmh3_input = favicon_b64
        h = 0
        for i in range(0, len(mmh3_input) - len(mmh3_input) % 4, 4):
            k = struct.unpack('<I', mmh3_input[i:i+4])[0]
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
        h ^= len(mmh3_input)
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16
        if h >= 0x80000000:
            h -= 0x100000000

        _log(f"[Search] Favicon hash: MD5={fav_hash} | MurmurHash3={h}", "OK")
        _log(f"[Search] Shodan query: http.favicon.hash:{h}", "INFO")
        return AttackResult("search", "favicon_hash", "SUCCESS",
                           target=domain, severity="INFO",
                           data={"md5": fav_hash, "mmh3": h,
                                 "shodan_query": f"http.favicon.hash:{h}"},
                           notes=f"Favicon hash: Shodan query → http.favicon.hash:{h}")

    def _check_ports(self, domain: str, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        ip = _resolve_host(domain)
        if not ip:
            return results

        open_ports = []

        def scan_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(ctx.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in COMMON_PORTS}
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)

        if open_ports:
            open_ports.sort()
            _log(f"[Search] Open ports on {ip}: {', '.join(str(p) for p in open_ports)}", "OK")
            results.append(AttackResult("search", "port_scan", "SUCCESS",
                           target=domain, data={"ip": ip, "open_ports": open_ports},
                           severity="INFO",
                           notes=f"Open ports: {', '.join(str(p) for p in open_ports)}"))
        return results


# ── Module 6: Organization Footprinting ──────────────────────────────────────

class SocialModule:
    """WHOIS lookup, social media footprinting, metadata extraction, Google dorking."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            _log(f"[Social] Starting organization footprinting for {domain}", "INFO")

            # WHOIS lookup
            whois_result = self._whois_lookup(domain)
            if whois_result:
                results.extend(whois_result)

            # Social media profile construction
            social_results = self._social_profiles(domain)
            results.extend(social_results)

            # GitHub organization search
            github_results = self._github_enum(domain, ctx.timeout)
            if github_results:
                results.extend(github_results)

            # Page metadata extraction
            meta_results = self._extract_metadata(domain, ctx.timeout)
            if meta_results:
                results.extend(meta_results)

            # Google dorking query generation
            dork_results = self._generate_dorks(domain)
            results.extend(dork_results)

        return results

    def _whois_lookup(self, domain: str) -> List[AttackResult]:
        results = []
        if not WHOIS:
            _log("[Social] Install python-whois: pip install python-whois", "ERR")
            return results

        try:
            w = python_whois.whois(domain)
            whois_data = {}

            registrar = w.registrar
            if registrar:
                whois_data["registrar"] = registrar
                _log(f"[Social] Registrar: {registrar}", "OK")

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                whois_data["creation_date"] = str(creation)
                _log(f"[Social] Domain created: {creation}", "INFO")

            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                whois_data["expiration_date"] = str(expiry)
                _log(f"[Social] Domain expires: {expiry}", "INFO")

            name_servers = w.name_servers
            if name_servers:
                if isinstance(name_servers, list):
                    name_servers = [ns.lower() for ns in name_servers]
                whois_data["name_servers"] = name_servers
                _log(f"[Social] Name servers: {', '.join(name_servers) if isinstance(name_servers, list) else name_servers}", "INFO")

            org = w.org
            if org:
                whois_data["organization"] = org
                _log(f"[Social] Organization: {org}", "OK")

            # Registrant info (if not privacy-protected)
            registrant = w.get("name") or w.get("registrant_name")
            if registrant and "privacy" not in str(registrant).lower() and "redacted" not in str(registrant).lower():
                whois_data["registrant"] = registrant
                _log(f"[Social] Registrant: {registrant}", "CRIT")
                results.append(AttackResult("social", "whois_registrant", "SUCCESS",
                               target=domain, severity="HIGH",
                               data={"registrant": registrant},
                               notes=f"WHOIS registrant not privacy-protected: {registrant}"))

            emails_found = w.emails
            if emails_found:
                if isinstance(emails_found, str):
                    emails_found = [emails_found]
                whois_data["emails"] = emails_found
                _log(f"[Social] WHOIS emails: {', '.join(emails_found)}", "OK")

            results.append(AttackResult("social", "whois_lookup", "SUCCESS",
                           target=domain, data=whois_data, severity="INFO",
                           notes=f"WHOIS: registrar={registrar or 'N/A'}, created={creation or 'N/A'}"))

        except Exception as exc:
            _log(f"[Social] WHOIS lookup failed: {exc}", "ERR")
            results.append(AttackResult("social", "whois_lookup", "FAILED",
                           target=domain, severity="INFO",
                           notes=f"WHOIS lookup failed: {exc}"))
        return results

    def _social_profiles(self, domain: str) -> List[AttackResult]:
        # Extract likely org name from domain
        org_name = domain.split(".")[0]
        profiles = {
            "LinkedIn":  f"https://linkedin.com/company/{org_name}",
            "Twitter/X": f"https://x.com/{org_name}",
            "GitHub":    f"https://github.com/{org_name}",
            "Facebook":  f"https://facebook.com/{org_name}",
            "Instagram": f"https://instagram.com/{org_name}",
            "Crunchbase": f"https://crunchbase.com/organization/{org_name}",
        }
        _log(f"[Social] Constructed social media profile URLs for '{org_name}':", "INFO")
        for platform, url in profiles.items():
            _log(f"  {platform}: {url}", "INFO")

        return [AttackResult("social", "social_profiles", "SUCCESS",
                            target=domain, data=profiles, severity="INFO",
                            notes=f"Social profile URLs constructed for org '{org_name}'")]

    def _github_enum(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        if not REQUESTS:
            return results

        org_name = domain.split(".")[0]
        try:
            resp = requests.get(f"https://api.github.com/orgs/{org_name}",
                               timeout=timeout,
                               headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                info = {
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "public_repos": data.get("public_repos"),
                    "public_members": data.get("public_members_url", "").replace("{/member}", ""),
                    "blog": data.get("blog"),
                    "location": data.get("location"),
                    "created_at": data.get("created_at"),
                }
                _log(f"[Social] GitHub org found: {org_name} — {data.get('public_repos', 0)} public repos", "OK")
                results.append(AttackResult("social", "github_org", "SUCCESS",
                               target=domain, data=info, severity="LOW",
                               notes=f"GitHub org '{org_name}': {data.get('public_repos', 0)} public repos"))

                # Fetch top repos
                repos_resp = requests.get(f"https://api.github.com/orgs/{org_name}/repos?sort=updated&per_page=10",
                                         timeout=timeout,
                                         headers={"Accept": "application/vnd.github.v3+json"})
                if repos_resp.status_code == 200:
                    repos = repos_resp.json()
                    repo_names = [r.get("full_name") for r in repos]
                    languages = list(set(r.get("language") for r in repos if r.get("language")))
                    _log(f"[Social] GitHub repos: {', '.join(repo_names[:5])}", "INFO")
                    _log(f"[Social] Languages: {', '.join(languages)}", "INFO")
                    results.append(AttackResult("social", "github_repos", "SUCCESS",
                                   target=domain, data={"repos": repo_names, "languages": languages},
                                   severity="INFO",
                                   notes=f"Top repos: {', '.join(repo_names[:5])}"))

            elif resp.status_code == 404:
                _log(f"[Social] No GitHub org found for '{org_name}'", "INFO")
            else:
                _log(f"[Social] GitHub API returned {resp.status_code}", "WARN")
        except Exception as exc:
            _log(f"[Social] GitHub API error: {exc}", "ERR")
        return results

    def _extract_metadata(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = _safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = _safe_request(f"http://{domain}/", timeout=timeout)
        if not resp:
            return results

        metadata = {}

        # Title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            metadata["title"] = title_match.group(1).strip()

        # Meta description
        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']',
                               resp.text, re.IGNORECASE)
        if desc_match:
            metadata["description"] = desc_match.group(1).strip()

        # Open Graph tags
        og_tags = re.findall(r'<meta[^>]*property=["\']og:(\w+)["\'][^>]*content=["\'](.*?)["\']',
                             resp.text, re.IGNORECASE)
        if og_tags:
            metadata["og"] = {tag: value for tag, value in og_tags}

        # Generator meta tag
        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']',
                              resp.text, re.IGNORECASE)
        if gen_match:
            metadata["generator"] = gen_match.group(1).strip()
            _log(f"[Social] Generator: {metadata['generator']}", "OK")

        if metadata:
            _log(f"[Social] Page title: {metadata.get('title', 'N/A')}", "INFO")
            results.append(AttackResult("social", "metadata_extract", "SUCCESS",
                           target=domain, data=metadata, severity="INFO",
                           notes=f"Page metadata: title='{metadata.get('title', 'N/A')}'"))
        return results

    def _generate_dorks(self, domain: str) -> List[AttackResult]:
        dorks = [dork.format(domain=domain) for dork in GOOGLE_DORKS]
        _log(f"[Social] Generated {len(dorks)} Google dork queries for {domain}", "OK")
        for dork in dorks[:5]:
            _log(f"  {dork}", "INFO")
        _log(f"  ... and {len(dorks) - 5} more", "INFO")

        return [AttackResult("social", "google_dorks", "SUCCESS",
                            target=domain, data=dorks, severity="INFO",
                            notes=f"{len(dorks)} Google dork queries generated for manual OSINT")]


# ── Banner & Legal ────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        banner = pyfiglet.figlet_format("Spectre", font="slant")
        print(f"\033[36m{banner}\033[0m")
    else:
        print("\033[36m" + "=" * 50)
        print("  S P E C T R E   F R A M E W O R K")
        print("=" * 50 + "\033[0m")
    print(f"  {TOOL_NAME} v{VERSION}")
    print(f"  Author: {AUTHOR}")
    print(f"  OSINT & Passive Reconnaissance\n")


def print_legal(auto_accept: bool) -> bool:
    print(LEGAL_WARNING)
    if auto_accept:
        _log("Legal warning auto-accepted via --yes", "INFO")
        return True
    try:
        answer = input("\n  Do you have written authorization? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            _log("Authorization not confirmed. Exiting.", "ERR")
            return False
        return True
    except (KeyboardInterrupt, EOFError):
        print()
        return False


# ── Results Output ────────────────────────────────────────────────────────────

def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crits   = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    highs   = sum(1 for r in ctx.results if r.severity == "HIGH")

    print(f"\n\033[36m{'═' * 60}\n  SPECTRE RECONNAISSANCE RESULTS\n{'═' * 60}\033[0m")
    print(f"  Targets: {', '.join(ctx.targets)}")
    print(f"  Total: {len(ctx.results)} | Success: \033[32m{success}\033[0m"
          f" | Critical: \033[35m{crits}\033[0m | High: \033[33m{highs}\033[0m\n")

    for r in ctx.results:
        icons = {"SUCCESS": "\033[32m[+]", "FAILED": "\033[31m[x]",
                 "PARTIAL": "\033[33m[~]", "INFO": "\033[36m[*]"}
        sev_colors = {"CRITICAL": "\033[35m", "HIGH": "\033[31m",
                      "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[37m"}
        c = icons.get(r.status, "   ")
        sc = sev_colors.get(r.severity, "")
        reset = "\033[0m"
        print(f"  {c}{reset} [{r.module}] {r.action} {sc}[{r.severity}]{reset}")
        if r.notes:
            print(f"        {r.notes}")

    # Domain summaries
    for domain in ctx.targets:
        subs = ctx.subdomains.get(domain, set())
        emails = ctx.emails.get(domain, set())
        techs = ctx.technologies.get(domain, [])
        if subs or emails or techs:
            print(f"\n\033[36m  ── {domain} Summary ──\033[0m")
            if subs:
                print(f"    Subdomains: {len(subs)}")
            if emails:
                print(f"    Email addresses: {len(emails)}")
            if techs:
                print(f"    Technologies: {', '.join(techs)}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "targets": ctx.targets,
            "results": [
                {"module": r.module, "action": r.action, "status": r.status,
                 "target": r.target, "severity": r.severity, "notes": r.notes,
                 "data": r.data, "timestamp": r.timestamp}
                for r in ctx.results
            ],
            "subdomains": {d: list(s) for d, s in ctx.subdomains.items()},
            "emails": {d: list(e) for d, e in ctx.emails.items()},
            "dns_records": ctx.dns_records,
            "technologies": ctx.technologies,
            "whois": ctx.whois_data,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


# ── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
        Examples:
          python {COMMAND}.py --domain example.com --modules scan
          python {COMMAND}.py --targets domains.txt --modules dns cert
          python {COMMAND}.py --domain example.com --modules email social
          python {COMMAND}.py --domain example.com --modules all --output recon.json
          python {COMMAND}.py --domain example.com --modules all --yes --threads 20
        """))
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--domain", "-d", help="Single target domain")
    target_group.add_argument("--targets", "-t", help="File containing target domains (one per line)")
    p.add_argument("--modules", "-m", nargs="+",
                   choices=["scan", "email", "dns", "cert", "search", "social", "all"],
                   default=["scan"],
                   help="Modules to run (default: scan)")
    p.add_argument("--output", "-o", help="Save results to JSON file")
    p.add_argument("--yes", "-y", action="store_true", help="Auto-accept legal warning")
    p.add_argument("--threads", type=int, default=10, help="Thread count (default: 10)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests (default: 0.3)")
    p.add_argument("--stealth", action="store_true", help="Enable stealth mode (slower, less detectable)")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    print_banner()
    if not print_legal(args.yes):
        return 1

    # Build target list
    targets: List[str] = []
    if args.domain:
        targets.append(args.domain.strip().lower())
    elif args.targets:
        try:
            with open(args.targets, "r") as f:
                targets = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            _log(f"Target file not found: {args.targets}", "ERR")
            return 1

    if not targets:
        _log("No targets specified.", "ERR")
        return 1

    _log(f"Targets: {', '.join(targets)}", "INFO")

    # Stealth mode adjustments
    if args.stealth:
        args.delay = max(args.delay, 2.0)
        args.threads = min(args.threads, 3)
        _log("Stealth mode enabled — reduced threads and increased delay", "WARN")

    ctx = EngagementContext(
        targets=targets,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        stealth=args.stealth,
        output_file=args.output,
    )

    run_all = "all" in args.modules
    modules_to_run = ["scan", "email", "dns", "cert", "search", "social"] if run_all else args.modules

    module_map = {
        "scan":   SubdomainModule(),
        "email":  EmailModule(),
        "dns":    DNSIntelModule(),
        "cert":   CertModule(),
        "search": SearchModule(),
        "social": SocialModule(),
    }

    for mod_name in modules_to_run:
        mod = module_map.get(mod_name)
        if not mod:
            continue
        _log(f"Running module: {mod_name.upper()}", "INFO")
        print(f"\033[36m{'─' * 50}\033[0m")
        try:
            mod_results = mod.run(ctx)
            ctx.results.extend(mod_results)
        except KeyboardInterrupt:
            _log("Interrupted by user", "WARN")
            break
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
