"""WHOIS lookup, social media footprinting, metadata extraction, Google dorking."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from spectre.logger import log
from spectre.models import AttackResult, EngagementContext
from spectre.modules.base import BaseModule
from spectre.utils.network import safe_request

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from spectre.data import GOOGLE_DORKS
except ImportError:
    GOOGLE_DORKS: List[str] = [
        'site:{domain}',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
    ]


class SocialModule(BaseModule):
    """WHOIS lookup, social media footprinting, metadata extraction, Google dorking."""

    name = "social"

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            log(f"[Social] Starting organization footprinting for {domain}", "INFO")

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
        if not HAS_WHOIS:
            log("[Social] Install python-whois: pip install python-whois", "ERR")
            return results

        try:
            w = python_whois.whois(domain)
            whois_data = {}

            registrar = w.registrar
            if registrar:
                whois_data["registrar"] = registrar
                log(f"[Social] Registrar: {registrar}", "OK")

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                whois_data["creation_date"] = str(creation)
                log(f"[Social] Domain created: {creation}", "INFO")

            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                whois_data["expiration_date"] = str(expiry)
                log(f"[Social] Domain expires: {expiry}", "INFO")

            name_servers = w.name_servers
            if name_servers:
                if isinstance(name_servers, list):
                    name_servers = [ns.lower() for ns in name_servers]
                whois_data["name_servers"] = name_servers
                log(f"[Social] Name servers: {', '.join(name_servers) if isinstance(name_servers, list) else name_servers}", "INFO")

            org = w.org
            if org:
                whois_data["organization"] = org
                log(f"[Social] Organization: {org}", "OK")

            # Registrant info (if not privacy-protected)
            registrant = w.get("name") or w.get("registrant_name")
            if registrant and "privacy" not in str(registrant).lower() and "redacted" not in str(registrant).lower():
                whois_data["registrant"] = registrant
                log(f"[Social] Registrant: {registrant}", "CRIT")
                results.append(AttackResult("social", "whois_registrant", "SUCCESS",
                               target=domain, severity="HIGH",
                               data={"registrant": registrant},
                               notes=f"WHOIS registrant not privacy-protected: {registrant}"))

            emails_found = w.emails
            if emails_found:
                if isinstance(emails_found, str):
                    emails_found = [emails_found]
                whois_data["emails"] = emails_found
                log(f"[Social] WHOIS emails: {', '.join(emails_found)}", "OK")

            results.append(AttackResult("social", "whois_lookup", "SUCCESS",
                           target=domain, data=whois_data, severity="INFO",
                           notes=f"WHOIS: registrar={registrar or 'N/A'}, created={creation or 'N/A'}"))

        except Exception as exc:
            log(f"[Social] WHOIS lookup failed: {exc}", "ERR")
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
        log(f"[Social] Constructed social media profile URLs for '{org_name}':", "INFO")
        for platform, url in profiles.items():
            log(f"  {platform}: {url}", "INFO")

        return [AttackResult("social", "social_profiles", "SUCCESS",
                            target=domain, data=profiles, severity="INFO",
                            notes=f"Social profile URLs constructed for org '{org_name}'")]

    def _github_enum(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        if not HAS_REQUESTS:
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
                log(f"[Social] GitHub org found: {org_name} — {data.get('public_repos', 0)} public repos", "OK")
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
                    log(f"[Social] GitHub repos: {', '.join(repo_names[:5])}", "INFO")
                    log(f"[Social] Languages: {', '.join(languages)}", "INFO")
                    results.append(AttackResult("social", "github_repos", "SUCCESS",
                                   target=domain, data={"repos": repo_names, "languages": languages},
                                   severity="INFO",
                                   notes=f"Top repos: {', '.join(repo_names[:5])}"))

            elif resp.status_code == 404:
                log(f"[Social] No GitHub org found for '{org_name}'", "INFO")
            else:
                log(f"[Social] GitHub API returned {resp.status_code}", "WARN")
        except Exception as exc:
            log(f"[Social] GitHub API error: {exc}", "ERR")
        return results

    def _extract_metadata(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = safe_request(f"http://{domain}/", timeout=timeout)
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
            log(f"[Social] Generator: {metadata['generator']}", "OK")

        if metadata:
            log(f"[Social] Page title: {metadata.get('title', 'N/A')}", "INFO")
            results.append(AttackResult("social", "metadata_extract", "SUCCESS",
                           target=domain, data=metadata, severity="INFO",
                           notes=f"Page metadata: title='{metadata.get('title', 'N/A')}'"))
        return results

    def _generate_dorks(self, domain: str) -> List[AttackResult]:
        dorks = [dork.format(domain=domain) for dork in GOOGLE_DORKS]
        log(f"[Social] Generated {len(dorks)} Google dork queries for {domain}", "OK")
        for dork in dorks[:5]:
            log(f"  {dork}", "INFO")
        log(f"  ... and {len(dorks) - 5} more", "INFO")

        return [AttackResult("social", "google_dorks", "SUCCESS",
                            target=domain, data=dorks, severity="INFO",
                            notes=f"{len(dorks)} Google dork queries generated for manual OSINT")]
