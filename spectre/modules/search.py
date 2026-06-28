"""HTTP fingerprinting, technology detection, robots/sitemap parsing, security headers."""

from __future__ import annotations

import concurrent.futures
import hashlib
import re
import socket
from typing import Dict, List, Optional

from spectre.logger import log
from spectre.models import AttackResult, EngagementContext
from spectre.modules.base import BaseModule
from spectre.utils.network import resolve_host, safe_request

try:
    from spectre.data import COMMON_PORTS, SECURITY_HEADERS, TECH_SIGNATURES
except ImportError:
    TECH_SIGNATURES: Dict[str, List[str]] = {}
    SECURITY_HEADERS: List[str] = []
    COMMON_PORTS: List[int] = [21, 22, 25, 80, 443, 3306, 5432, 8080, 8443]


class SearchModule(BaseModule):
    """HTTP fingerprinting, technology detection, robots/sitemap parsing, security headers."""

    name = "search"

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            log(f"[Search] Starting infrastructure fingerprinting for {domain}", "INFO")

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
            resp = safe_request(f"{scheme}://{domain}/", timeout=timeout)
            if not resp:
                continue

            fingerprint_headers = ["Server", "X-Powered-By", "X-Generator",
                                   "X-AspNet-Version", "X-Runtime"]
            found = {}
            for header in fingerprint_headers:
                value = resp.headers.get(header)
                if value:
                    found[header] = value
                    log(f"[Search] {header}: {value}", "OK")

            if found:
                results.append(AttackResult("search", "header_fingerprint", "SUCCESS",
                               target=domain, data=found, severity="LOW",
                               notes=f"Server fingerprint: {', '.join(f'{k}={v}' for k, v in found.items())}"))
            break
        return results

    def _detect_technologies(self, domain: str, timeout: int) -> List[str]:
        detected = []
        resp = safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = safe_request(f"http://{domain}/", timeout=timeout)
        if not resp:
            return detected

        body = resp.text.lower()
        headers_str = str(resp.headers).lower()
        combined = body + headers_str

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    detected.append(tech)
                    log(f"[Search] Technology detected: {tech}", "OK")
                    break
        return detected

    def _parse_robots(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = safe_request(f"https://{domain}/robots.txt", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = safe_request(f"http://{domain}/robots.txt", timeout=timeout)
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
            log(f"[Search] robots.txt: {len(disallow_paths)} disallowed paths", "OK")
            results.append(AttackResult("search", "robots_parse", "SUCCESS",
                           target=domain, data=disallow_paths, severity="INFO",
                           notes=f"robots.txt: {len(disallow_paths)} disallowed paths"))

        if interesting_paths:
            log(f"[Search] Sensitive paths in robots.txt: {', '.join(interesting_paths)}", "CRIT")
            results.append(AttackResult("search", "robots_sensitive", "SUCCESS",
                           target=domain, data=interesting_paths, severity="HIGH",
                           notes=f"Sensitive paths exposed in robots.txt: {', '.join(interesting_paths)}"))

        return results

    def _parse_sitemap(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = safe_request(f"https://{domain}/sitemap.xml", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = safe_request(f"http://{domain}/sitemap.xml", timeout=timeout)
        if not resp or resp.status_code != 200:
            return results

        urls = re.findall(r'<loc>\s*(.*?)\s*</loc>', resp.text, re.IGNORECASE)
        if urls:
            log(f"[Search] sitemap.xml: {len(urls)} URLs indexed", "OK")
            results.append(AttackResult("search", "sitemap_parse", "SUCCESS",
                           target=domain, data=urls[:100], severity="INFO",
                           notes=f"sitemap.xml: {len(urls)} URLs — reveals site structure"))
        return results

    def _audit_security_headers(self, domain: str, timeout: int) -> List[AttackResult]:
        results = []
        resp = safe_request(f"https://{domain}/", timeout=timeout)
        if not resp:
            resp = safe_request(f"http://{domain}/", timeout=timeout)
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
            log(f"[Search] Missing security headers ({len(missing)}): {', '.join(missing)}", "WARN")
            severity = "HIGH" if len(missing) > 5 else "MEDIUM"
            results.append(AttackResult("search", "security_headers", "SUCCESS",
                           target=domain, severity=severity,
                           data={"present": present, "missing": missing},
                           notes=f"Missing {len(missing)}/{len(SECURITY_HEADERS)} security headers: {', '.join(missing)}"))

        if present:
            log(f"[Search] Present security headers: {', '.join(present)}", "OK")

        # Check HSTS specifically
        hsts = resp.headers.get("Strict-Transport-Security")
        if hsts:
            if "includeSubDomains" not in hsts:
                results.append(AttackResult("search", "hsts_partial", "SUCCESS",
                               target=domain, severity="LOW",
                               notes="HSTS present but does not include subdomains"))
        return results

    def _favicon_hash(self, domain: str, timeout: int) -> Optional[AttackResult]:
        resp = safe_request(f"https://{domain}/favicon.ico", timeout=timeout)
        if not resp or resp.status_code != 200:
            resp = safe_request(f"http://{domain}/favicon.ico", timeout=timeout)
        if not resp or resp.status_code != 200 or len(resp.content) < 10:
            return None

        import base64
        import struct

        favicon_b64 = base64.encodebytes(resp.content)
        fav_hash = hashlib.md5(favicon_b64).hexdigest()
        # MurmurHash3 approximation for Shodan compatibility
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

        log(f"[Search] Favicon hash: MD5={fav_hash} | MurmurHash3={h}", "OK")
        log(f"[Search] Shodan query: http.favicon.hash:{h}", "INFO")
        return AttackResult("search", "favicon_hash", "SUCCESS",
                           target=domain, severity="INFO",
                           data={"md5": fav_hash, "mmh3": h,
                                 "shodan_query": f"http.favicon.hash:{h}"},
                           notes=f"Favicon hash: Shodan query → http.favicon.hash:{h}")

    def _check_ports(self, domain: str, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        ip = resolve_host(domain)
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
            log(f"[Search] Open ports on {ip}: {', '.join(str(p) for p in open_ports)}", "OK")
            results.append(AttackResult("search", "port_scan", "SUCCESS",
                           target=domain, data={"ip": ip, "open_ports": open_ports},
                           severity="INFO",
                           notes=f"Open ports: {', '.join(str(p) for p in open_ports)}"))
        return results
