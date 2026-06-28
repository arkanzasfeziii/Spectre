"""Certificate transparency analysis, SSL/TLS inspection, and certificate intelligence."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional

from spectre.logger import log
from spectre.models import AttackResult, EngagementContext
from spectre.modules.base import BaseModule

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CertModule(BaseModule):
    """Certificate transparency analysis, SSL/TLS inspection, and certificate intelligence."""

    name = "cert"

    TLS_VERSIONS = {
        "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        for domain in ctx.targets:
            log(f"[Cert] Starting certificate analysis for {domain}", "INFO")

            # crt.sh certificate enumeration
            certs = self._crtsh_certs(domain, ctx.timeout)
            if certs:
                log(f"[Cert] crt.sh returned {len(certs)} certificates", "OK")
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
                log(f"[Cert] TLS versions supported: {', '.join(supported)}", "OK")
                if deprecated:
                    log(f"[Cert] Deprecated TLS versions enabled: {', '.join(deprecated)}", "CRIT")
                    results.append(AttackResult("cert", "tls_deprecated", "SUCCESS",
                                   target=domain, severity="HIGH",
                                   data={"supported": supported, "deprecated": deprecated},
                                   notes=f"Deprecated TLS: {', '.join(deprecated)} — downgrade attacks possible"))
                results.append(AttackResult("cert", "tls_versions", "SUCCESS",
                               target=domain, data=tls_results, severity="INFO",
                               notes=f"TLS support: {', '.join(supported)}"))

        return results

    def _crtsh_certs(self, domain: str, timeout: int) -> List[Dict]:
        if not HAS_REQUESTS:
            return []
        try:
            resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                               timeout=timeout, verify=True)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            log(f"[Cert] crt.sh query error: {exc}", "ERR")
        return []

    def _inspect_live_cert(self, domain: str, timeout: int) -> Optional[Dict]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    if HAS_CRYPTOGRAPHY and cert_der:
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
            log(f"[Cert] SSL connection to {domain}:443 failed: {exc}", "WARN")
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

        log(f"[Cert] Issuer: {issuer}", "OK")
        log(f"[Cert] Expires: {not_after}", "INFO")

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
                    log(f"[Cert] Certificate EXPIRED {abs(days_left)} days ago!", "CRIT")
                    results.append(AttackResult("cert", "expiry_check", "SUCCESS",
                                   target=domain, severity="CRITICAL",
                                   notes=f"Certificate expired {abs(days_left)} days ago"))
                elif days_left < 30:
                    log(f"[Cert] Certificate expires in {days_left} days", "WARN")
                    results.append(AttackResult("cert", "expiry_check", "SUCCESS",
                                   target=domain, severity="MEDIUM",
                                   notes=f"Certificate expires in {days_left} days"))
            except (ValueError, TypeError):
                pass

        # SANs analysis
        if sans:
            log(f"[Cert] SANs ({len(sans)}): {', '.join(sans[:10])}", "OK")
            wildcards = [s for s in sans if s.startswith("*.")]
            if wildcards:
                log(f"[Cert] Wildcard certificates: {', '.join(wildcards)}", "WARN")
                results.append(AttackResult("cert", "wildcard_cert", "SUCCESS",
                               target=domain, severity="MEDIUM",
                               data=wildcards,
                               notes=f"Wildcard certs: {', '.join(wildcards)}"))

            # SANs expose internal subdomains
            internal_indicators = ["internal", "corp", "intranet", "staging", "dev", "test", "uat"]
            internal_sans = [s for s in sans if any(ind in s.lower() for ind in internal_indicators)]
            if internal_sans:
                log(f"[Cert] Internal subdomains in SANs: {', '.join(internal_sans)}", "CRIT")
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
