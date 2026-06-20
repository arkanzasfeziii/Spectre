# Spectre — OSINT & Passive Reconnaissance Framework

> **Map every subdomain, harvest email patterns, interrogate DNS records, inspect certificates, fingerprint infrastructure, and footprint the organization — without sending a single exploit.**

---

## Threat Model

Reconnaissance failures are not technical — they are operational. Organizations expose more through passive channels than most defenders realize: certificate transparency logs publish internal subdomain names, DNS records leak mail infrastructure and cloud providers, WHOIS reveals organizational structure, and robots.txt advertises the paths administrators wanted hidden.

Spectre models the attacker who builds a complete target profile before writing a single packet to the wire:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **Certificate Transparency** | Internal subdomain names published in CT logs (dev, staging, internal, uat) | Query crt.sh for all issued certificates — extract SANs that reveal internal infrastructure names |
| **DNS Intelligence** | SPF/DMARC misconfigured or absent; zone transfers permitted; DKIM selectors enumerable | Enumerate all DNS record types; identify email authentication gaps for spoofing; attempt AXFR |
| **WHOIS Exposure** | Domain privacy not enabled; registrant name, email, and organization visible | Extract registrant identity, organization name, registration timeline, and associated email addresses |
| **Email Pattern Leak** | Predictable email naming convention; SMTP VRFY enabled on mail server | Construct email patterns from domain; verify addresses via SMTP; build phishing target list |
| **robots.txt Disclosure** | Sensitive paths (admin panels, API endpoints, config files) listed in Disallow directives | Parse robots.txt for paths the organization explicitly marked as sensitive — treat as a directory of targets |
| **Infrastructure Fingerprint** | Server headers, technology stack, and favicon hashes exposed in HTTP responses | Fingerprint web server, framework, and CDN; compute favicon hash for Shodan cross-referencing |

**Scope:** Authorized red team engagements where the objective is to quantify an organization's passive exposure — what an adversary learns before any active exploitation begins.

---

## Why This Exists

Reconnaissance is the most skipped phase in offensive engagements. Operators jump to scanning and exploitation because recon feels slow, its outputs feel scattered, and the tools that exist don't chain their findings into an actionable target profile.

The gap between "I have a domain name" and "I have a complete map of subdomains, email patterns, DNS misconfigurations, certificate exposures, technology stack, and organizational structure" is exactly the gap that separates a noisy scan from a targeted operation:

- Certificate transparency logs are public. Every certificate issued for a domain — including internal subdomains like `staging.internal.corp.example.com` — is permanently recorded and queryable
- DNS records are not just routing data. SPF, DMARC, and DKIM records reveal email infrastructure and authentication posture. A missing DMARC record means the domain can be spoofed with zero effort
- WHOIS without privacy protection exposes the registrant's identity, organization, and often personal email — enough to build a pretexting scenario
- robots.txt is a map drawn by the defender. Every `Disallow` entry is a path the organization considers sensitive enough to hide from crawlers — and interesting enough for an attacker to investigate
- HTTP response headers and favicon hashes are passive fingerprints. A single Shodan query with a favicon hash can reveal every server running the same application worldwide

Spectre chains these passive sources. Subdomains found via crt.sh feed into DNS enumeration. DNS records identify mail servers that feed into email verification. WHOIS data enriches organizational footprinting. The output is not a list of raw findings — it is a structured reconnaissance package.

---

## Capabilities

### Subdomain Enumeration (`scan`)
- **Certificate transparency** — query crt.sh for all certificates issued for the target domain; extract unique subdomains from certificate Name Value fields and SANs
- **DNS brute-force** — resolve ~100 common subdomain prefixes (www, mail, api, vpn, dev, staging, admin, portal, sso, auth, ci, grafana, jenkins, etc.) against the target domain
- **Wildcard detection** — resolve a random 16-character subdomain to detect wildcard DNS; exclude wildcard IPs from brute-force results to eliminate false positives
- **IP resolution** — resolve all discovered subdomains to their IPv4 addresses via `socket.getaddrinfo`; threaded resolution with configurable worker count
- **Attack surface scoring** — flag domains with >20 exposed subdomains as high-severity (large attack surface)

### Email Harvesting (`email`)
- **MX record lookup** — verify the domain accepts email by resolving MX records; identify mail server hostnames and providers
- **Role-based address generation** — generate 25 common role addresses (info@, admin@, support@, hr@, security@, abuse@, postmaster@, etc.)
- **Email pattern detection** — construct 8 corporate email naming patterns ({first}.{last}@, {f}{last}@, {first}_{last}@, etc.) for use with employee name lists
- **SMTP VRFY verification** — connect to the primary MX host on port 25; attempt SMTP VRFY for each role address; flag servers that confirm addresses as high-severity
- **Breach database URLs** — construct lookup URLs for HaveIBeenPwned, DeHashed, IntelX, and Leak-Lookup for manual domain-wide breach checking
- **Hunter.io integration** — construct Hunter.io domain lookup URL for email pattern verification

### DNS Intelligence (`dns`)
- **Full record enumeration** — query A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, PTR records for the target domain
- **SPF analysis** — parse SPF TXT records; extract `include:` mechanisms and `ip4:` directives; flag `+all` (pass all — no protection), `~all` (softfail), and `?all` (neutral) as misconfigured
- **DMARC check** — query `_dmarc.{domain}` TXT record; extract policy (none/quarantine/reject); flag `p=none` as high-severity (spoofed mail accepted)
- **DKIM brute-force** — enumerate 20+ common DKIM selectors (default, google, selector1, selector2, k1, mandrill, sendgrid, amazonses, etc.) against `{selector}._domainkey.{domain}`
- **DNS provider identification** — map NS records to known providers (Cloudflare, Route 53, Azure DNS, Google Cloud DNS, GoDaddy, Namecheap, etc.)
- **Zone transfer attempt** — attempt AXFR against all nameservers; report full zone contents if any nameserver permits the transfer

### Certificate Transparency & SSL (`cert`)
- **crt.sh enumeration** — query certificate transparency logs for all certificates issued for `%.{domain}`; return issuer, validity dates, and SAN entries
- **Live certificate inspection** — connect to port 443; extract subject, issuer, validity period, serial number, and all SANs from the presented certificate
- **Issuer identification** — classify certificate issuer (Let's Encrypt, DigiCert, Comodo, Sectigo, GoDaddy, Amazon, Google Trust, Cloudflare, ZeroSSL)
- **Expiry monitoring** — flag certificates expired or expiring within 30 days
- **Wildcard detection** — identify wildcard certificates (`*.example.com`) in SANs
- **Internal SAN exposure** — flag SANs containing internal indicators (internal, corp, intranet, staging, dev, test, uat) as high-severity information leaks
- **TLS version detection** — test TLS 1.0, 1.1, 1.2, and 1.3 support; flag deprecated versions (1.0, 1.1) as downgrade-attack vectors

### Infrastructure Fingerprinting (`search`)
- **HTTP header fingerprinting** — extract Server, X-Powered-By, X-Generator, X-AspNet-Version, X-Runtime headers from HTTP responses
- **Technology detection** — scan response body and headers for 22 technology signatures: WordPress, Drupal, Joomla, Laravel, Django, React, Angular, Vue.js, Next.js, ASP.NET, Spring, Express, Nginx, Apache, Cloudflare, AWS S3, Varnish, IIS, Tomcat, GraphQL, Swagger
- **robots.txt analysis** — parse Disallow directives; flag sensitive paths (admin, api, config, backup, internal, .env, .git, phpmyadmin, console, dashboard)
- **sitemap.xml parsing** — extract all `<loc>` URLs to reveal site structure and content organization
- **Security headers audit** — check 10 security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP); flag missing headers with severity scaling
- **Favicon hash calculation** — compute MD5 and MurmurHash3 of favicon.ico; output Shodan-compatible `http.favicon.hash:{hash}` query for cross-referencing
- **Port scanning** — check 9 common ports (21, 22, 25, 80, 443, 3306, 5432, 8080, 8443) via TCP connect; threaded scanning

### Organization Footprinting (`social`)
- **WHOIS lookup** — extract registrar, creation date, expiry date, name servers, organization, registrant name, and contact emails; flag unprotected registrant data as high-severity
- **Social media profiling** — construct profile URLs for LinkedIn, Twitter/X, GitHub, Facebook, Instagram, and Crunchbase based on domain name
- **GitHub organization enumeration** — query GitHub API for org profile, public repo count, top repositories, and programming languages used
- **Page metadata extraction** — extract HTML title, meta description, Open Graph tags, and generator meta tag from the domain's index page
- **Google dork generation** — produce 17 targeted dork queries: `site:`, `inurl:admin`, `inurl:login`, `filetype:pdf/xlsx/docx/conf/env/log/sql/bak/xml`, `intitle:"index of"`, `intext:"password"`

---

## Architecture

```
Target Domain(s)
       │
       ▼
EngagementContext
┌──────────────────────────────────────────┐
│  targets · threads · timeout · delay     │
│  subdomains · emails · dns_records       │
│  certificates · technologies · whois     │
└──────────────────────────────────────────┘
       │
       ├──────────────┬──────────────┐
       ▼              ▼              ▼
  SubdomainModule  EmailModule  DNSIntelModule
  crt.sh + brute   MX + VRFY    A/MX/NS/TXT/SOA
  wildcard detect  patterns     SPF/DMARC/DKIM
       │              │         zone transfer
       │              │              │
       ├──────────────┼──────────────┤
       ▼              ▼              ▼
  CertModule     SearchModule   SocialModule
  CT logs + SSL  HTTP headers   WHOIS lookup
  SAN extraction tech detect    GitHub enum
  TLS versions   robots.txt     Google dorks
  issuer ID      favicon hash   metadata
                 port scan      social URLs
       │              │              │
       └──────────────┴──────────────┘
                      │
                      ▼
               JSON Report
       (domain · module · severity)
```

---

## Attack Flow

1. **Target acquisition** — specify a single domain via `--domain` or a list via `--targets`; Spectre normalizes all inputs to lowercase and validates format
2. **Subdomain enumeration** — detect wildcard DNS to avoid false positives; query crt.sh certificate transparency for all issued certificates; brute-force ~100 common subdomain prefixes; resolve all discovered subdomains to IP addresses
3. **Email reconnaissance** — confirm the domain accepts email via MX lookup; generate role-based and pattern-based addresses; attempt SMTP VRFY verification against the primary mail server; construct breach database lookup URLs
4. **DNS intelligence** — enumerate all standard record types; analyze SPF configuration for email spoofing viability; check DMARC policy enforcement level; brute-force DKIM selectors; identify the DNS provider; attempt zone transfer against all nameservers
5. **Certificate analysis** — query transparency logs for historical certificates; inspect the live SSL certificate for SANs, issuer, and expiry; detect internal subdomain names leaked through SANs; test for deprecated TLS versions
6. **Infrastructure fingerprinting** — extract server and technology headers; detect frameworks and CDNs from response content; parse robots.txt for sensitive paths; compute favicon hash for Shodan cross-referencing; audit security headers; scan common ports
7. **Organization footprinting** — WHOIS lookup for registrant and registration data; enumerate GitHub organization repos and languages; extract page metadata and Open Graph tags; generate targeted Google dork queries
8. **Report** — `--output recon.json` with structured findings per module, severity ratings, and domain-level summaries

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Enumerate subdomains for a single domain
python spectre.py --domain example.com --modules scan

# Full reconnaissance chain
python spectre.py --domain example.com --modules all --output recon.json

# DNS intelligence + certificate analysis
python spectre.py --domain example.com --modules dns cert

# Email harvesting + organization footprinting
python spectre.py --domain example.com --modules email social

# Multiple domains from a file
python spectre.py --targets domains.txt --modules all --output findings.json

# Stealth mode — slower requests, fewer threads
python spectre.py --domain example.com --modules all --stealth --yes

# Non-interactive with custom thread count
python spectre.py --domain example.com --modules all --yes --threads 20 --timeout 15

# Infrastructure fingerprinting only
python spectre.py --domain example.com --modules search
```

---

## Output

```
  ___                   _
 / __|  _ __   ___  __ | |_  _ _  ___
 \__ \ | '_ \ / -_)/ _||  _|| '_|/ -_)
 |___/ | .__/ \___|\__| \__||_|  \___|
       |_|

  Spectre Framework v1.0.0
  Author: arkanzasfeziii
  OSINT & Passive Reconnaissance

09:14:01 [INFO] Targets: megacorp.com
09:14:01 [INFO] Running module: SCAN
──────────────────────────────────────────────────
09:14:01 [INFO] [Subdomain] Starting enumeration for megacorp.com
09:14:01 [WARN] [Subdomain] Wildcard DNS detected for *.megacorp.com → 104.18.22.1
09:14:03 [OK]   [Subdomain] crt.sh returned 47 subdomains
09:14:05 [OK]   [Subdomain] Brute-force found 23 live subdomains
09:14:06 [OK]   [Subdomain] Total unique subdomains for megacorp.com: 58
09:14:06 [INFO]   vpn.megacorp.com → 10.0.44.2
09:14:06 [INFO]   staging.internal.megacorp.com → 10.0.12.8
09:14:06 [INFO]   jenkins.megacorp.com → 34.102.55.12
09:14:06 [INFO]   grafana.megacorp.com → 34.102.55.13

09:14:06 [INFO] Running module: EMAIL
──────────────────────────────────────────────────
09:14:06 [OK]   [Email] MX records found: mx1.mailprovider.com, mx2.mailprovider.com
09:14:07 [INFO] [Email] Generated 25 role-based addresses
09:14:08 [CRIT] [Email] SMTP VRFY confirmed 3 addresses

09:14:08 [INFO] Running module: DNS
──────────────────────────────────────────────────
09:14:08 [OK]   [DNS] A: 104.18.22.1, 104.18.23.1
09:14:08 [OK]   [DNS] MX: 10 mx1.mailprovider.com., 20 mx2.mailprovider.com.
09:14:08 [OK]   [DNS] NS: ns1.cloudflare.com., ns2.cloudflare.com.
09:14:09 [OK]   [DNS] TXT: "v=spf1 include:mailprovider.com ~all"
09:14:09 [WARN] [DNS] SPF uses ~all (softfail) — spoofed mail may be delivered
09:14:09 [CRIT] [DNS] No DMARC record — domain has no spoofing policy
09:14:10 [OK]   [DNS] DKIM selector found: google → v=DKIM1; k=rsa; p=MIIBIjAN...
09:14:10 [INFO] [DNS] DNS provider: Cloudflare
09:14:10 [INFO] [DNS] Zone transfer denied by all nameservers (expected)

09:14:10 [INFO] Running module: CERT
──────────────────────────────────────────────────
09:14:11 [OK]   [Cert] crt.sh returned 84 certificates
09:14:12 [OK]   [Cert] Issuer: Let's Encrypt
09:14:12 [INFO] [Cert] Expires: 2026-09-14
09:14:12 [OK]   [Cert] SANs (6): megacorp.com, www.megacorp.com, api.megacorp.com,
                        staging.megacorp.com, internal.megacorp.com, dev.megacorp.com
09:14:12 [CRIT] [Cert] Internal subdomains in SANs: staging.megacorp.com, internal.megacorp.com, dev.megacorp.com
09:14:13 [OK]   [Cert] TLS versions supported: TLSv1.2, TLSv1.3

09:14:13 [INFO] Running module: SEARCH
──────────────────────────────────────────────────
09:14:14 [OK]   [Search] Server: cloudflare
09:14:14 [OK]   [Search] Technology detected: Cloudflare
09:14:14 [OK]   [Search] Technology detected: React
09:14:14 [OK]   [Search] Technology detected: Next.js
09:14:15 [OK]   [Search] robots.txt: 8 disallowed paths
09:14:15 [CRIT] [Search] Sensitive paths in robots.txt: /admin, /api/internal, /.env
09:14:15 [WARN] [Search] Missing security headers (4): Content-Security-Policy,
                         X-Frame-Options, Permissions-Policy, Cross-Origin-Opener-Policy
09:14:16 [OK]   [Search] Favicon hash: Shodan query → http.favicon.hash:-1274016831
09:14:16 [OK]   [Search] Open ports on 104.18.22.1: 22, 80, 443, 8080

09:14:16 [INFO] Running module: SOCIAL
──────────────────────────────────────────────────
09:14:17 [OK]   [Social] Registrar: Namecheap, Inc.
09:14:17 [INFO] [Social] Domain created: 2019-03-14
09:14:17 [INFO] [Social] Domain expires: 2027-03-14
09:14:17 [CRIT] [Social] Registrant: John Smith (WHOIS not privacy-protected)
09:14:18 [OK]   [Social] GitHub org found: megacorp — 34 public repos
09:14:18 [INFO] [Social] Languages: Python, TypeScript, Go, Rust
09:14:18 [OK]   [Social] Generated 17 Google dork queries for megacorp.com

═══════════════════════════════════════════════════════
  SPECTRE RECONNAISSANCE RESULTS
═══════════════════════════════════════════════════════
  Targets: megacorp.com
  Total: 31 | Success: 29 | Critical: 5 | High: 3

  [+] [subdomain] crtsh_enum [INFO]
        47 subdomains from certificate transparency
  [+] [subdomain] brute_force [INFO]
        23 subdomains via DNS brute-force
  [+] [subdomain] large_surface [HIGH]
        Large attack surface: 58 subdomains exposed
  [+] [email] smtp_vrfy [HIGH]
        SMTP VRFY enabled — 3 addresses verified
  [+] [dns] spf_analysis [MEDIUM]
        SPF: v=spf1 include:mailprovider.com ~all | Issues: softfail
  [+] [dns] dmarc_check [CRITICAL]
        No DMARC record — no email authentication policy
  [+] [cert] internal_sans [HIGH]
        Internal subdomains exposed via certificate SANs
  [+] [search] robots_sensitive [HIGH]
        Sensitive paths exposed in robots.txt: /admin, /api/internal, /.env
  [+] [social] whois_registrant [HIGH]
        WHOIS registrant not privacy-protected: John Smith

  ── megacorp.com Summary ──
    Subdomains: 58
    Email addresses: 25
    Technologies: Cloudflare, React, Next.js

[+] Results saved → recon.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module | Description |
|---|---|---|---|
| Gather Victim Identity Information | T1589 | EmailModule, SocialModule | Email addresses, employee names, organizational roles |
| Gather Victim Network Information | T1590 | SubdomainModule, DNSIntelModule | Subdomains, DNS records, IP ranges, mail servers |
| Gather Victim Org Information | T1591 | SocialModule | WHOIS registrant, business relationships, org structure |
| Gather Victim Host Information | T1592 | SearchModule, CertModule | Server software, client configurations, firmware versions |
| Search Open Websites/Domains | T1593 | SocialModule, SearchModule | Social media profiles, public code repositories, metadata |
| Search Open Technical Databases | T1596 | CertModule, DNSIntelModule | Certificate transparency logs, DNS databases, WHOIS |

**Tactics:** TA0043 Reconnaissance

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Certificate SANs leaking internal subdomains; WHOIS registrant exposure; server headers revealing technology stack |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | robots.txt exposing sensitive paths; sitemap.xml revealing site structure; .env files in disallow lists |
| CWE-16 | Configuration | Missing SPF/DMARC/DKIM records enabling email spoofing; absent security headers; deprecated TLS versions enabled |

---

## Legal Notice

Spectre is designed exclusively for authorized penetration testing and security assessment activities where explicit written permission has been obtained from the asset owner. Unauthorized reconnaissance against domains or organizations without prior authorization is illegal and may violate computer fraud statutes in multiple jurisdictions. The author assumes no liability for misuse.
