"""Static data for Spectre modules."""

from __future__ import annotations

from typing import Dict, List

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
