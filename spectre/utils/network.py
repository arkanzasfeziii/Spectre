"""Network utilities: HTTP requests, DNS queries, hostname resolution."""

from __future__ import annotations

import random
import socket
import time
from typing import Any, Dict, List, Optional

from spectre.models import EngagementContext

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def delay(ctx: EngagementContext) -> None:
    if ctx.delay > 0:
        jitter = ctx.delay * (0.5 + random.random())
        time.sleep(jitter)


def safe_request(url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None,
                 verify: bool = False) -> Optional[Any]:
    if not HAS_REQUESTS:
        return None
    try:
        hdrs = {"User-Agent": DEFAULT_UA}
        if headers:
            hdrs.update(headers)
        return requests.get(url, headers=hdrs, timeout=timeout, verify=verify,
                            allow_redirects=True)
    except Exception:
        return None


def resolve_host(hostname: str) -> Optional[str]:
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except (socket.gaierror, socket.herror, OSError):
        pass
    return None


def dns_query(name: str, rdtype: str) -> List[str]:
    if not HAS_DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=5)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []
