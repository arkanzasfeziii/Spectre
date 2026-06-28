"""Data models used across all Spectre modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    target: str = ""
    data: Any = None
    severity: str = "INFO"
    notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class EngagementContext:
    targets: List[str] = field(default_factory=list)
    threads: int = 10
    timeout: int = 10
    delay: float = 0.3
    stealth: bool = False
    results: List[AttackResult] = field(default_factory=list)
    output_file: Optional[str] = None
    subdomains: Dict[str, Set[str]] = field(default_factory=dict)
    emails: Dict[str, Set[str]] = field(default_factory=dict)
    dns_records: Dict[str, Dict] = field(default_factory=dict)
    certificates: Dict[str, List] = field(default_factory=dict)
    technologies: Dict[str, List] = field(default_factory=dict)
    whois_data: Dict[str, Dict] = field(default_factory=dict)
