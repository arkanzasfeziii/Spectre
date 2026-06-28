"""Constants and configuration for Spectre."""

from __future__ import annotations

from spectre import __version__, __author__

TOOL_NAME = "Spectre Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "spectre"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SPECTRE — AUTHORIZED RECONNAISSANCE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework performs passive and semi-active reconnaissance: subdomain   ║
║  enumeration, email harvesting, DNS intelligence, certificate transparency  ║
║  analysis, infrastructure fingerprinting, and organization footprinting.    ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (domains / IP ranges)                                    ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
