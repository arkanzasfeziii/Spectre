"""Custom exception hierarchy for Spectre."""

from __future__ import annotations


class SpectreError(Exception):
    """Base exception."""


class ModuleError(SpectreError):
    """Module runtime error."""


class DependencyError(SpectreError):
    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
