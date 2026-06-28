"""Abstract base class for all Spectre modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from spectre.models import AttackResult, EngagementContext


class BaseModule(ABC):

    name: str = "base"

    @abstractmethod
    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        ...
