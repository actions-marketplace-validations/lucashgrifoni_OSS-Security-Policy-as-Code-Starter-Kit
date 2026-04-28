"""Shared types for evidence collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class CollectionResult:
    """Result of a single evidence collection operation."""

    evidence_key: str
    data: dict[str, Any]
    source_url: str
    collected_at: str


class EvidenceCollector(ABC):
    """Abstract base for platform-specific evidence collectors."""

    @abstractmethod
    def collect(self, repo_slug: str) -> list[CollectionResult]:
        """Collect all available evidence for the given repository.

        Args:
            repo_slug: Platform-specific repository identifier (e.g. ``org/repo`` for GitHub).

        Returns:
            One :class:`CollectionResult` per evidence JSON file to be written.
        """
        ...
