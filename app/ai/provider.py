"""
AI provider interface and Anthropic implementation for AEGIS-Recon.

Design principles:
- LLM can NEVER execute commands or trigger actions.
- LLM output is schema-validated before use.
- All findings are supplied to the LLM — it cannot invent CVEs.
- Deterministic fallback always available when LLM is unavailable.
- Prompt injection defenses: data is delimited, instructions are clear.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIProvider(ABC):
    """Abstract interface for AI analysis providers."""

    @abstractmethod
    def analyze_findings(
        self,
        findings: list[dict[str, Any]],
        scan_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Analyze scan findings and produce a summary.

        Args:
            findings: List of finding dicts (from the database).
            scan_context: Scan metadata (target, profile, timestamps).

        Returns:
            Analysis dict with keys: summary, recommendations,
            risk_overview, limitations.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and reachable."""
        ...
