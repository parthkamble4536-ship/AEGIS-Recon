"""
Typed exception hierarchy for AEGIS-Recon.

Each exception type maps to a specific API error response.
No blanket exception handlers — each failure mode has its own type.
"""

from __future__ import annotations


class AegisError(Exception):
    """Base exception for all AEGIS-Recon errors."""

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


# ── Validation Errors ────────────────────────────────────


class ValidationError(AegisError):
    """Input validation failed (bad IP, port, profile, etc.)."""
    pass


class AllowlistError(AegisError):
    """Target is not in the authorized allowlist."""
    pass


class AllowlistLoadError(AegisError):
    """Could not load or parse the allowlist file."""
    pass


# ── Scanner Errors ───────────────────────────────────────


class ScannerError(AegisError):
    """General scanner failure."""
    pass


class NmapNotFoundError(ScannerError):
    """Nmap binary not found on the system."""
    pass


class ScanTimeoutError(ScannerError):
    """Scan exceeded the configured timeout."""
    pass


class ScanExecutionError(ScannerError):
    """Nmap process returned a non-zero exit code."""
    pass


# ── Parser Errors ────────────────────────────────────────


class ParserError(AegisError):
    """Failed to parse scanner output."""
    pass


class MalformedXMLError(ParserError):
    """XML output is malformed or missing expected elements."""
    pass


# ── Intelligence Errors ──────────────────────────────────


class IntelError(AegisError):
    """General intelligence module failure."""
    pass


class IntelUnavailableError(IntelError):
    """External intelligence source is unreachable or rate-limited."""
    pass


class IntelParseError(IntelError):
    """Failed to parse response from intelligence source."""
    pass


# ── Database Errors ──────────────────────────────────────


class DatabaseError(AegisError):
    """Database operation failed."""
    pass


# ── AI / LLM Errors ─────────────────────────────────────


class LLMError(AegisError):
    """General LLM analysis failure."""
    pass


class LLMUnavailableError(LLMError):
    """LLM provider is unreachable or not configured."""
    pass


class LLMValidationError(LLMError):
    """LLM output failed schema validation (hallucination, injection, etc.)."""
    pass


# ── Report Errors ────────────────────────────────────────


class ReportError(AegisError):
    """Report generation failed."""
    pass
