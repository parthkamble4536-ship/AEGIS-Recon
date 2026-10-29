"""
Match result model for AEGIS-Recon Correlation Engine V2.

Represents the result of matching a NormalizedService against CVE
intelligence, with explicit confidence, method, evidence, and reason
fields to make every correlation decision explainable and auditable.

CRITICAL: A match result is NEVER a confirmed vulnerability.
          Every result carries verification_required=True unless
          actual exploitation evidence exists (which AEGIS never has).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class MatchConfidence(StrEnum):
    """Explicit confidence level for a CVE correlation match."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MatchMethod(StrEnum):
    """
    The method used to correlate a service to a CVE.

    Listed in order of decreasing confidence:
    1. CPE_EXACT        — exact CPE URI match in NVD affected configurations
    2. CPE_VERSION_RANGE — CPE vendor+product match + version within affected range
    3. VENDOR_PRODUCT_VERSION — vendor + product + version all matched
    4. PRODUCT_VERSION  — product + version matched (vendor unknown or not matched)
    5. PRODUCT_ONLY     — product name matched, version unconfirmed
    """

    CPE_EXACT = "cpe_exact"
    CPE_VERSION_RANGE = "cpe_version_range"
    VENDOR_PRODUCT_VERSION = "vendor_product_version"
    PRODUCT_VERSION = "product_version"
    PRODUCT_ONLY = "product_only"


@dataclass
class MatchResult:
    """
    Result of correlating a NormalizedService against CVE intelligence.

    Every field is populated explicitly so the correlation decision can be
    fully explained and audited without referring to raw NVD data.
    """

    cve_id: str

    # What method was used and what was matched
    match_method: MatchMethod = MatchMethod.PRODUCT_ONLY
    matched_vendor: str = ""
    matched_product: str = ""
    matched_version: str = ""
    matched_cpe: str = ""

    # Confidence in this correlation
    confidence: MatchConfidence = MatchConfidence.LOW

    # Supporting evidence items (list of short descriptive strings)
    evidence: list[str] = field(default_factory=list)

    # Human-readable explanation of why this match was made
    reason: str = ""

    # ALWAYS True — a version match is never a confirmed vulnerability
    # Only manual verification or actual exploitation evidence changes this
    verification_required: bool = True
