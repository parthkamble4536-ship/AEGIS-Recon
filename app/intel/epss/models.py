"""
EPSS score model for AEGIS-Recon.

EPSS (Exploit Prediction Scoring System) provides a probability estimate
that a CVE will be exploited in the wild within 30 days.

CRITICAL: If EPSS is unavailable, probability is None — NOT 0.0.
          Do not interpret missing EPSS data as low risk.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EPSSScore:
    """
    EPSS score for a single CVE.

    Fields:
        cve_id:       CVE identifier (e.g. "CVE-2021-44228").
        probability:  Float in [0, 1] representing exploit probability within 30 days.
                      None if EPSS data is unavailable — never defaults to 0.
        percentile:   Percentile rank of this CVE among all scored CVEs (0–1).
                      None if unavailable.
        source:       Data source identifier (always "FIRST-EPSS").
        retrieved_at: ISO-8601 timestamp when data was fetched from the API.
        expires_at:   ISO-8601 timestamp after which the cached value should be
                      re-fetched (typically retrieved_at + 24 h).
    """

    cve_id: str
    probability: float | None  # NEVER default to 0 — use None for unavailable
    percentile: float | None  # NEVER default to 0 — use None for unavailable
    source: str = "FIRST-EPSS"
    retrieved_at: str = ""
    expires_at: str = ""

