"""
Evidence models for AEGIS-Recon Phase 6.

Every claim in a finding should be backed by one or more Evidence records.
This allows an analyst (or auditor) to answer:
    "Why did AEGIS flag this? What data supports it?"

Evidence sources:
    NMAP            — directly observed via network scan
    NVD             — NVD API CVE record
    CISA_KEV        — CISA Known Exploited Vulnerabilities catalog
    EPSS            — FIRST EPSS score
    VENDOR_ADVISORY — vendor security advisory (future integration)
    AEGIS_RULE      — deterministic internal rule (e.g., KEV check)
    AI              — AI-generated analysis (always lower trust)
    ANALYST         — human analyst annotation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceSource(StrEnum):
    """The origin of an evidence item."""

    NMAP = "nmap"
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    VENDOR_ADVISORY = "vendor_advisory"
    AEGIS_RULE = "aegis_rule"
    AI = "ai"
    ANALYST = "analyst"


class EvidenceType(StrEnum):
    """
    Classification of how evidence relates to a finding.

    Mirrors the four existing evidence_type values in the findings table
    so the provenance layer stays consistent with the existing system.
    """

    OBSERVED = "observed"  # Directly observed fact (e.g., Nmap output)
    EXTERNAL_INTELLIGENCE = "external_intelligence"  # NVD, KEV, EPSS data
    HYPOTHESIS = "hypothesis"  # Inferred from version match, not confirmed
    RECOMMENDATION = "recommendation"  # Suggested action, not a confirmed finding


@dataclass
class Evidence:
    """
    A single piece of evidence attached to a finding.

    Attributes:
        evidence_id: UUID of this evidence record.
        finding_id: UUID of the finding this evidence supports.
        evidence_type: How this evidence relates to the finding.
        source: Where the evidence came from.
        source_reference: URL, API endpoint, or rule ID.
        collected_at: ISO 8601 timestamp when collected.
        content_hash: SHA-256 of the evidence content (for integrity).
        description: Human-readable summary of what the evidence shows.
        raw_data: The raw evidence payload (may be None for audit efficiency).
    """

    evidence_id: str
    finding_id: str
    evidence_type: EvidenceType
    source: EvidenceSource
    source_reference: str
    collected_at: str
    content_hash: str
    description: str
    raw_data: str | None = None


@dataclass
class EvidenceChain:
    """
    The full evidence chain for a finding — all evidence records together.

    Attributes:
        finding_id: The finding being supported.
        items: All evidence records for this finding.
        strongest_type: The most authoritative evidence type present.
    """

    finding_id: str
    items: list[Evidence] = field(default_factory=list)

    @property
    def strongest_type(self) -> EvidenceType:
        """
        Return the strongest evidence type in the chain.

        Priority: OBSERVED > EXTERNAL_INTELLIGENCE > HYPOTHESIS > RECOMMENDATION
        """
        priority = [
            EvidenceType.OBSERVED,
            EvidenceType.EXTERNAL_INTELLIGENCE,
            EvidenceType.HYPOTHESIS,
            EvidenceType.RECOMMENDATION,
        ]
        types_present = {e.evidence_type for e in self.items}
        for t in priority:
            if t in types_present:
                return t
        return EvidenceType.HYPOTHESIS

    @property
    def sources(self) -> list[str]:
        """Return unique source names in this chain."""
        return sorted({e.source.value for e in self.items})

    def summary(self) -> dict[str, object]:
        """Human-readable summary of the evidence chain."""
        return {
            "finding_id": self.finding_id,
            "evidence_count": len(self.items),
            "strongest_type": self.strongest_type.value,
            "sources": self.sources,
            "items": [
                {
                    "evidence_id": e.evidence_id,
                    "type": e.evidence_type.value,
                    "source": e.source.value,
                    "source_reference": e.source_reference,
                    "collected_at": e.collected_at,
                    "content_hash": e.content_hash,
                    "description": e.description,
                }
                for e in self.items
            ],
        }
