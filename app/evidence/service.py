"""
Evidence service for AEGIS-Recon Phase 6.

Constructs evidence chains from existing finding data and
answers "Why did AEGIS flag this?" for a given finding.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.evidence.models import Evidence, EvidenceChain, EvidenceSource, EvidenceType
from app.evidence.repository import create_evidence, list_evidence_for_finding

logger = get_logger(__name__)


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_content(content: str) -> str:
    """SHA-256 of evidence content (for integrity tracking)."""
    return hashlib.sha256(content.encode()).hexdigest()


def build_evidence_chain(finding_id: str) -> EvidenceChain:
    """
    Build the full evidence chain for a finding from the database.

    Returns an EvidenceChain with all persisted evidence items.
    """
    items = list_evidence_for_finding(finding_id)
    return EvidenceChain(finding_id=finding_id, items=items)


def record_nmap_evidence(
    finding_id: str,
    description: str,
    raw_nmap_output: str = "",
) -> Evidence:
    """
    Record a directly-observed Nmap evidence item for a finding.

    This is OBSERVED evidence — the strongest category.
    Use when the scanner directly saw something (open port, banner, etc.)
    """
    content = f"nmap:{finding_id}:{description}:{raw_nmap_output}"
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType.OBSERVED,
        source=EvidenceSource.NMAP,
        source_reference="nmap-scan",
        collected_at=_now_utc(),
        content_hash=_hash_content(content),
        description=description,
        raw_data=raw_nmap_output or None,
    )
    return create_evidence(evidence)


def record_nvd_evidence(
    finding_id: str,
    cve_id: str,
    description: str,
    nvd_url: str = "",
) -> Evidence:
    """
    Record NVD intelligence evidence for a finding.

    This is EXTERNAL_INTELLIGENCE evidence.
    """
    source_ref = nvd_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    content = f"nvd:{cve_id}:{description}"
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType.EXTERNAL_INTELLIGENCE,
        source=EvidenceSource.NVD,
        source_reference=source_ref,
        collected_at=_now_utc(),
        content_hash=_hash_content(content),
        description=description,
    )
    return create_evidence(evidence)


def record_kev_evidence(
    finding_id: str,
    cve_id: str,
    kev_due_date: str = "",
) -> Evidence:
    """
    Record CISA KEV evidence for a finding.

    This is EXTERNAL_INTELLIGENCE evidence (known exploited in the wild).
    """
    description = (
        f"{cve_id} is listed in the CISA Known Exploited Vulnerabilities catalog."
    )
    if kev_due_date:
        description += f" Remediation due: {kev_due_date}."

    content = f"kev:{cve_id}:{kev_due_date}"
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType.EXTERNAL_INTELLIGENCE,
        source=EvidenceSource.CISA_KEV,
        source_reference="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        collected_at=_now_utc(),
        content_hash=_hash_content(content),
        description=description,
    )
    return create_evidence(evidence)


def record_epss_evidence(
    finding_id: str,
    cve_id: str,
    probability: float,
    percentile: float,
) -> Evidence:
    """
    Record EPSS score evidence for a finding.

    This is EXTERNAL_INTELLIGENCE evidence.
    """
    description = (
        f"{cve_id} has an EPSS probability of {probability:.1%} "
        f"(percentile {percentile:.1f}). Higher probability indicates "
        f"greater likelihood of exploitation in the wild."
    )
    content = f"epss:{cve_id}:{probability}:{percentile}"
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType.EXTERNAL_INTELLIGENCE,
        source=EvidenceSource.EPSS,
        source_reference="https://api.first.org/data/v1/epss",
        collected_at=_now_utc(),
        content_hash=_hash_content(content),
        description=description,
    )
    return create_evidence(evidence)


def record_version_match_hypothesis(
    finding_id: str,
    cve_id: str,
    matched_version: str,
    match_method: str,
) -> Evidence:
    """
    Record a version-match hypothesis evidence item.

    This is always HYPOTHESIS — never OBSERVED.

    CRITICAL: A version match is NEVER a confirmed vulnerability.
    This function enforces that by always using EvidenceType.HYPOTHESIS.
    """
    description = (
        f"Version match hypothesis: {cve_id} may affect version {matched_version!r} "
        f"based on {match_method}. Manual verification required. "
        f"Version presence does not confirm vulnerability."
    )
    content = f"version-match:{cve_id}:{matched_version}:{match_method}"
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType.HYPOTHESIS,  # NEVER change this to OBSERVED
        source=EvidenceSource.AEGIS_RULE,
        source_reference=f"match:{match_method}",
        collected_at=_now_utc(),
        content_hash=_hash_content(content),
        description=description,
    )
    return create_evidence(evidence)


def explain_why_flagged(finding_id: str) -> dict[str, Any]:
    """
    Construct a human-readable explanation for why AEGIS flagged this finding.

    Returns a dict suitable for API response or dashboard display.
    """
    chain = build_evidence_chain(finding_id)
    if not chain.items:
        return {
            "finding_id": finding_id,
            "explanation": "No evidence records found for this finding.",
            "evidence_count": 0,
            "strongest_type": None,
            "sources": [],
            "items": [],
        }

    explanation_parts = []
    for item in chain.items:
        explanation_parts.append(f"[{item.source.value.upper()}] {item.description}")

    explanation = " | ".join(explanation_parts)

    result = chain.summary()
    result["explanation"] = explanation
    return result
