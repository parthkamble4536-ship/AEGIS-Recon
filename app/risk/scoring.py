"""
Explainable risk scoring engine for AEGIS-Recon.

Produces a priority score from 0-100 with a list of contributing factors.
CVSS is always shown separately from the contextual priority score.

Scoring philosophy:
- CVSS is an input, not the output. It measures theoretical severity.
- Priority considers: CVSS, KEV status, confidence, service exposure,
  evidence type, and whether a version match is exact.
- Every factor is listed so the analyst can understand and override.
- No single factor can make a hypothesis look like a confirmed vuln.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskAssessment:
    """Explainable risk assessment for a finding."""

    priority_score: float = 0.0  # 0-100 composite score
    priority_label: str = "informational"  # critical, high, medium, low, informational
    cvss_score: float | None = None  # Shown separately
    cvss_severity: str = "unknown"  # From NVD
    factors: list[dict[str, str | float]] = field(default_factory=list)
    # Each factor: {"name": "...", "impact": +/-N, "detail": "..."}
    evidence_type: str = "hypothesis"
    confidence: str = "low"


def calculate_risk(
    *,
    cvss_score: float | None = None,
    cvss_severity: str = "unknown",
    confidence: str = "low",
    evidence_type: str = "hypothesis",
    is_kev: bool = False,
    has_exploit_ref: bool = False,
    service_name: str = "",
    port: int = 0,
    match_method: str = "",
) -> RiskAssessment:
    """
    Calculate an explainable priority score for a finding.

    The score is NOT just CVSS. It integrates:
    - Base CVSS score (weighted, not dominant)
    - Intelligence signals (KEV, exploit references)
    - Match quality (confidence, evidence type, match method)
    - Service context (internet-facing common ports)

    Args:
        cvss_score: CVSS v3 or v2 base score (0-10).
        cvss_severity: CVSS severity label.
        confidence: Match confidence (high, medium, low).
        evidence_type: Evidence classification.
        is_kev: Whether the CVE is in CISA KEV.
        has_exploit_ref: Whether exploit references exist.
        service_name: Service name (e.g., "http", "ssh").
        port: Port number.
        match_method: How the CVE was matched.

    Returns:
        RiskAssessment with score, label, and factor breakdown.
    """
    score = 0.0
    factors: list[dict[str, str | float]] = []

    # ── Factor 1: CVSS Base Score (0-40 points) ─────────
    if cvss_score is not None:
        cvss_contribution = min(cvss_score * 4, 40.0)
        score += cvss_contribution
        factors.append({
            "name": "CVSS Base Score",
            "impact": round(cvss_contribution, 1),
            "detail": f"CVSS {cvss_score}/10 ({cvss_severity}) contributes up to 40% of priority.",
        })
    else:
        factors.append({
            "name": "CVSS Base Score",
            "impact": 0,
            "detail": "No CVSS score available. Score based on other factors only.",
        })

    # ── Factor 2: KEV Status (+20 points) ────────────────
    if is_kev:
        score += 20.0
        factors.append({
            "name": "CISA KEV Listed",
            "impact": 20.0,
            "detail": "CVE is in CISA Known Exploited Vulnerabilities catalog — confirmed actively exploited.",
        })

    # ── Factor 3: Confidence Level ───────────────────────
    confidence_scores = {"high": 15.0, "medium": 8.0, "low": 2.0}
    conf_points = confidence_scores.get(confidence, 2.0)
    score += conf_points
    factors.append({
        "name": "Match Confidence",
        "impact": conf_points,
        "detail": f"Confidence: {confidence}. Method: {match_method or 'unknown'}.",
    })

    # ── Factor 4: Evidence Type ──────────────────────────
    evidence_scores = {
        "observed": 10.0,
        "external_intelligence": 8.0,
        "hypothesis": 3.0,
        "recommendation": 0.0,
    }
    ev_points = evidence_scores.get(evidence_type, 3.0)
    score += ev_points
    factors.append({
        "name": "Evidence Type",
        "impact": ev_points,
        "detail": f"Evidence: {evidence_type}. "
        + _evidence_explanation(evidence_type),
    })

    # ── Factor 5: Exploit References (+5 points) ─────────
    if has_exploit_ref:
        score += 5.0
        factors.append({
            "name": "Exploit Reference",
            "impact": 5.0,
            "detail": "Public exploit references found in NVD data.",
        })

    # ── Factor 6: Service Exposure (+5 points) ───────────
    high_value_services = {"http", "https", "ssh", "ftp", "smb", "rdp", "telnet", "mysql", "postgresql", "mssql"}
    high_value_ports = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443}

    if service_name.lower() in high_value_services or port in high_value_ports:
        score += 5.0
        factors.append({
            "name": "Service Exposure",
            "impact": 5.0,
            "detail": f"Service {service_name}:{port} is commonly targeted.",
        })

    # ── Clamp and classify ───────────────────────────────
    score = min(max(score, 0.0), 100.0)
    label = _score_to_label(score)

    return RiskAssessment(
        priority_score=round(score, 1),
        priority_label=label,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        factors=factors,
        evidence_type=evidence_type,
        confidence=confidence,
    )


def _score_to_label(score: float) -> str:
    """Convert numeric priority score to a label."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    return "informational"


def _evidence_explanation(evidence_type: str) -> str:
    """Provide a plain-English explanation of the evidence type."""
    explanations = {
        "observed": "Directly observed in scan output (e.g., open port, banner, script result).",
        "external_intelligence": "Correlated from an authoritative external source (NVD, CISA KEV).",
        "hypothesis": "Inferred from version or product match — NOT confirmed. Manual verification required.",
        "recommendation": "Suggested action, not a finding. No exploitability assessed.",
    }
    return explanations.get(evidence_type, "Unknown evidence type.")
