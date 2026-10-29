"""
Individual risk factor calculators for AEGIS-Recon Risk Engine V2.

Each function takes relevant inputs and returns a ScoringFactor.
Factors are composable — the engine picks which to apply.
"""

from __future__ import annotations

from app.risk.models import RiskPolicyWeights, ScoringFactor


def cvss_factor(
    cvss_score: float | None,
    cvss_severity: str,
    weights: RiskPolicyWeights,
) -> ScoringFactor:
    """CVSS base score contribution (scaled 0-10 → 0-weight)."""
    if cvss_score is None:
        return ScoringFactor(
            name="CVSS Base Score",
            impact=0.0,
            detail="No CVSS score available. Score based on other factors only.",
            weight_used=weights.cvss_weight,
        )
    contribution = min((cvss_score / 10.0) * weights.cvss_weight, weights.cvss_weight)
    return ScoringFactor(
        name="CVSS Base Score",
        impact=round(contribution, 1),
        detail=f"CVSS {cvss_score}/10 ({cvss_severity}) scaled to {contribution:.1f} points.",
        weight_used=weights.cvss_weight,
    )


def kev_factor(is_kev: bool, weights: RiskPolicyWeights) -> ScoringFactor | None:
    """CISA KEV listing bonus. Returns None if not in KEV."""
    if not is_kev:
        return None
    return ScoringFactor(
        name="CISA KEV Listed",
        impact=weights.kev_bonus,
        detail="CVE is in CISA Known Exploited Vulnerabilities — confirmed actively exploited.",
        weight_used=weights.kev_bonus,
    )


def epss_factor(
    epss_probability: float | None,
    weights: RiskPolicyWeights,
) -> ScoringFactor:
    """
    EPSS probability contribution.

    CRITICAL: epss_probability=None means UNAVAILABLE, not low risk.
    When unavailable, 0 points are added but the factor is recorded.
    """
    if epss_probability is None:
        return ScoringFactor(
            name="EPSS Score",
            impact=0.0,
            detail="EPSS data unavailable — not interpreted as low risk.",
            weight_used=weights.epss_weight,
        )
    contribution = min(epss_probability * weights.epss_weight, weights.epss_weight)
    return ScoringFactor(
        name="EPSS Score",
        impact=round(contribution, 1),
        detail=(
            f"EPSS probability {epss_probability:.4f} "
            f"(~{epss_probability*100:.1f}% chance of exploitation within 30 days)."
        ),
        weight_used=weights.epss_weight,
    )


def exploit_ref_factor(
    has_exploit_ref: bool, weights: RiskPolicyWeights
) -> ScoringFactor | None:
    """Public exploit reference bonus."""
    if not has_exploit_ref:
        return None
    return ScoringFactor(
        name="Exploit Reference",
        impact=weights.exploit_ref_bonus,
        detail="Public exploit references found in NVD data.",
        weight_used=weights.exploit_ref_bonus,
    )


def confidence_factor(confidence: str, match_method: str, weights: RiskPolicyWeights) -> ScoringFactor:
    """Match confidence contribution."""
    conf_map = {
        "high": ("HIGH", weights.confidence_high),
        "HIGH": ("HIGH", weights.confidence_high),
        "medium": ("MEDIUM", weights.confidence_medium),
        "MEDIUM": ("MEDIUM", weights.confidence_medium),
        "low": ("LOW", weights.confidence_low),
        "LOW": ("LOW", weights.confidence_low),
    }
    label, points = conf_map.get(confidence, ("LOW", weights.confidence_low))
    return ScoringFactor(
        name="Match Confidence",
        impact=points,
        detail=f"Confidence: {label}. Method: {match_method or 'unknown'}.",
        weight_used=max(weights.confidence_high, weights.confidence_medium, weights.confidence_low),
    )


def evidence_factor(evidence_type: str, weights: RiskPolicyWeights) -> ScoringFactor:
    """Evidence type contribution."""
    ev_map = {
        "observed": weights.evidence_observed,
        "external_intelligence": weights.evidence_external,
        "hypothesis": weights.evidence_hypothesis,
        "recommendation": weights.evidence_recommendation,
    }
    points = ev_map.get(evidence_type, weights.evidence_hypothesis)
    explanations = {
        "observed": "Directly observed in scan output.",
        "external_intelligence": "Correlated from authoritative external source (NVD/CISA KEV).",
        "hypothesis": "Inferred from version/product match — NOT confirmed. Verify manually.",
        "recommendation": "Suggested action — not a finding.",
    }
    return ScoringFactor(
        name="Evidence Type",
        impact=points,
        detail=f"Evidence: {evidence_type}. {explanations.get(evidence_type, '')}",
        weight_used=weights.evidence_observed,
    )


def service_exposure_factor(
    service_name: str,
    port: int,
    weights: RiskPolicyWeights,
) -> ScoringFactor | None:
    """Bonus for commonly targeted services/ports."""
    high_value_services = {
        "http", "https", "ssh", "ftp", "smb", "rdp",
        "telnet", "mysql", "postgresql", "mssql",
    }
    high_value_ports = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443}

    if service_name.lower() in high_value_services or port in high_value_ports:
        return ScoringFactor(
            name="Service Exposure",
            impact=weights.service_exposure_bonus,
            detail=f"Service {service_name}:{port} is commonly targeted.",
            weight_used=weights.service_exposure_bonus,
        )
    return None


def asset_criticality_factor(
    criticality: str,
    weights: RiskPolicyWeights,
) -> ScoringFactor:
    """Asset criticality bonus."""
    crit_map = {
        "CRITICAL": weights.asset_criticality_critical,
        "HIGH": weights.asset_criticality_high,
        "MEDIUM": weights.asset_criticality_medium,
        "LOW": weights.asset_criticality_low,
    }
    points = crit_map.get(criticality.upper(), 0.0)
    return ScoringFactor(
        name="Asset Criticality",
        impact=points,
        detail=(
            f"Asset criticality: {criticality}. "
            f"{'Business-critical asset — higher priority.' if points > 0 else 'Low criticality asset.'}"
        ),
        weight_used=weights.asset_criticality_critical,
    )

