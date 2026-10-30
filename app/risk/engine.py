"""
Risk Engine V2 for AEGIS-Recon.

Extends the original scoring engine (app/risk/scoring.py) with:
- EPSS integration (unavailable = None, not 0)
- Asset criticality and environment context
- Configurable policy weights (configs/risk_policy.yaml)
- Environment multiplier
- Reproducible scoring_policy_version tracking

The original calculate_risk() in scoring.py is PRESERVED — this engine
wraps and extends it without replacing it.

Every score produced here is:
1. Reproducible (same inputs → same output)
2. Explainable (every factor recorded with impact and detail)
3. Auditable (policy version stored with each assessment)
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.risk.factors import (
    asset_criticality_factor,
    confidence_factor,
    cvss_factor,
    epss_factor,
    evidence_factor,
    exploit_ref_factor,
    kev_factor,
    service_exposure_factor,
)
from app.risk.models import RiskAssessmentV2, RiskPolicyWeights, ScoringFactor
from app.risk.policy import load_policy

logger = get_logger(__name__)

# Module-level policy cache (reload on process restart)
_policy: RiskPolicyWeights | None = None


def get_policy() -> RiskPolicyWeights:
    """Return the current risk policy, loading it on first call."""
    global _policy
    if _policy is None:
        _policy = load_policy()
    return _policy


def calculate_risk_v2(
    *,
    cvss_score: float | None = None,
    cvss_severity: str = "unknown",
    confidence: str = "low",
    evidence_type: str = "hypothesis",
    is_kev: bool = False,
    has_exploit_ref: bool = False,
    epss_probability: float | None = None,  # None = unavailable, NOT 0
    service_name: str = "",
    port: int = 0,
    match_method: str = "",
    asset_criticality: str = "LOW",
    asset_environment: str = "LAB",
    asset_exposure: str = "UNKNOWN",
    policy: RiskPolicyWeights | None = None,
) -> RiskAssessmentV2:
    """
    Calculate an explainable, context-aware priority score for a finding.

    Uses the V2 risk engine with configurable policy weights, EPSS integration,
    and asset context (criticality, environment, exposure).

    CRITICAL: epss_probability=None means EPSS data is UNAVAILABLE.
              It is NOT treated as low exploit probability.

    Args:
        cvss_score:         CVSS v3 or v2 base score (0–10).
        cvss_severity:      CVSS severity label from NVD.
        confidence:         Match confidence (high/medium/low or HIGH/MEDIUM/LOW).
        evidence_type:      Evidence classification (observed/external_intelligence/hypothesis/recommendation).
        is_kev:             CVE in CISA KEV catalog.
        has_exploit_ref:    Public exploit references in NVD data.
        epss_probability:   EPSS probability [0–1] or None if unavailable.
        service_name:       Service name (e.g., "http", "ssh").
        port:               Port number.
        match_method:       How the CVE was correlated.
        asset_criticality:  Asset criticality (LOW/MEDIUM/HIGH/CRITICAL).
        asset_environment:  Asset environment (LAB/DEV/TEST/STAGING/PRODUCTION).
        asset_exposure:     Asset exposure (INTERNAL/EXTERNALLY_EXPOSED/UNKNOWN).
        policy:             Override policy weights (uses loaded policy if None).

    Returns:
        RiskAssessmentV2 with score, label, full factor breakdown, and policy version.
    """
    weights = policy or get_policy()
    factors: list[ScoringFactor] = []
    raw_score = 0.0

    # ── Factor 1: CVSS ────────────────────────────────────────────────────────
    f = cvss_factor(cvss_score, cvss_severity, weights)
    factors.append(f)
    raw_score += f.impact

    # ── Factor 2: KEV ─────────────────────────────────────────────────────────
    f2 = kev_factor(is_kev, weights)
    if f2:
        factors.append(f2)
        raw_score += f2.impact

    # ── Factor 3: EPSS ────────────────────────────────────────────────────────
    f3 = epss_factor(epss_probability, weights)
    factors.append(f3)
    raw_score += f3.impact

    # ── Factor 4: Exploit Reference ───────────────────────────────────────────
    f4 = exploit_ref_factor(has_exploit_ref, weights)
    if f4:
        factors.append(f4)
        raw_score += f4.impact

    # ── Factor 5: Match Confidence ────────────────────────────────────────────
    f5 = confidence_factor(confidence, match_method, weights)
    factors.append(f5)
    raw_score += f5.impact

    # ── Factor 6: Evidence Type ───────────────────────────────────────────────
    f6 = evidence_factor(evidence_type, weights)
    factors.append(f6)
    raw_score += f6.impact

    # ── Factor 7: Service Exposure ────────────────────────────────────────────
    f7 = service_exposure_factor(service_name, port, weights)
    if f7:
        factors.append(f7)
        raw_score += f7.impact

    # ── Factor 8: Asset Criticality ───────────────────────────────────────────
    f8 = asset_criticality_factor(asset_criticality, weights)
    factors.append(f8)
    raw_score += f8.impact

    # ── Environment multiplier ────────────────────────────────────────────────
    env_multipliers = {
        "PRODUCTION": weights.env_production_multiplier,
        "STAGING": weights.env_staging_multiplier,
        "TEST": weights.env_test_multiplier,
        "DEV": weights.env_dev_multiplier,
        "LAB": weights.env_lab_multiplier,
    }
    multiplier = env_multipliers.get(asset_environment.upper(), weights.env_lab_multiplier)

    if multiplier != 1.0:
        pre_mult = raw_score
        raw_score *= multiplier
        factors.append(
            ScoringFactor(
                name="Environment Multiplier",
                impact=round(raw_score - pre_mult, 1),
                detail=(
                    f"Environment: {asset_environment}. Score multiplied by {multiplier:.2f}x."
                ),
                weight_used=multiplier,
            )
        )

    # ── Clamp and classify ────────────────────────────────────────────────────
    final_score = min(max(raw_score, 0.0), 100.0)
    label = _score_to_label(final_score)

    logger.debug(
        "risk_v2_calculated",
        score=round(final_score, 1),
        label=label,
        asset_criticality=asset_criticality,
        asset_environment=asset_environment,
        is_kev=is_kev,
        policy_version=weights.policy_version,
    )

    return RiskAssessmentV2(
        priority_score=round(final_score, 1),
        priority_label=label,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        epss_probability=epss_probability,
        factors=factors,
        evidence_type=evidence_type,
        confidence=confidence,
        asset_criticality=asset_criticality,
        asset_environment=asset_environment,
        asset_exposure=asset_exposure,
        scoring_policy_version=weights.policy_version,
        scoring_policy_name=weights.policy_name,
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
