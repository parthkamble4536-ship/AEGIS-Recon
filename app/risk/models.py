"""
Risk policy models for AEGIS-Recon Risk Engine V2.

Defines the configurable weight structure loaded from configs/risk_policy.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskPolicyWeights:
    """
    Configurable weights for each risk factor.

    Each weight is a float ≥ 0. The engine normalises so the
    maximum achievable score is always 100.
    """

    # Intelligence signals
    cvss_weight: float = 40.0        # Max contribution from CVSS (scaled 0-10 → 0-weight)
    kev_bonus: float = 20.0          # Flat bonus when CVE is in CISA KEV
    epss_weight: float = 10.0        # Max contribution from EPSS probability (0-1 → 0-weight)
    exploit_ref_bonus: float = 5.0   # Flat bonus when public exploit reference exists

    # Match quality
    confidence_high: float = 15.0    # Bonus for HIGH match confidence
    confidence_medium: float = 8.0   # Bonus for MEDIUM match confidence
    confidence_low: float = 2.0      # Bonus for LOW match confidence

    # Evidence type
    evidence_observed: float = 10.0
    evidence_external: float = 8.0
    evidence_hypothesis: float = 3.0
    evidence_recommendation: float = 0.0

    # Asset context
    service_exposure_bonus: float = 5.0    # High-value service/port
    asset_criticality_critical: float = 15.0
    asset_criticality_high: float = 10.0
    asset_criticality_medium: float = 5.0
    asset_criticality_low: float = 0.0

    # Environment multiplier (applied after scoring)
    env_production_multiplier: float = 1.0
    env_staging_multiplier: float = 0.9
    env_test_multiplier: float = 0.7
    env_dev_multiplier: float = 0.6
    env_lab_multiplier: float = 0.5

    # Policy metadata
    policy_version: str = "v2.0"
    policy_name: str = "default"


@dataclass
class ScoringFactor:
    """A single factor that contributed to a risk score."""

    name: str
    impact: float
    detail: str
    weight_used: float = 0.0


@dataclass
class RiskAssessmentV2:
    """
    Extended risk assessment with full factor breakdown (Risk Engine V2).

    Backward-compatible extension of the original RiskAssessment.
    The original RiskAssessment from scoring.py is preserved; this adds
    asset context, EPSS, and policy versioning.
    """

    priority_score: float = 0.0
    priority_label: str = "informational"
    cvss_score: float | None = None
    cvss_severity: str = "unknown"
    epss_probability: float | None = None  # None = unavailable, not low risk
    factors: list[ScoringFactor] = field(default_factory=list)
    evidence_type: str = "hypothesis"
    confidence: str = "low"

    # Asset context (new in V2)
    asset_criticality: str = "LOW"
    asset_environment: str = "LAB"
    asset_exposure: str = "UNKNOWN"

    # Reproducibility
    scoring_policy_version: str = "v2.0"
    scoring_policy_name: str = "default"

