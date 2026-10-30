"""
Tests for Risk Engine V2 (Phase 4).

Verifies the configurable 8-factor scoring system with asset context,
EPSS integration, environment multiplier, and policy versioning.
"""

from __future__ import annotations

import pytest

from app.risk.engine import calculate_risk_v2
from app.risk.explain import explain_assessment
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

# ─────────────────────────────────────────────────────────────────────────────
# Policy weights fixture
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def default_weights() -> RiskPolicyWeights:
    return RiskPolicyWeights()


# ─────────────────────────────────────────────────────────────────────────────
# Factor unit tests
# ─────────────────────────────────────────────────────────────────────────────


class TestFactors:
    def test_cvss_factor_max(self, default_weights: RiskPolicyWeights) -> None:
        """CVSS 10/10 → maximum CVSS weight."""
        f = cvss_factor(10.0, "CRITICAL", default_weights)
        assert f.impact == pytest.approx(default_weights.cvss_weight)

    def test_cvss_factor_none(self, default_weights: RiskPolicyWeights) -> None:
        """No CVSS → 0 impact."""
        f = cvss_factor(None, "unknown", default_weights)
        assert f.impact == 0.0

    def test_cvss_factor_proportional(self, default_weights: RiskPolicyWeights) -> None:
        """CVSS 5 → half of max CVSS weight."""
        f = cvss_factor(5.0, "MEDIUM", default_weights)
        assert f.impact == pytest.approx(default_weights.cvss_weight / 2, rel=0.01)

    def test_kev_factor_true(self, default_weights: RiskPolicyWeights) -> None:
        """KEV listed → full kev_bonus."""
        f = kev_factor(True, default_weights)
        assert f is not None
        assert f.impact == default_weights.kev_bonus

    def test_kev_factor_false(self, default_weights: RiskPolicyWeights) -> None:
        """Not in KEV → None (no factor added)."""
        f = kev_factor(False, default_weights)
        assert f is None

    def test_epss_factor_available(self, default_weights: RiskPolicyWeights) -> None:
        """EPSS 100% → max epss_weight."""
        f = epss_factor(1.0, default_weights)
        assert f.impact == pytest.approx(default_weights.epss_weight)

    def test_epss_factor_unavailable_records_detail(
        self, default_weights: RiskPolicyWeights
    ) -> None:
        """
        CRITICAL: EPSS unavailable (None) → 0 impact but factor IS recorded.
        The factor is not skipped — analysts must see that EPSS was unavailable.
        """
        f = epss_factor(None, default_weights)
        assert f.impact == 0.0
        assert "unavailable" in f.detail.lower()

    def test_epss_factor_zero_probability(self, default_weights: RiskPolicyWeights) -> None:
        """EPSS 0.0 (extremely unlikely) → 0 impact, but detail says 0%, not unavailable."""
        f = epss_factor(0.0, default_weights)
        assert f.impact == 0.0
        assert "unavailable" not in f.detail.lower()
        assert "0.0%" in f.detail or "0%" in f.detail

    def test_exploit_ref_factor(self, default_weights: RiskPolicyWeights) -> None:
        """Exploit ref present → exploit_ref_bonus."""
        f = exploit_ref_factor(True, default_weights)
        assert f is not None
        assert f.impact == default_weights.exploit_ref_bonus

    def test_exploit_ref_factor_none_when_absent(self, default_weights: RiskPolicyWeights) -> None:
        f = exploit_ref_factor(False, default_weights)
        assert f is None

    def test_confidence_factor_high(self, default_weights: RiskPolicyWeights) -> None:
        f = confidence_factor("high", "cpe_exact", default_weights)
        assert f.impact == default_weights.confidence_high

    def test_confidence_factor_low(self, default_weights: RiskPolicyWeights) -> None:
        f = confidence_factor("low", "product_only", default_weights)
        assert f.impact == default_weights.confidence_low

    def test_evidence_factor_hypothesis_lower_than_external(
        self, default_weights: RiskPolicyWeights
    ) -> None:
        hyp = evidence_factor("hypothesis", default_weights)
        ext = evidence_factor("external_intelligence", default_weights)
        assert hyp.impact < ext.impact

    def test_service_exposure_http(self, default_weights: RiskPolicyWeights) -> None:
        f = service_exposure_factor("http", 80, default_weights)
        assert f is not None
        assert f.impact == default_weights.service_exposure_bonus

    def test_service_exposure_unknown(self, default_weights: RiskPolicyWeights) -> None:
        f = service_exposure_factor("custom-app", 9999, default_weights)
        assert f is None

    def test_asset_criticality_critical(self, default_weights: RiskPolicyWeights) -> None:
        f = asset_criticality_factor("CRITICAL", default_weights)
        assert f.impact == default_weights.asset_criticality_critical

    def test_asset_criticality_low_zero(self, default_weights: RiskPolicyWeights) -> None:
        f = asset_criticality_factor("LOW", default_weights)
        assert f.impact == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Engine integration tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRiskEngineV2:
    def test_kev_critical_production_scores_highest(self) -> None:
        """KEV + CRITICAL asset + PRODUCTION → top-tier score."""
        result = calculate_risk_v2(
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            epss_probability=0.97,
            service_name="ssh",
            port=22,
            asset_criticality="CRITICAL",
            asset_environment="PRODUCTION",
            asset_exposure="EXTERNALLY_EXPOSED",
        )
        assert result.priority_score >= 80
        assert result.priority_label == "critical"

    def test_lab_asset_scores_lower_than_production(self) -> None:
        """Same vulnerability, LAB asset → lower score than PRODUCTION (env multiplier)."""
        base_kwargs = {
            "cvss_score": 8.0,
            "cvss_severity": "HIGH",
            "confidence": "high",
            "evidence_type": "external_intelligence",
            "is_kev": True,
            "asset_criticality": "HIGH",
        }
        prod = calculate_risk_v2(**base_kwargs, asset_environment="PRODUCTION")
        lab = calculate_risk_v2(**base_kwargs, asset_environment="LAB")
        assert prod.priority_score > lab.priority_score

    def test_epss_unavailable_not_same_as_zero(self) -> None:
        """
        CRITICAL: epss=None (unavailable) must NOT produce same score as epss=0.0.
        Actually epss=None contributes 0 points (same as 0.0 EPSS) but the factor
        detail must say 'unavailable' not '0%'.
        """
        result_none = calculate_risk_v2(epss_probability=None)
        result_zero = calculate_risk_v2(epss_probability=0.0)

        # Scores may be equal (both contribute 0 EPSS points) but factor details differ
        epss_factors_none = [f for f in result_none.factors if f.name == "EPSS Score"]
        epss_factors_zero = [f for f in result_zero.factors if f.name == "EPSS Score"]

        assert epss_factors_none, "EPSS factor must always be recorded"
        assert epss_factors_zero, "EPSS factor must always be recorded"
        assert "unavailable" in epss_factors_none[0].detail.lower()
        assert "unavailable" not in epss_factors_zero[0].detail.lower()

    def test_policy_version_recorded(self) -> None:
        """scoring_policy_version must be set in every assessment."""
        result = calculate_risk_v2(cvss_score=5.0, cvss_severity="MEDIUM")
        assert result.scoring_policy_version != ""
        assert result.scoring_policy_name != ""

    def test_score_clamped_to_100(self) -> None:
        """Score never exceeds 100 even with every factor maxed."""
        result = calculate_risk_v2(
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            confidence="high",
            evidence_type="observed",
            is_kev=True,
            has_exploit_ref=True,
            epss_probability=1.0,
            service_name="ssh",
            port=22,
            asset_criticality="CRITICAL",
            asset_environment="PRODUCTION",
        )
        assert result.priority_score <= 100.0

    def test_score_never_negative(self) -> None:
        """Score is always ≥ 0."""
        result = calculate_risk_v2(
            cvss_score=0.0,
            confidence="low",
            evidence_type="recommendation",
            asset_criticality="LOW",
            asset_environment="LAB",
        )
        assert result.priority_score >= 0.0

    def test_factors_always_present(self) -> None:
        """Assessment always has a non-empty factors list."""
        result = calculate_risk_v2()
        assert len(result.factors) >= 3

    def test_asset_context_recorded(self) -> None:
        """Asset context is stored in the assessment."""
        result = calculate_risk_v2(
            asset_criticality="HIGH",
            asset_environment="STAGING",
            asset_exposure="INTERNAL",
        )
        assert result.asset_criticality == "HIGH"
        assert result.asset_environment == "STAGING"
        assert result.asset_exposure == "INTERNAL"

    def test_critical_asset_scores_higher_than_low(self) -> None:
        """Same CVE on CRITICAL asset > LOW asset (all else equal)."""
        critical = calculate_risk_v2(
            cvss_score=7.0, asset_criticality="CRITICAL", asset_environment="PRODUCTION"
        )
        low = calculate_risk_v2(
            cvss_score=7.0, asset_criticality="LOW", asset_environment="PRODUCTION"
        )
        assert critical.priority_score > low.priority_score

    def test_configurable_weights_change_score(self) -> None:
        """Custom policy weights change the score deterministically."""
        default_policy = RiskPolicyWeights()
        boosted_policy = RiskPolicyWeights(kev_bonus=40.0)  # double KEV bonus

        default_result = calculate_risk_v2(cvss_score=5.0, is_kev=True, policy=default_policy)
        boosted_result = calculate_risk_v2(cvss_score=5.0, is_kev=True, policy=boosted_policy)
        assert boosted_result.priority_score > default_result.priority_score

    def test_reproducibility_same_inputs_same_output(self) -> None:
        """Identical inputs must produce identical scores (deterministic)."""
        kwargs = {
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "confidence": "medium",
            "evidence_type": "hypothesis",
            "is_kev": False,
            "epss_probability": 0.15,
            "service_name": "http",
            "port": 80,
            "asset_criticality": "MEDIUM",
            "asset_environment": "STAGING",
        }
        r1 = calculate_risk_v2(**kwargs)
        r2 = calculate_risk_v2(**kwargs)
        assert r1.priority_score == r2.priority_score
        assert r1.priority_label == r2.priority_label


# ─────────────────────────────────────────────────────────────────────────────
# Explain module tests
# ─────────────────────────────────────────────────────────────────────────────


class TestExplain:
    def test_explanation_contains_score(self) -> None:
        """explain_assessment output mentions the priority score."""
        result = calculate_risk_v2(cvss_score=7.0, cvss_severity="HIGH", is_kev=True)
        explanation = explain_assessment(result)
        assert str(result.priority_score) in explanation

    def test_explanation_contains_label(self) -> None:
        """explain_assessment output mentions the priority label."""
        result = calculate_risk_v2(
            cvss_score=9.5,
            cvss_severity="CRITICAL",
            is_kev=True,
            asset_criticality="CRITICAL",
            asset_environment="PRODUCTION",
            epss_probability=0.95,
        )
        explanation = explain_assessment(result)
        assert result.priority_label.upper() in explanation

    def test_explanation_mentions_epss_unavailable(self) -> None:
        """When EPSS is None, explanation says 'Unavailable'."""
        result = calculate_risk_v2(epss_probability=None)
        explanation = explain_assessment(result)
        assert "Unavailable" in explanation or "unavailable" in explanation

    def test_explanation_mentions_policy(self) -> None:
        """Explanation includes policy version."""
        result = calculate_risk_v2()
        explanation = explain_assessment(result)
        assert result.scoring_policy_version in explanation

    def test_explanation_has_asset_section(self) -> None:
        """Explanation includes Asset Context section."""
        result = calculate_risk_v2(asset_criticality="HIGH")
        explanation = explain_assessment(result)
        assert "Asset Context" in explanation


# ─────────────────────────────────────────────────────────────────────────────
# Policy tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRiskPolicy:
    def test_default_policy_loads(self) -> None:
        """Default policy has expected field values."""
        policy = RiskPolicyWeights()
        assert policy.cvss_weight == 40.0
        assert policy.kev_bonus == 20.0
        assert policy.epss_weight == 10.0
        assert policy.policy_version == "v2.0"

    def test_policy_load_missing_file_returns_defaults(self) -> None:
        """Missing YAML file → default weights (no crash)."""
        from pathlib import Path

        from app.risk.policy import load_policy

        policy = load_policy(Path("/nonexistent/path/risk_policy.yaml"))
        assert isinstance(policy, RiskPolicyWeights)
        assert policy.cvss_weight == 40.0

    def test_model_fields_complete(self) -> None:
        """RiskAssessmentV2 has all required spec fields."""
        r = RiskAssessmentV2(
            priority_score=75.0,
            priority_label="high",
            cvss_score=8.5,
            cvss_severity="HIGH",
            epss_probability=0.42,
            factors=[ScoringFactor(name="test", impact=10.0, detail="test")],
            evidence_type="external_intelligence",
            confidence="high",
            asset_criticality="HIGH",
            asset_environment="PRODUCTION",
            asset_exposure="EXTERNALLY_EXPOSED",
            scoring_policy_version="v2.0",
            scoring_policy_name="default",
        )
        assert r.priority_score == 75.0
        assert r.scoring_policy_version == "v2.0"
        assert r.epss_probability == pytest.approx(0.42)
