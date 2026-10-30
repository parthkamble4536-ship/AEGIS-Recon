"""
Human-readable explanation generator for Risk Engine V2.

Converts a RiskAssessmentV2 into an analyst-friendly explanation of
why the finding was scored the way it was.
"""

from __future__ import annotations

from app.risk.models import RiskAssessmentV2


def explain_assessment(assessment: RiskAssessmentV2) -> str:
    """
    Generate a plain-English explanation of the risk assessment.

    Answers the question: "Why did AEGIS score this finding at X?"

    Returns:
        Multi-line string explaining the priority score and contributing factors.
    """
    lines = [
        f"Priority Score: {assessment.priority_score:.1f}/100 ({assessment.priority_label.upper()})",
        f"Policy: {assessment.scoring_policy_name} ({assessment.scoring_policy_version})",
        "",
        "Contributing Factors:",
    ]

    for factor in assessment.factors:
        sign = "+" if factor.impact >= 0 else ""
        lines.append(f"  {sign}{factor.impact:.1f}  {factor.name}: {factor.detail}")

    lines.append("")
    lines.append("Asset Context:")
    lines.append(f"  Criticality:  {assessment.asset_criticality}")
    lines.append(f"  Environment:  {assessment.asset_environment}")
    lines.append(f"  Exposure:     {assessment.asset_exposure}")

    if assessment.epss_probability is None:
        lines.append("  EPSS:         Unavailable (not interpreted as low risk)")
    else:
        lines.append(
            f"  EPSS:         {assessment.epss_probability:.4f} ({assessment.epss_probability * 100:.1f}% exploitation probability)"
        )

    lines.append("")
    lines.append(
        "NOTE: This score is based on intelligence correlation and asset context. "
        "A score does NOT confirm a vulnerability is exploitable on this specific asset. "
        "Manual verification is required."
    )

    return "\n".join(lines)


def explain_score_difference(score_a: float, score_b: float, context_a: str, context_b: str) -> str:
    """
    Explain why the same CVE scored differently on two assets.

    Args:
        score_a: Priority score on asset A.
        score_b: Priority score on asset B.
        context_a: Description of asset A context.
        context_b: Description of asset B context.

    Returns:
        Human-readable comparison string.
    """
    delta = abs(score_a - score_b)
    higher = "A" if score_a > score_b else "B"
    return (
        f"Asset {higher} scored {delta:.1f} points higher.\n"
        f"Asset A context: {context_a}\n"
        f"Asset B context: {context_b}"
    )
