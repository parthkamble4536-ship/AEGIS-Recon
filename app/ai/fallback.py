"""
Deterministic fallback analysis for AEGIS-Recon.

Produces a structured analysis summary WITHOUT any LLM,
using only the scored findings data. This is always available
and serves as:
1. The default when AI is disabled or unavailable.
2. A ground-truth baseline to compare LLM output against.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


def generate_deterministic_analysis(
    findings: list[dict[str, Any]],
    scan_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a structured analysis from findings without any AI.

    Args:
        findings: List of finding dicts from the database.
        scan_context: Scan metadata.

    Returns:
        Analysis dict matching the same schema as AI output.
    """
    if not findings:
        return {
            "summary": (
                f"Scan of {scan_context.get('target', 'unknown')} completed. "
                f"{scan_context.get('service_count', 0)} services discovered. "
                "No CVE matches were found for the detected services."
            ),
            "risk_overview": "No vulnerability findings to assess. This may mean services are up to date, or that version detection was insufficient for CVE matching.",
            "critical_findings": [],
            "recommendations": [
                "Verify that service version detection was successful (check for services with missing versions).",
                "Consider running a more thorough scan profile if version info is missing.",
                "Manually review services for known vulnerabilities not covered by CPE matching.",
            ],
            "confidence_notes": "No findings to assess. Absence of findings does not guarantee security.",
            "limitations": "CVE matching depends on accurate version detection. Services without version information cannot be matched.",
            "analysis_method": "deterministic",
        }

    # Categorize findings
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    [f for f in findings if f.get("severity") == "medium"]
    [f for f in findings if f.get("severity") in ("low", "informational")]
    kev_findings = [f for f in findings if f.get("is_kev")]

    high_confidence = [f for f in findings if f.get("confidence") == "high"]
    hypothesis_only = [f for f in findings if f.get("evidence_type") == "hypothesis"]

    # Build summary
    target = scan_context.get("target", "unknown")
    service_count = scan_context.get("service_count", 0)

    summary_parts = [
        f"Scan of {target} discovered {service_count} services and matched {len(findings)} potential CVEs.",
    ]

    if critical or high:
        summary_parts.append(
            f"{len(critical)} critical and {len(high)} high severity findings identified."
        )
    if kev_findings:
        summary_parts.append(
            f"{len(kev_findings)} finding(s) are in the CISA Known Exploited Vulnerabilities catalog."
        )

    # Build risk overview
    risk_parts = []
    if kev_findings:
        kev_cves = ", ".join(f.get("cve_id", "?") for f in kev_findings[:5])
        risk_parts.append(
            f"HIGHEST PRIORITY: {len(kev_findings)} CVE(s) are actively exploited ({kev_cves}). "
            "These should be addressed immediately."
        )

    if critical:
        crit_cves = ", ".join(f.get("cve_id", "?") for f in critical[:5])
        risk_parts.append(
            f"Critical severity: {len(critical)} finding(s) with CVSS >= 9.0 ({crit_cves})."
        )

    if hypothesis_only:
        risk_parts.append(
            f"Note: {len(hypothesis_only)} of {len(findings)} findings are hypotheses based on version matching. "
            "Manual verification is required before treating them as confirmed vulnerabilities."
        )

    if not risk_parts:
        risk_parts.append(
            "All findings are low or medium severity with no active exploitation signals."
        )

    # Build critical findings list
    critical_finding_descs = []
    for f in sorted(findings, key=lambda x: x.get("priority_score", 0) or 0, reverse=True)[:10]:
        desc = (
            f"{f.get('cve_id', 'Unknown')} — {f.get('severity', '?')} "
            f"(CVSS {f.get('cvss_score', '?')}) on {f.get('service_name', '?')}:{f.get('port', '?')} "
            f"[{f.get('product', '')} {f.get('version', '')}]. "
            f"Confidence: {f.get('confidence', '?')}. Evidence: {f.get('evidence_type', '?')}."
        )
        if f.get("is_kev"):
            desc += " ⚠️ ACTIVELY EXPLOITED (CISA KEV)."
        critical_finding_descs.append(desc)

    # Build recommendations
    recommendations = []
    if kev_findings:
        recommendations.append(
            "URGENT: Patch or mitigate KEV-listed vulnerabilities immediately — "
            + ", ".join(f.get("cve_id", "?") for f in kev_findings[:5])
            + "."
        )
    if critical:
        recommendations.append(
            "Address critical-severity CVEs: "
            + ", ".join(f.get("cve_id", "?") for f in critical[:5])
            + "."
        )
    if high:
        recommendations.append(f"Review and remediate {len(high)} high-severity findings.")
    recommendations.append(
        "Verify all findings manually — automated matching may produce false positives."
    )
    recommendations.append("Consider network segmentation for services with known vulnerabilities.")
    recommendations.append("Update services to latest stable versions where possible.")

    # Confidence notes
    conf_parts = []
    if high_confidence:
        conf_parts.append(
            f"{len(high_confidence)} findings have high confidence (exact CPE or version range match)."
        )
    if hypothesis_only:
        conf_parts.append(
            f"{len(hypothesis_only)} findings are hypotheses and require manual verification. "
            "A version match does not confirm exploitability."
        )
    conf_parts.append(
        "Confidence levels: high = exact CPE/version match, "
        "medium = keyword or partial match, low = broad product match."
    )

    return {
        "summary": " ".join(summary_parts),
        "risk_overview": " ".join(risk_parts),
        "critical_findings": critical_finding_descs,
        "recommendations": recommendations,
        "confidence_notes": " ".join(conf_parts),
        "limitations": (
            "This analysis is based on automated version-to-CVE matching. "
            "It cannot detect: configuration weaknesses, logic flaws, zero-day vulnerabilities, "
            "or compensating controls. Absence of findings does not imply security. "
            "Match accuracy depends on Nmap's version detection capability."
        ),
        "analysis_method": "deterministic",
    }
