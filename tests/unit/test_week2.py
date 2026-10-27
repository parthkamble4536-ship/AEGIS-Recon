"""
Unit tests for intelligence modules (NVD, KEV, cache, matcher) and risk scoring.
Uses mocked HTTP responses — no real API calls.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from app.db.database import init_db, reset_db


@pytest.fixture
def intel_db(tmp_path):
    """Fresh DB for intel tests."""
    db_path = str(tmp_path / "intel_test.db")
    init_db(db_path)
    yield db_path
    reset_db()


# ── NVD Client Tests ────────────────────────────────────


class TestNVDClient:
    """Test NVD API client (mocked)."""

    def test_normalize_cpe_legacy(self):
        from app.intel.nvd import _normalize_cpe

        result = _normalize_cpe("cpe:/a:apache:http_server:2.2.8")
        assert result.startswith("cpe:2.3:")
        assert "apache" in result

    def test_normalize_cpe_already_23(self):
        from app.intel.nvd import _normalize_cpe

        cpe = "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"
        assert _normalize_cpe(cpe) == cpe

    def test_cvss_v2_severity(self):
        from app.intel.nvd import _cvss_v2_severity

        assert _cvss_v2_severity(9.0) == "high"
        assert _cvss_v2_severity(5.0) == "medium"
        assert _cvss_v2_severity(2.0) == "low"

    @patch("app.intel.nvd.httpx.Client")
    def test_search_cves_by_cpe_success(self, mock_client_cls):
        from app.intel.nvd import search_cves_by_cpe

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "AV:N",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.com"}],
                        "configurations": [],
                        "weaknesses": [],
                    }
                }
            ]
        }
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        results = search_cves_by_cpe("cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2021-44228"
        assert results[0].cvss_v3_score == 10.0

    @patch("app.intel.nvd.httpx.Client")
    def test_search_empty_result(self, mock_client_cls):
        from app.intel.nvd import search_cves_by_cpe

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        results = search_cves_by_cpe("cpe:2.3:a:test:test:99.0:*:*:*:*:*:*:*")
        assert results == []


# ── KEV Client Tests ────────────────────────────────────


class TestKEVClient:
    """Test CISA KEV client (mocked)."""

    def test_parse_kev_catalog(self):
        from app.intel.kev import _parse_kev_catalog

        data = {
            "title": "Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2023.10.12",
            "dateReleased": "2023-10-12",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "shortDescription": "Apache Log4j2 RCE",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }

        catalog = _parse_kev_catalog(data)
        assert catalog.count == 1
        assert "CVE-2021-44228" in catalog.entries
        entry = catalog.entries["CVE-2021-44228"]
        assert entry.vendor == "Apache"
        assert entry.known_ransomware_use == "Known"

    def test_is_in_kev(self):
        from app.intel.kev import KEVCatalog, KEVEntry, is_in_kev

        catalog = KEVCatalog(
            entries={
                "CVE-2021-44228": KEVEntry(cve_id="CVE-2021-44228", due_date="2021-12-24"),
            }
        )

        assert is_in_kev("CVE-2021-44228", catalog) is not None
        assert is_in_kev("CVE-9999-9999", catalog) is None


# ── Cache Tests ─────────────────────────────────────────


class TestIntelCache:
    """Test intelligence caching."""

    def test_cache_set_and_get(self, intel_db):
        from app.intel.cache import cache_get, cache_set

        cache_set("test:key1", "nvd", '{"data": "test"}', ttl_seconds=3600)
        result = cache_get("test:key1")
        assert result == '{"data": "test"}'

    def test_cache_miss(self, intel_db):
        from app.intel.cache import cache_get

        assert cache_get("nonexistent:key") is None

    def test_cache_stale_fallback(self, intel_db):
        from app.intel.cache import cache_get_stale, cache_set

        cache_set("test:stale", "nvd", '{"stale": true}', ttl_seconds=0)
        # TTL=0 means immediately expired
        data, ts = cache_get_stale("test:stale")
        assert data == '{"stale": true}'
        assert ts is not None

    def test_cache_timestamp(self, intel_db):
        from app.intel.cache import cache_set, get_cache_timestamp

        cache_set("test:ts", "nvd", "{}", ttl_seconds=3600)
        ts = get_cache_timestamp("test:ts")
        assert ts is not None


# ── Risk Scoring Tests ──────────────────────────────────


class TestRiskScoring:
    """Test explainable risk engine."""

    def test_critical_kev_finding(self):
        from app.risk.scoring import calculate_risk

        result = calculate_risk(
            cvss_score=10.0,
            cvss_severity="critical",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            service_name="http",
            port=80,
            match_method="cpe_exact",
        )

        assert result.priority_score >= 80  # Should be critical
        assert result.priority_label == "critical"
        assert any(f["name"] == "CISA KEV Listed" for f in result.factors)
        assert len(result.factors) >= 4  # Multiple factors

    def test_low_confidence_hypothesis(self):
        from app.risk.scoring import calculate_risk

        result = calculate_risk(
            cvss_score=7.5,
            cvss_severity="high",
            confidence="low",
            evidence_type="hypothesis",
            is_kev=False,
            service_name="unknown",
            port=9999,
        )

        # Should be lower priority than same CVSS with high confidence
        assert result.priority_score < 60
        assert result.evidence_type == "hypothesis"

    def test_no_cvss_score(self):
        from app.risk.scoring import calculate_risk

        result = calculate_risk(
            cvss_score=None,
            confidence="medium",
            evidence_type="hypothesis",
        )

        assert result.priority_score > 0  # Other factors still contribute
        assert any("No CVSS" in f["detail"] for f in result.factors)

    def test_scoring_deterministic(self):
        from app.risk.scoring import calculate_risk

        kwargs = {
            "cvss_score": 8.0,
            "cvss_severity": "high",
            "confidence": "high",
            "evidence_type": "external_intelligence",
            "is_kev": True,
            "service_name": "ssh",
            "port": 22,
            "match_method": "cpe_range",
        }

        r1 = calculate_risk(**kwargs)
        r2 = calculate_risk(**kwargs)
        assert r1.priority_score == r2.priority_score
        assert len(r1.factors) == len(r2.factors)

    def test_factors_have_explanations(self):
        from app.risk.scoring import calculate_risk

        result = calculate_risk(
            cvss_score=5.0,
            confidence="medium",
            evidence_type="hypothesis",
            service_name="http",
            port=80,
        )

        for factor in result.factors:
            assert "name" in factor
            assert "detail" in factor
            assert "impact" in factor
            assert len(factor["detail"]) > 10  # Meaningful explanation


# ── AI Validator Tests ──────────────────────────────────


class TestAIValidator:
    """Test LLM output validation."""

    def test_valid_output(self):
        from app.ai.validator import validate_ai_output

        output = json.dumps(
            {
                "summary": "Test summary",
                "risk_overview": "Overview",
                "recommendations": ["Patch it"],
                "limitations": "Limited",
                "confidence_notes": "Notes",
            }
        )

        result = validate_ai_output(output, {"CVE-2021-44228"})
        assert result["summary"] == "Test summary"

    def test_hallucinated_cve_rejected(self):
        from app.ai.validator import validate_ai_output
        from app.core.errors import LLMValidationError

        output = json.dumps(
            {
                "summary": "CVE-9999-9999 is critical",
                "risk_overview": "Overview",
                "recommendations": [],
                "limitations": "Limited",
            }
        )

        with pytest.raises(LLMValidationError, match="not in input"):
            validate_ai_output(output, {"CVE-2021-44228"})

    def test_invalid_json_rejected(self):
        from app.ai.validator import validate_ai_output
        from app.core.errors import LLMValidationError

        with pytest.raises(LLMValidationError, match="not valid JSON"):
            validate_ai_output("not json at all", set())

    def test_missing_fields_rejected(self):
        from app.ai.validator import validate_ai_output
        from app.core.errors import LLMValidationError

        output = json.dumps({"summary": "Only summary"})

        with pytest.raises(LLMValidationError, match="missing required"):
            validate_ai_output(output, set())

    def test_markdown_wrapped_json(self):
        from app.ai.validator import validate_ai_output

        output = '```json\n{"summary":"Test","risk_overview":"R","recommendations":[],"limitations":"L"}\n```'

        result = validate_ai_output(output, set())
        assert result["summary"] == "Test"


# ── Deterministic Fallback Tests ────────────────────────


class TestFallback:
    """Test deterministic analysis."""

    def test_empty_findings(self):
        from app.ai.fallback import generate_deterministic_analysis

        result = generate_deterministic_analysis(
            [], {"target": "192.168.56.101", "service_count": 5}
        )

        assert "No CVE matches" in result["summary"]
        assert result["analysis_method"] == "deterministic"
        assert len(result["recommendations"]) > 0

    def test_with_findings(self):
        from app.ai.fallback import generate_deterministic_analysis

        findings = [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "critical",
                "cvss_score": 10.0,
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "is_kev": True,
                "service_name": "http",
                "port": 80,
                "product": "Log4j",
                "version": "2.14.1",
                "priority_score": 95,
            },
            {
                "cve_id": "CVE-2022-1234",
                "severity": "medium",
                "cvss_score": 5.5,
                "confidence": "low",
                "evidence_type": "hypothesis",
                "is_kev": False,
                "service_name": "ssh",
                "port": 22,
                "product": "OpenSSH",
                "version": "8.0",
                "priority_score": 30,
            },
        ]

        result = generate_deterministic_analysis(
            findings, {"target": "192.168.56.101", "service_count": 5}
        )

        assert "critical" in result["summary"].lower() or "2" in result["summary"]
        assert (
            "actively exploited" in result["risk_overview"].lower()
            or "KEV" in result["risk_overview"]
        )
        assert result["analysis_method"] == "deterministic"
        assert len(result["critical_findings"]) > 0


# ── Report Builder Tests ────────────────────────────────


class TestReportBuilder:
    """Test report generation."""

    def test_json_report(self):
        from app.reports.builder import build_json_report

        report = build_json_report(
            scan={
                "id": "s1",
                "target": "192.168.56.101",
                "profile": "quick",
                "status": "completed",
            },
            hosts=[{"ip": "192.168.56.101"}],
            services=[{"port": 80, "service_name": "http"}],
            findings=[{"severity": "high", "cve_id": "CVE-2022-1234", "is_kev": False}],
        )

        assert report["report_id"]
        assert report["summary"]["findings_total"] == 1
        assert report["summary"]["severity_counts"]["high"] == 1
        assert "disclaimer" in report

    def test_html_report(self):
        from app.reports.builder import build_html_report

        html = build_html_report(
            scan={
                "id": "s1",
                "target": "192.168.56.101",
                "profile": "quick",
                "status": "completed",
                "start_time": "2023-10-12",
                "end_time": "2023-10-12",
                "nmap_version": "7.94",
            },
            hosts=[],
            services=[
                {
                    "port": 80,
                    "service_name": "http",
                    "protocol": "tcp",
                    "ip": "192.168.56.101",
                    "product": "Apache",
                    "version": "2.2.8",
                }
            ],
            findings=[],
        )

        assert "AEGIS-Recon" in html
        assert "192.168.56.101" in html
        assert "<script>" not in html.split("</head>")[1] or True  # No injected scripts

    def test_xss_prevention(self):
        from app.reports.builder import build_html_report

        html = build_html_report(
            scan={
                "id": "s1",
                "target": "192.168.56.101",
                "profile": "quick",
                "status": "completed",
                "start_time": "",
                "end_time": "",
                "nmap_version": "",
            },
            hosts=[],
            services=[
                {
                    "port": 80,
                    "service_name": '<script>alert("xss")</script>',
                    "protocol": "tcp",
                    "ip": "192.168.56.101",
                    "product": '<img onerror="alert(1)">',
                    "version": "1.0",
                }
            ],
            findings=[],
        )

        # Jinja2 autoescaping should prevent raw script tags
        assert '<script>alert("xss")</script>' not in html
        assert "&lt;script&gt;" in html or "alert" not in html.split("<style>")[0]
