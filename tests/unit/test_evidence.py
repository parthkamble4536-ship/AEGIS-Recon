"""
Tests for Phase 6 — Evidence and Provenance Engine.

Tests:
- EvidenceSource / EvidenceType enum values
- Evidence dataclass construction
- EvidenceChain.strongest_type priority
- EvidenceChain.sources deduplication
- EvidenceChain.summary()
- record_nmap_evidence() creates OBSERVED evidence
- record_nvd_evidence() creates EXTERNAL_INTELLIGENCE
- record_kev_evidence() creates EXTERNAL_INTELLIGENCE
- record_epss_evidence() creates EXTERNAL_INTELLIGENCE with probability text
- record_version_match_hypothesis() ALWAYS creates HYPOTHESIS (never OBSERVED)
- explain_why_flagged() with no evidence
- explain_why_flagged() with evidence items
- API: GET /api/findings/{id}/evidence (empty)
- API: POST /api/findings/{id}/evidence (valid)
- API: POST /api/findings/{id}/evidence (invalid type)
- API: POST /api/findings/{id}/evidence (invalid source)
- API: GET /api/findings/{id}/why (no evidence)
- API: GET /api/findings/{id}/why (with evidence)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.evidence.models import (
    Evidence,
    EvidenceChain,
    EvidenceSource,
    EvidenceType,
)

# ── Model Tests ───────────────────────────────────────────────────────────────


class TestEvidenceModels:
    def test_evidence_source_values(self):
        assert EvidenceSource.NMAP == "nmap"
        assert EvidenceSource.NVD == "nvd"
        assert EvidenceSource.CISA_KEV == "cisa_kev"
        assert EvidenceSource.EPSS == "epss"
        assert EvidenceSource.AI == "ai"
        assert EvidenceSource.ANALYST == "analyst"

    def test_evidence_type_values(self):
        assert EvidenceType.OBSERVED == "observed"
        assert EvidenceType.EXTERNAL_INTELLIGENCE == "external_intelligence"
        assert EvidenceType.HYPOTHESIS == "hypothesis"
        assert EvidenceType.RECOMMENDATION == "recommendation"

    def test_evidence_construction(self):
        e = Evidence(
            evidence_id="e1",
            finding_id="f1",
            evidence_type=EvidenceType.OBSERVED,
            source=EvidenceSource.NMAP,
            source_reference="nmap-scan",
            collected_at="2024-01-01T00:00:00Z",
            content_hash="abc123",
            description="Open port 22/tcp observed.",
        )
        assert e.evidence_id == "e1"
        assert e.finding_id == "f1"
        assert e.raw_data is None

    def test_evidence_chain_strongest_type_observed_wins(self):
        """OBSERVED beats all others."""
        chain = EvidenceChain(
            finding_id="f1",
            items=[
                Evidence(
                    "e1",
                    "f1",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "Hypothesis",
                ),
                Evidence(
                    "e2",
                    "f1",
                    EvidenceType.OBSERVED,
                    EvidenceSource.NMAP,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "Observed",
                ),
            ],
        )
        assert chain.strongest_type == EvidenceType.OBSERVED

    def test_evidence_chain_strongest_type_external_beats_hypothesis(self):
        chain = EvidenceChain(
            finding_id="f1",
            items=[
                Evidence(
                    "e1",
                    "f1",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "Version match",
                ),
                Evidence(
                    "e2",
                    "f1",
                    EvidenceType.EXTERNAL_INTELLIGENCE,
                    EvidenceSource.NVD,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "NVD record",
                ),
            ],
        )
        assert chain.strongest_type == EvidenceType.EXTERNAL_INTELLIGENCE

    def test_evidence_chain_strongest_type_hypothesis_default(self):
        """When only HYPOTHESIS exists, returns HYPOTHESIS."""
        chain = EvidenceChain(
            finding_id="f1",
            items=[
                Evidence(
                    "e1",
                    "f1",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "Match",
                ),
            ],
        )
        assert chain.strongest_type == EvidenceType.HYPOTHESIS

    def test_evidence_chain_strongest_type_empty_chain(self):
        """Empty chain defaults to HYPOTHESIS."""
        chain = EvidenceChain(finding_id="f1")
        assert chain.strongest_type == EvidenceType.HYPOTHESIS

    def test_evidence_chain_sources(self):
        chain = EvidenceChain(
            finding_id="f1",
            items=[
                Evidence(
                    "e1",
                    "f1",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "",
                ),
                Evidence(
                    "e2",
                    "f1",
                    EvidenceType.EXTERNAL_INTELLIGENCE,
                    EvidenceSource.NVD,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "",
                ),
                Evidence(
                    "e3",
                    "f1",
                    EvidenceType.EXTERNAL_INTELLIGENCE,
                    EvidenceSource.NVD,
                    "",
                    "2024-01-01T00:00:00Z",
                    "",
                    "",
                ),  # duplicate source
            ],
        )
        assert chain.sources == ["aegis_rule", "nvd"]  # sorted, deduplicated

    def test_evidence_chain_summary_structure(self):
        chain = EvidenceChain(
            finding_id="f1",
            items=[
                Evidence(
                    "e1",
                    "f1",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "rule:version-match",
                    "2024-01-01T00:00:00Z",
                    "abc",
                    "Version matched",
                ),
            ],
        )
        s = chain.summary()
        assert s["finding_id"] == "f1"
        assert s["evidence_count"] == 1
        assert s["strongest_type"] == "hypothesis"
        assert "aegis_rule" in s["sources"]
        assert len(s["items"]) == 1
        assert s["items"][0]["evidence_id"] == "e1"


# ── Service Tests (mocked repository) ────────────────────────────────────────


class TestEvidenceService:
    @patch("app.evidence.service.create_evidence")
    def test_record_nmap_evidence_is_observed(self, mock_create):
        """Nmap evidence must be OBSERVED type."""
        mock_create.side_effect = lambda e: e  # return as-is

        from app.evidence.service import record_nmap_evidence

        record_nmap_evidence("f1", "Port 22/tcp open - ssh detected")

        assert mock_create.called
        call_arg = mock_create.call_args[0][0]
        assert call_arg.evidence_type == EvidenceType.OBSERVED
        assert call_arg.source == EvidenceSource.NMAP
        assert call_arg.finding_id == "f1"

    @patch("app.evidence.service.create_evidence")
    def test_record_nvd_evidence_is_external_intel(self, mock_create):
        """NVD evidence must be EXTERNAL_INTELLIGENCE."""
        mock_create.side_effect = lambda e: e

        from app.evidence.service import record_nvd_evidence

        record_nvd_evidence("f1", "CVE-2021-44228", "Log4Shell RCE")

        call_arg = mock_create.call_args[0][0]
        assert call_arg.evidence_type == EvidenceType.EXTERNAL_INTELLIGENCE
        assert call_arg.source == EvidenceSource.NVD

    @patch("app.evidence.service.create_evidence")
    def test_record_kev_evidence_is_external_intel(self, mock_create):
        """KEV evidence must be EXTERNAL_INTELLIGENCE."""
        mock_create.side_effect = lambda e: e

        from app.evidence.service import record_kev_evidence

        record_kev_evidence("f1", "CVE-2021-44228", "2024-01-15")

        call_arg = mock_create.call_args[0][0]
        assert call_arg.evidence_type == EvidenceType.EXTERNAL_INTELLIGENCE
        assert call_arg.source == EvidenceSource.CISA_KEV
        assert "2024-01-15" in call_arg.description

    @patch("app.evidence.service.create_evidence")
    def test_record_epss_evidence_includes_probability(self, mock_create):
        """EPSS evidence must include probability in description."""
        mock_create.side_effect = lambda e: e

        from app.evidence.service import record_epss_evidence

        record_epss_evidence("f1", "CVE-2021-44228", probability=0.975, percentile=99.5)

        call_arg = mock_create.call_args[0][0]
        assert call_arg.source == EvidenceSource.EPSS
        assert "97.5%" in call_arg.description

    @patch("app.evidence.service.create_evidence")
    def test_version_match_is_always_hypothesis(self, mock_create):
        """
        CRITICAL: version match MUST always be HYPOTHESIS, never OBSERVED.
        A version presence does not confirm a vulnerability.
        """
        mock_create.side_effect = lambda e: e

        from app.evidence.service import record_version_match_hypothesis

        record_version_match_hypothesis("f1", "CVE-2021-44228", "7.2p2", "cpe-version-range")

        call_arg = mock_create.call_args[0][0]
        assert call_arg.evidence_type == EvidenceType.HYPOTHESIS, (
            "Version match must NEVER be OBSERVED evidence!"
        )
        assert "Manual verification required" in call_arg.description

    @patch("app.evidence.service.list_evidence_for_finding")
    def test_explain_why_flagged_no_evidence(self, mock_list):
        """explain_why_flagged returns no-evidence message when list is empty."""
        mock_list.return_value = []

        from app.evidence.service import explain_why_flagged

        result = explain_why_flagged("f1")

        assert result["evidence_count"] == 0
        assert "No evidence records" in result["explanation"]

    @patch("app.evidence.service.list_evidence_for_finding")
    def test_explain_why_flagged_with_items(self, mock_list):
        """explain_why_flagged returns explanation from evidence items."""
        mock_list.return_value = [
            Evidence(
                "e1",
                "f1",
                EvidenceType.EXTERNAL_INTELLIGENCE,
                EvidenceSource.NVD,
                "https://nvd.nist.gov/",
                "2024-01-01T00:00:00Z",
                "abc",
                "CVE-2021-44228 affects log4j < 2.15.0",
            ),
            Evidence(
                "e2",
                "f1",
                EvidenceType.HYPOTHESIS,
                EvidenceSource.AEGIS_RULE,
                "match:cpe-range",
                "2024-01-01T00:00:00Z",
                "def",
                "Version 2.14.1 matched vulnerable range",
            ),
        ]

        from app.evidence.service import explain_why_flagged

        result = explain_why_flagged("f1")

        assert result["evidence_count"] == 2
        assert "NVD" in result["explanation"]
        assert "AEGIS_RULE" in result["explanation"]
        assert result["strongest_type"] == "external_intelligence"


# ── API Tests ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    from app.main import create_app

    app = create_app()
    return TestClient(app)


class TestEvidenceAPI:
    @patch("app.api.evidence.list_evidence_for_finding")
    def test_get_evidence_empty(self, mock_list, client):
        """GET /api/findings/{id}/evidence returns empty list."""
        mock_list.return_value = []
        resp = client.get("/api/findings/f1/evidence")
        assert resp.status_code == 200
        assert resp.json() == []

    @patch("app.api.evidence.list_evidence_for_finding")
    def test_get_evidence_with_items(self, mock_list, client):
        """GET /api/findings/{id}/evidence returns serialized evidence."""
        mock_list.return_value = [
            Evidence(
                "e1",
                "f1",
                EvidenceType.OBSERVED,
                EvidenceSource.NMAP,
                "nmap-scan",
                "2024-01-01T00:00:00Z",
                "abc123",
                "Port 22 open",
            ),
        ]
        resp = client.get("/api/findings/f1/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["source"] == "nmap"
        assert data[0]["evidence_type"] == "observed"

    def test_post_evidence_invalid_type(self, client):
        """POST evidence with invalid evidence_type → 422."""
        resp = client.post(
            "/api/findings/f1/evidence",
            json={"evidence_type": "definitely_invalid", "description": "test"},
        )
        assert resp.status_code == 422

    def test_post_evidence_invalid_source(self, client):
        """POST evidence with invalid source → 422."""
        resp = client.post(
            "/api/findings/f1/evidence",
            json={"evidence_type": "observed", "source": "invalid_source", "description": "test"},
        )
        assert resp.status_code == 422

    @patch("app.api.evidence.create_evidence")
    def test_post_evidence_success(self, mock_create, client):
        """POST evidence with valid data → 201."""
        mock_create.side_effect = lambda e: e

        resp = client.post(
            "/api/findings/f1/evidence",
            json={
                "evidence_type": "hypothesis",
                "source": "analyst",
                "description": "Manually verified on test system",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["source"] == "analyst"
        assert data["finding_id"] == "f1"

    @patch("app.api.evidence.explain_why_flagged")
    def test_get_why_no_evidence(self, mock_explain, client):
        """GET /api/findings/{id}/why returns explanation."""
        mock_explain.return_value = {
            "finding_id": "f1",
            "explanation": "No evidence records found.",
            "evidence_count": 0,
            "strongest_type": None,
            "sources": [],
            "items": [],
        }
        resp = client.get("/api/findings/f1/why")
        assert resp.status_code == 200
        assert "explanation" in resp.json()

    @patch("app.api.evidence.explain_why_flagged")
    def test_get_why_with_evidence(self, mock_explain, client):
        """GET /api/findings/{id}/why returns structured explanation."""
        mock_explain.return_value = {
            "finding_id": "f1",
            "explanation": "[NVD] CVE matched | [AEGIS_RULE] Version in range",
            "evidence_count": 2,
            "strongest_type": "external_intelligence",
            "sources": ["aegis_rule", "nvd"],
            "items": [],
        }
        resp = client.get("/api/findings/f1/why")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_count"] == 2
        assert data["strongest_type"] == "external_intelligence"
