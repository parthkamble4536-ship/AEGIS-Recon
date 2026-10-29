"""
Tests for EPSS Intelligence (Phase 2).

All tests mock network and cache calls — no real API calls are made.

CRITICAL RULE VERIFIED:
  EPSS unavailable → None, NOT 0.0
  Missing EPSS data is not interpreted as low risk.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.intel.epss.client import EPSSClient
from app.intel.epss.models import EPSSScore

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2021-44228"
CACHE_KEY = "epss:cve-2021-44228"

NOW = datetime.now(UTC)
RETRIEVED_AT = NOW.isoformat()
EXPIRES_AT = (NOW + timedelta(seconds=86400)).isoformat()


def _api_response(cve_id: str = CVE_ID, epss: str = "0.9737", percentile: str = "0.9999") -> dict:
    """Build a mock FIRST.org EPSS API response."""
    return {
        "status": "OK",
        "data": [
            {
                "cve": cve_id,
                "epss": epss,
                "percentile": percentile,
                "date": "2024-01-01",
            }
        ],
    }


def _serialized_score(
    probability: float | None = 0.9737,
    percentile: float | None = 0.9999,
) -> str:
    return json.dumps(
        {
            "cve_id": CVE_ID,
            "probability": probability,
            "percentile": percentile,
            "source": "FIRST-EPSS",
            "retrieved_at": RETRIEVED_AT,
            "expires_at": EXPIRES_AT,
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# Valid response
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSValidResponse:
    def test_valid_response_returns_score(self) -> None:
        """Happy path: API returns valid data → EPSSScore with probability and percentile."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = _api_response()
        mock_resp.raise_for_status.return_value = None

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            client = EPSSClient()
            result = client.get_score(CVE_ID)

        assert result is not None
        assert result.cve_id == CVE_ID
        assert result.probability == pytest.approx(0.9737, rel=1e-3)
        assert result.percentile == pytest.approx(0.9999, rel=1e-3)
        assert result.source == "FIRST-EPSS"
        assert result.retrieved_at != ""
        assert result.expires_at != ""

    def test_valid_response_stores_source_and_timestamps(self) -> None:
        """Result always includes source identifier and freshness timestamps."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = _api_response()
        mock_resp.raise_for_status.return_value = None

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is not None
        assert result.source == "FIRST-EPSS"
        assert result.retrieved_at != ""
        assert result.expires_at != ""
        # expires_at must be after retrieved_at
        assert result.expires_at > result.retrieved_at


# ─────────────────────────────────────────────────────────────────────────────
# Unknown CVE (no score)
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSUnknownCVE:
    def test_unknown_cve_returns_none_probability(self) -> None:
        """CVE not in EPSS database → EPSSScore with None probability (not 0)."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "OK", "data": []}  # empty data
        mock_resp.raise_for_status.return_value = None

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is not None
        assert result.probability is None, "Unknown CVE must have probability=None, not 0"
        assert result.percentile is None

    def test_unknown_cve_not_zero(self) -> None:
        """probability=None must never be 0 for unknown CVE — absence != low risk."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "OK", "data": []}
        mock_resp.raise_for_status.return_value = None

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score("CVE-9999-0001")

        assert result is not None
        assert result.probability != 0, "probability=0 implies low risk; use None for unknown"


# ─────────────────────────────────────────────────────────────────────────────
# API timeout
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSTimeout:
    def test_timeout_returns_none_when_no_cache(self) -> None:
        """API timeout + no stale cache → return None (not 0)."""
        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.TimeoutException("timed out")
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is None

    def test_timeout_falls_back_to_stale_cache(self) -> None:
        """API timeout + stale cache available → return stale data with warning."""
        stale = _serialized_score(probability=0.5, percentile=0.8)

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(stale, RETRIEVED_AT)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.TimeoutException("timed out")
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is not None
        assert result.probability == pytest.approx(0.5)
        assert result.percentile == pytest.approx(0.8)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP error
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSHTTPError:
    def test_http_500_returns_none_when_no_cache(self) -> None:
        """HTTP 500 error + no stale cache → None."""
        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_resp = MagicMock(spec=httpx.Response)
            mock_resp.status_code = 500
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                "500 Internal Server Error", request=MagicMock(), response=mock_resp
            )
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is None

    def test_http_error_uses_stale_cache(self) -> None:
        """HTTP error + stale cache → return stale EPSSScore."""
        stale = _serialized_score(probability=0.3, percentile=0.6)

        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(stale, RETRIEVED_AT)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_resp = MagicMock(spec=httpx.Response)
            mock_resp.status_code = 503
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                "503", request=MagicMock(), response=mock_resp
            )
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is not None
        assert result.probability == pytest.approx(0.3)


# ─────────────────────────────────────────────────────────────────────────────
# Malformed JSON
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSMalformedJSON:
    def test_malformed_json_returns_none(self) -> None:
        """Malformed API JSON response → log error, return None."""
        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.side_effect = json.JSONDecodeError("bad json", "", 0)
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is None

    def test_missing_required_field_returns_none(self) -> None:
        """Response missing required 'epss' field → KeyError handled → None."""
        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            # Missing "epss" key in item
            mock_resp.json.return_value = {
                "status": "OK",
                "data": [{"cve": CVE_ID, "percentile": "0.9"}],
            }
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Cache hit
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSCacheHit:
    def test_cache_hit_returns_without_network_call(self) -> None:
        """Fresh cache hit → return cached score, no HTTP call made."""
        cached = _serialized_score(probability=0.8521, percentile=0.9800)

        with (
            patch("app.intel.epss.client.cache_get", return_value=cached),
            patch("app.intel.epss.client.cache_set") as mock_set,
            patch("httpx.Client") as mock_client_cls,
        ):
            result = EPSSClient().get_score(CVE_ID)

            # No HTTP call
            mock_client_cls.assert_not_called()
            # No cache write
            mock_set.assert_not_called()

        assert result is not None
        assert result.probability == pytest.approx(0.8521)
        assert result.percentile == pytest.approx(0.9800)

    def test_cache_hit_preserves_none_probability(self) -> None:
        """Cached score with probability=None is deserialized correctly (not converted to 0)."""
        cached = _serialized_score(probability=None, percentile=None)

        with (
            patch("app.intel.epss.client.cache_get", return_value=cached),
            patch("httpx.Client") as mock_client_cls,
        ):
            result = EPSSClient().get_score(CVE_ID)
            mock_client_cls.assert_not_called()

        assert result is not None
        assert result.probability is None
        assert result.percentile is None


# ─────────────────────────────────────────────────────────────────────────────
# Cache expiry
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSCacheExpiry:
    def test_expired_cache_triggers_network_call(self) -> None:
        """cache_get returns None (expired) → fresh API call is made."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = _api_response(epss="0.6000", percentile="0.8500")
        mock_resp.raise_for_status.return_value = None

        with (
            # cache_get returns None → expired or missing
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set") as mock_set,
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

            # Network call was made
            mock_client.get.assert_called_once()
            # Result was cached
            mock_set.assert_called_once()

        assert result is not None
        assert result.probability == pytest.approx(0.60, rel=1e-2)


# ─────────────────────────────────────────────────────────────────────────────
# Unavailable EPSS = None (not 0) — the critical safety rule
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSUnavailableIsNone:
    def test_complete_unavailability_returns_none_not_zero(self) -> None:
        """
        CRITICAL: When EPSS is completely unavailable (timeout + no cache),
        the return value must be None, not EPSSScore(probability=0).
        Missing intelligence is NOT the same as low risk.
        """
        with (
            patch("app.intel.epss.client.cache_get", return_value=None),
            patch("app.intel.epss.client.cache_get_stale", return_value=(None, None)),
            patch("app.intel.epss.client.cache_set"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.TimeoutException("down")
            mock_client_cls.return_value.__enter__.return_value = mock_client

            result = EPSSClient().get_score(CVE_ID)

        # Must be None — not EPSSScore(probability=0)
        assert result is None, (
            "EPSS unavailable must return None, not EPSSScore(probability=0). "
            "Absence of EPSS data must not be interpreted as low exploit probability."
        )

    def test_score_probability_zero_is_a_real_score(self) -> None:
        """
        Verify that probability=0.0 is a legitimate score (extremely low exploit
        probability), and is distinct from probability=None (data unavailable).
        """
        score_zero = EPSSScore(cve_id=CVE_ID, probability=0.0, percentile=0.0)
        score_none = EPSSScore(cve_id=CVE_ID, probability=None, percentile=None)

        assert score_zero.probability == 0.0
        assert score_none.probability is None
        # They are meaningfully different
        assert score_zero.probability != score_none.probability


# ─────────────────────────────────────────────────────────────────────────────
# Model tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEPSSModel:
    def test_epss_score_model_fields(self) -> None:
        """EPSSScore has all required fields from the spec."""
        score = EPSSScore(
            cve_id="CVE-2021-44228",
            probability=0.9737,
            percentile=0.9999,
            source="FIRST-EPSS",
            retrieved_at="2024-01-01T00:00:00+00:00",
            expires_at="2024-01-02T00:00:00+00:00",
        )
        assert score.cve_id == "CVE-2021-44228"
        assert score.probability == pytest.approx(0.9737)
        assert score.percentile == pytest.approx(0.9999)
        assert score.source == "FIRST-EPSS"
        assert score.retrieved_at != ""
        assert score.expires_at != ""
