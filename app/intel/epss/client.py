"""
EPSS API client for AEGIS-Recon.

Fetches Exploit Prediction Scoring System (EPSS) scores from the FIRST.org API.
Uses the existing SQLite TTL cache architecture (intel_cache table) to reduce
API calls and enable offline/stale-cache fallback.

API endpoint: https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY

CRITICAL: If EPSS is unavailable → returns None (NOT 0.0).
          Never interpret missing data as low exploit probability.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx

from app.core.logging import get_logger
from app.intel.cache import cache_get, cache_get_stale, cache_set
from app.intel.epss.models import EPSSScore

logger = get_logger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CACHE_TTL_SECONDS = 86400  # 24 hours — EPSS updates daily
EPSS_SOURCE = "FIRST-EPSS"
EPSS_TIMEOUT_SECONDS = 10.0


class EPSSClient:
    """
    Client for retrieving EPSS scores with SQLite TTL caching.

    Cache keys: "epss:{cve_id}" (lowercase CVE ID)
    """

    def __init__(self, cache_ttl: int = EPSS_CACHE_TTL_SECONDS) -> None:
        self.cache_ttl = cache_ttl

    def get_score(self, cve_id: str) -> EPSSScore | None:
        """
        Retrieve the EPSS score for a single CVE.

        Resolution order:
        1. Fresh cache hit   → return cached score
        2. Live API call     → cache result and return
        3. Stale cache hit   → log warning, return stale score
        4. Complete failure  → return None (NOT a score of 0)

        Args:
            cve_id: CVE identifier, e.g. "CVE-2021-44228".

        Returns:
            EPSSScore if data is available (fresh or stale), else None.
            probability/percentile are None when EPSS has no data for this CVE.
        """
        cve_upper = cve_id.upper()
        cache_key = f"epss:{cve_upper.lower()}"

        # 1. Fresh cache hit
        cached = cache_get(cache_key)
        if cached is not None:
            logger.debug("epss_cache_hit", cve_id=cve_upper)
            return self._deserialize(cached)

        # 2. Live API call
        try:
            score = self._fetch_from_api(cve_upper)
            serialized = self._serialize(score)
            cache_set(cache_key, EPSS_SOURCE, serialized, self.cache_ttl)
            return score

        except httpx.TimeoutException:
            logger.warning("epss_api_timeout", cve_id=cve_upper)

        except httpx.HTTPStatusError as exc:
            logger.warning(
                "epss_api_http_error",
                cve_id=cve_upper,
                status_code=exc.response.status_code,
            )

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.error("epss_api_malformed_response", cve_id=cve_upper, error=str(exc))

        except Exception as exc:  # noqa: BLE001
            logger.error("epss_api_unexpected_error", cve_id=cve_upper, error=str(exc))

        # 3. Stale cache fallback
        stale_data, stale_ts = cache_get_stale(cache_key)
        if stale_data:
            logger.warning("epss_using_stale_cache", cve_id=cve_upper, fetched_at=stale_ts)
            return self._deserialize(stale_data)

        # 4. Completely unavailable — return None, NOT 0
        logger.warning("epss_unavailable", cve_id=cve_upper)
        return None

    def _fetch_from_api(self, cve_id: str) -> EPSSScore:
        """
        Fetch EPSS data from the FIRST.org API.

        Raises:
            httpx.TimeoutException: on request timeout.
            httpx.HTTPStatusError: on non-2xx response.
            json.JSONDecodeError: on malformed response body.
            KeyError: if expected response fields are missing.
        """
        with httpx.Client(timeout=EPSS_TIMEOUT_SECONDS) as client:
            response = client.get(EPSS_API_URL, params={"cve": cve_id})
            response.raise_for_status()
            data = response.json()

        now = datetime.now(UTC)
        retrieved_at = now.isoformat()
        expires_at = (now + timedelta(seconds=self.cache_ttl)).isoformat()

        # API response shape: {"status": "OK", "data": [{"cve": "...", "epss": "...", "percentile": "..."}]}
        items: list[dict] = data.get("data", [])

        if not items:
            # CVE exists but EPSS has no score for it
            logger.info("epss_no_score_for_cve", cve_id=cve_id)
            return EPSSScore(
                cve_id=cve_id,
                probability=None,  # not 0 — simply not scored
                percentile=None,
                source=EPSS_SOURCE,
                retrieved_at=retrieved_at,
                expires_at=expires_at,
            )

        item = items[0]
        return EPSSScore(
            cve_id=cve_id,
            probability=float(item["epss"]),
            percentile=float(item["percentile"]),
            source=EPSS_SOURCE,
            retrieved_at=retrieved_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _serialize(score: EPSSScore) -> str:
        """Serialize EPSSScore to JSON string for caching."""
        return json.dumps(
            {
                "cve_id": score.cve_id,
                "probability": score.probability,
                "percentile": score.percentile,
                "source": score.source,
                "retrieved_at": score.retrieved_at,
                "expires_at": score.expires_at,
            }
        )

    @staticmethod
    def _deserialize(data: str) -> EPSSScore:
        """Deserialize cached JSON back to EPSSScore."""
        item = json.loads(data)
        return EPSSScore(
            cve_id=item["cve_id"],
            probability=item.get("probability"),  # None preserved
            percentile=item.get("percentile"),  # None preserved
            source=item.get("source", EPSS_SOURCE),
            retrieved_at=item.get("retrieved_at", ""),
            expires_at=item.get("expires_at", ""),
        )
