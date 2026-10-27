"""
NVD API 2.0 client for AEGIS-Recon.

Queries the NIST National Vulnerability Database for CVE data by:
- CPE match string (primary method)
- Keyword search (fallback)

Design:
- Rate limiting enforced client-side (5 req/30s without key, 50 with key).
- All responses cached via intel_cache table.
- Timeouts and retries with exponential backoff.
- External data is UNTRUSTED — all fields are sanitized before storage.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.errors import IntelUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit window
_last_request_time: float = 0.0
_request_count: int = 0
_window_start: float = 0.0
WINDOW_SECONDS = 30


@dataclass
class NVDVulnerability:
    """Parsed CVE data from the NVD API."""

    cve_id: str
    description: str = ""
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v2_score: float | None = None
    severity: str = "unknown"
    published: str = ""
    modified: str = ""
    references: list[str] = field(default_factory=list)
    cpe_matches: list[dict[str, Any]] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    source_url: str = ""


def _enforce_rate_limit(max_requests: int) -> None:
    """
    Enforce NVD API rate limiting.

    Args:
        max_requests: Max requests per 30-second window.
    """
    global _last_request_time, _request_count, _window_start

    now = time.monotonic()

    # Reset window if expired
    if now - _window_start > WINDOW_SECONDS:
        _window_start = now
        _request_count = 0

    if _request_count >= max_requests:
        sleep_time = WINDOW_SECONDS - (now - _window_start) + 0.5
        if sleep_time > 0:
            logger.info("nvd_rate_limit_wait", sleep_seconds=round(sleep_time, 1))
            time.sleep(sleep_time)
            _window_start = time.monotonic()
            _request_count = 0

    _request_count += 1
    _last_request_time = time.monotonic()


def search_cves_by_cpe(
    cpe_string: str,
    *,
    api_key: str = "",
    rate_limit: int = 5,
    timeout: int = 30,
) -> list[NVDVulnerability]:
    """
    Search NVD for CVEs matching a CPE string.

    Args:
        cpe_string: CPE 2.3 URI (e.g., "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*")
                    or legacy CPE URI (e.g., "cpe:/a:apache:http_server:2.2.8").
        api_key: Optional NVD API key for higher rate limits.
        rate_limit: Max requests per 30-second window.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of NVDVulnerability objects.

    Raises:
        IntelUnavailableError: If the NVD API is unreachable or rate-limited.
    """
    # Normalize legacy CPE to 2.3 format for the API
    cpe_name = _normalize_cpe(cpe_string)

    params: dict[str, str] = {"cpeName": cpe_name}
    headers: dict[str, str] = {}

    if api_key:
        headers["apiKey"] = api_key
        rate_limit = min(rate_limit, 50)

    _enforce_rate_limit(rate_limit)

    return _query_nvd(params, headers, timeout)


def search_cves_by_keyword(
    keyword: str,
    *,
    api_key: str = "",
    rate_limit: int = 5,
    timeout: int = 30,
) -> list[NVDVulnerability]:
    """
    Search NVD for CVEs by keyword (product name + version).

    This is a fallback when CPE-based search isn't possible.

    Args:
        keyword: Search term (e.g., "Apache httpd 2.2.8").
        api_key: Optional NVD API key.
        rate_limit: Max requests per 30-second window.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of NVDVulnerability objects.
    """
    params: dict[str, str] = {"keywordSearch": keyword}
    headers: dict[str, str] = {}

    if api_key:
        headers["apiKey"] = api_key

    _enforce_rate_limit(rate_limit)

    return _query_nvd(params, headers, timeout)


def _query_nvd(
    params: dict[str, str],
    headers: dict[str, str],
    timeout: int,
) -> list[NVDVulnerability]:
    """Execute an NVD API query with retry logic."""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(NVD_BASE_URL, params=params, headers=headers)

            if response.status_code == 200:
                return _parse_nvd_response(response.json())
            elif response.status_code == 403:
                logger.warning("nvd_rate_limited", attempt=attempt + 1)
                if attempt < max_retries - 1:
                    time.sleep(WINDOW_SECONDS + 1)
                    continue
                raise IntelUnavailableError(
                    "NVD API rate limit exceeded.",
                    detail="Wait 30 seconds or add an API key to .env.",
                )
            elif response.status_code == 404:
                return []
            else:
                logger.warning(
                    "nvd_unexpected_status",
                    status=response.status_code,
                    attempt=attempt + 1,
                )
                if attempt < max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise IntelUnavailableError(
                    f"NVD API returned status {response.status_code}.",
                )

        except httpx.TimeoutException:
            logger.warning("nvd_timeout", attempt=attempt + 1)
            if attempt < max_retries - 1:
                time.sleep(2**attempt)
                continue
            raise IntelUnavailableError("NVD API request timed out.")

        except httpx.HTTPError as e:
            logger.warning("nvd_http_error", error=str(e), attempt=attempt + 1)
            if attempt < max_retries - 1:
                time.sleep(2**attempt)
                continue
            raise IntelUnavailableError(f"NVD API connection error: {e}")

    return []


def _parse_nvd_response(data: dict[str, Any]) -> list[NVDVulnerability]:
    """Parse the NVD API JSON response into structured objects."""
    vulnerabilities: list[NVDVulnerability] = []

    if not isinstance(data, dict):
        return vulnerabilities

    for item in data.get("vulnerabilities", []):
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Description (English preferred)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:2000]
                    break

            # CVSS scores
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None
            severity = "unknown"

            metrics = cve_data.get("metrics", {})

            # Try CVSS v3.1 first, then v3.0
            for v3_key in ("cvssMetricV31", "cvssMetricV30"):
                v3_data = metrics.get(v3_key, [])
                if v3_data:
                    primary = v3_data[0].get("cvssData", {})
                    cvss_v3_score = primary.get("baseScore")
                    cvss_v3_vector = primary.get("vectorString", "")
                    severity = primary.get("baseSeverity", "unknown").lower()
                    break

            # CVSS v2 fallback
            v2_data = metrics.get("cvssMetricV2", [])
            if v2_data:
                cvss_v2_score = v2_data[0].get("cvssData", {}).get("baseScore")
                if severity == "unknown" and cvss_v2_score is not None:
                    severity = _cvss_v2_severity(cvss_v2_score)

            # References (limited)
            references = []
            for ref in cve_data.get("references", [])[:10]:
                url = ref.get("url", "")
                if url:
                    references.append(url[:500])

            # CPE match configurations
            cpe_matches = _extract_cpe_matches(cve_data.get("configurations", []))

            # Weaknesses
            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val and val != "NVD-CWE-Other":
                        weaknesses.append(val)

            vuln = NVDVulnerability(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                severity=severity,
                published=cve_data.get("published", ""),
                modified=cve_data.get("lastModified", ""),
                references=references,
                cpe_matches=cpe_matches,
                weaknesses=weaknesses,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
            vulnerabilities.append(vuln)

        except Exception as e:
            logger.warning("nvd_parse_cve_error", error=str(e), cve_id=cve_id)
            continue

    logger.info("nvd_results_parsed", count=len(vulnerabilities))
    return vulnerabilities


def _extract_cpe_matches(configurations: list[dict]) -> list[dict[str, Any]]:
    """Extract CPE match criteria from NVD configurations (for version range checks)."""
    matches: list[dict[str, Any]] = []

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                entry: dict[str, Any] = {
                    "criteria": match.get("criteria", ""),
                    "vulnerable": match.get("vulnerable", False),
                }
                # Version range fields
                for key in (
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ):
                    if key in match:
                        entry[key] = match[key]
                matches.append(entry)

    return matches


def _normalize_cpe(cpe_string: str) -> str:
    """
    Normalize a CPE URI to CPE 2.3 format for the NVD API.

    Converts legacy "cpe:/a:vendor:product:version" to
    "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*".
    """
    if cpe_string.startswith("cpe:2.3:"):
        return cpe_string

    if cpe_string.startswith("cpe:/"):
        parts = cpe_string[5:].split(":")
        # Pad to 11 components
        while len(parts) < 11:
            parts.append("*")
        return "cpe:2.3:" + ":".join(parts[:11])

    return cpe_string


def _cvss_v2_severity(score: float) -> str:
    """Map CVSS v2 score to severity label."""
    if score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    return "low"
