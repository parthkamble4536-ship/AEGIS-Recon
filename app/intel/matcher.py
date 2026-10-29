"""
CVE matcher for AEGIS-Recon.

Matches discovered services against CVE data from the NVD,
assigning confidence levels based on match quality.

Match strategies (in order of confidence):
1. Exact CPE match → high confidence
2. CPE with version range check → medium-high confidence
3. Product + version keyword match → medium confidence
4. Product-only match (no version) → low confidence

A match is NEVER a confirmed vulnerability. Every match carries
an explicit confidence level and evidence type.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.errors import IntelUnavailableError
from app.core.logging import get_logger
from app.intel.cache import cache_get, cache_get_stale, cache_set, get_cache_timestamp
from app.intel.kev import KEVCatalog, is_in_kev
from app.intel.nvd import (
    NVDVulnerability,
    search_cves_by_cpe,
    search_cves_by_keyword,
)

logger = get_logger(__name__)


@dataclass
class CVEMatch:
    """A matched CVE with confidence metadata."""

    cve_id: str
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "unknown"
    confidence: str = "low"  # high, medium, low
    evidence_type: str = "hypothesis"  # external_intelligence or hypothesis
    evidence_detail: str = ""
    match_method: str = ""  # cpe_exact, cpe_range, keyword, product_only
    source: str = "NVD"
    source_url: str = ""
    references: list[str] = field(default_factory=list)
    is_kev: bool = False
    kev_due_date: str = ""
    kev_detail: str = ""
    intel_timestamp: str = ""


def match_service_cves(
    product: str,
    version: str,
    cpe_list: list[str],
    *,
    api_key: str = "",
    rate_limit: int = 5,
    nvd_cache_ttl: int = 86400,
    kev_catalog: KEVCatalog | None = None,
) -> list[CVEMatch]:
    """
    Find CVEs matching a discovered service.

    Tries CPE-based matching first (higher confidence), then
    falls back to keyword search.

    Args:
        product: Service product name (e.g., "Apache httpd").
        version: Service version (e.g., "2.2.8").
        cpe_list: CPE URIs from Nmap (e.g., ["cpe:/a:apache:http_server:2.2.8"]).
        api_key: Optional NVD API key.
        rate_limit: NVD rate limit.
        nvd_cache_ttl: Cache TTL in seconds.
        kev_catalog: Optional loaded KEV catalog for enrichment.

    Returns:
        List of CVEMatch objects, sorted by CVSS score (highest first).
    """
    matches: dict[str, CVEMatch] = {}  # Deduplicate by CVE ID

    # Strategy 1: CPE-based search (highest confidence)
    for cpe in cpe_list:
        cpe_matches = _search_by_cpe(
            cpe,
            product,
            version,
            api_key=api_key,
            rate_limit=rate_limit,
            cache_ttl=nvd_cache_ttl,
        )
        for m in cpe_matches:
            if m.cve_id not in matches or _confidence_rank(m.confidence) > _confidence_rank(
                matches[m.cve_id].confidence
            ):
                matches[m.cve_id] = m

    # Strategy 2: Keyword fallback (only if no CPE results and we have product+version)
    if not matches and product and version:
        try:
            keyword_matches = _search_by_keyword(
                product,
                version,
                api_key=api_key,
                rate_limit=rate_limit,
                cache_ttl=nvd_cache_ttl,
            )
        except IntelUnavailableError:
            logger.warning("keyword_search_unavailable", product=product, version=version)
            keyword_matches = []
        for m in keyword_matches:
            if m.cve_id not in matches:
                matches[m.cve_id] = m

    # Enrich with KEV data
    if kev_catalog:
        for cve_id, match in matches.items():
            kev_entry = is_in_kev(cve_id, kev_catalog)
            if kev_entry:
                match.is_kev = True
                match.kev_due_date = kev_entry.due_date
                match.kev_detail = (
                    f"Listed in CISA KEV catalog. "
                    f"Ransomware use: {kev_entry.known_ransomware_use}. "
                    f"Action: {kev_entry.required_action[:200]}"
                )
                # KEV listing upgrades evidence type
                if match.evidence_type == "hypothesis":
                    match.evidence_type = "external_intelligence"
                    match.evidence_detail += " Confirmed actively exploited (CISA KEV)."

    # Sort by CVSS score descending
    result = sorted(
        matches.values(),
        key=lambda m: m.cvss_score or 0,
        reverse=True,
    )

    logger.info(
        "cve_matching_complete",
        product=product,
        version=version,
        matches_found=len(result),
        kev_matches=sum(1 for m in result if m.is_kev),
    )

    return result


def _search_by_cpe(
    cpe: str,
    product: str,
    version: str,
    *,
    api_key: str,
    rate_limit: int,
    cache_ttl: int,
) -> list[CVEMatch]:
    """Search NVD by CPE with caching."""
    cache_key = f"nvd:cpe:{cpe}"

    # Check cache
    cached = cache_get(cache_key)
    if cached is not None:
        vulns = _deserialize_vulns(cached)
        intel_ts = get_cache_timestamp(cache_key) or ""
    else:
        # Try live API
        try:
            vulns = search_cves_by_cpe(cpe, api_key=api_key, rate_limit=rate_limit)
            cache_set(cache_key, "nvd", _serialize_vulns(vulns), cache_ttl)
            intel_ts = datetime.now(UTC).isoformat()
        except IntelUnavailableError:
            # Try stale cache as fallback
            stale_data, stale_ts = cache_get_stale(cache_key)
            if stale_data:
                logger.warning("nvd_using_stale_cache", cpe=cpe)
                vulns = _deserialize_vulns(stale_data)
                intel_ts = stale_ts or ""
            else:
                logger.warning("nvd_unavailable_no_cache", cpe=cpe)
                return []

    # Convert to matches with confidence assessment
    matches = []
    for vuln in vulns:
        confidence, method, detail = _assess_cpe_confidence(cpe, version, vuln)
        matches.append(
            CVEMatch(
                cve_id=vuln.cve_id,
                title=vuln.description[:200] if vuln.description else vuln.cve_id,
                description=vuln.description,
                cvss_score=vuln.cvss_v3_score or vuln.cvss_v2_score,
                cvss_vector=vuln.cvss_v3_vector,
                severity=vuln.severity,
                confidence=confidence,
                evidence_type="external_intelligence" if confidence == "high" else "hypothesis",
                evidence_detail=detail,
                match_method=method,
                source="NVD",
                source_url=vuln.source_url,
                references=vuln.references,
                intel_timestamp=intel_ts,
            )
        )

    return matches


def _search_by_keyword(
    product: str,
    version: str,
    *,
    api_key: str,
    rate_limit: int,
    cache_ttl: int,
) -> list[CVEMatch]:
    """Search NVD by keyword with caching."""
    keyword = f"{product} {version}"
    cache_key = f"nvd:keyword:{keyword}"

    cached = cache_get(cache_key)
    if cached is not None:
        vulns = _deserialize_vulns(cached)
        intel_ts = get_cache_timestamp(cache_key) or ""
    else:
        try:
            vulns = search_cves_by_keyword(keyword, api_key=api_key, rate_limit=rate_limit)
            cache_set(cache_key, "nvd", _serialize_vulns(vulns), cache_ttl)
            intel_ts = datetime.now(UTC).isoformat()
        except IntelUnavailableError:
            stale_data, stale_ts = cache_get_stale(cache_key)
            if stale_data:
                vulns = _deserialize_vulns(stale_data)
                intel_ts = stale_ts or ""
            else:
                return []

    matches = []
    for vuln in vulns:
        matches.append(
            CVEMatch(
                cve_id=vuln.cve_id,
                title=vuln.description[:200] if vuln.description else vuln.cve_id,
                description=vuln.description,
                cvss_score=vuln.cvss_v3_score or vuln.cvss_v2_score,
                cvss_vector=vuln.cvss_v3_vector,
                severity=vuln.severity,
                confidence="medium",
                evidence_type="hypothesis",
                evidence_detail=f"Keyword match for '{keyword}'. Version not verified against CPE ranges.",
                match_method="keyword",
                source="NVD",
                source_url=vuln.source_url,
                references=vuln.references,
                intel_timestamp=intel_ts,
            )
        )

    return matches


def _assess_cpe_confidence(cpe: str, version: str, vuln: NVDVulnerability) -> tuple[str, str, str]:
    """
    Assess how confident we are that a CPE match means the service is vulnerable.

    Returns:
        (confidence, match_method, evidence_detail)
    """
    # Check if the exact CPE is in the vulnerability's affected configurations
    for match in vuln.cpe_matches:
        criteria = match.get("criteria", "")
        vulnerable = match.get("vulnerable", False)

        if not vulnerable:
            continue

        # Check for version range
        v_start_inc = match.get("versionStartIncluding", "")
        v_start_exc = match.get("versionStartExcluding", "")
        v_end_inc = match.get("versionEndIncluding", "")
        v_end_exc = match.get("versionEndExcluding", "")

        has_range = any([v_start_inc, v_start_exc, v_end_inc, v_end_exc])

        if has_range and version:
            in_range = _check_version_range(version, v_start_inc, v_start_exc, v_end_inc, v_end_exc)
            if in_range:
                range_desc = _describe_range(v_start_inc, v_start_exc, v_end_inc, v_end_exc)
                return (
                    "high",
                    "cpe_range",
                    f"Version {version} falls within affected range {range_desc} for {vuln.cve_id}.",
                )
            elif in_range is False:
                continue  # Explicitly not in range

        # Check for exact CPE criteria match
        if _cpe_matches_criteria(cpe, criteria):
            return (
                "high",
                "cpe_exact",
                f"Exact CPE match: {cpe} matches {vuln.cve_id} affected configuration.",
            )

    # CPE was used in search but no exact configuration match
    return (
        "medium",
        "cpe_search",
        f"CPE-based search result. Service CPE {cpe} returned this CVE but exact version range not confirmed.",
    )


def _cpe_matches_criteria(service_cpe: str, criteria_cpe: str) -> bool:
    """Check if a service CPE matches a vulnerability criteria CPE."""
    # Normalize both to comparable format
    s_parts = service_cpe.replace("cpe:/", "cpe:2.3:").split(":")
    c_parts = criteria_cpe.split(":")

    # Compare vendor:product at minimum
    if len(s_parts) >= 5 and len(c_parts) >= 5:
        # parts[3] = vendor, parts[4] = product
        if s_parts[3] == c_parts[3] and s_parts[4] == c_parts[4]:
            # If version matches too, even better
            if len(s_parts) >= 6 and len(c_parts) >= 6:
                if c_parts[5] == "*" or s_parts[5] == c_parts[5]:
                    return True
            return True

    return False


def _check_version_range(
    version: str,
    start_inc: str,
    start_exc: str,
    end_inc: str,
    end_exc: str,
) -> bool | None:
    """
    Check if a version falls within a specified range.

    Returns True if in range, False if not, None if unable to determine.
    """
    try:
        v = _parse_version_tuple(version)
        if v is None:
            return None

        # Check lower bound
        if start_inc:
            lower = _parse_version_tuple(start_inc)
            if lower and v < lower:
                return False
        if start_exc:
            lower = _parse_version_tuple(start_exc)
            if lower and v <= lower:
                return False

        # Check upper bound
        if end_inc:
            upper = _parse_version_tuple(end_inc)
            if upper and v > upper:
                return False
        if end_exc:
            upper = _parse_version_tuple(end_exc)
            if upper and v >= upper:
                return False

        return True

    except Exception:
        return None


def _parse_version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple of integers."""
    # Extract numeric parts
    parts = re.findall(r"\d+", version)
    if not parts:
        return None
    try:
        return tuple(int(p) for p in parts[:4])
    except ValueError:
        return None


def _describe_range(start_inc: str, start_exc: str, end_inc: str, end_exc: str) -> str:
    """Create a human-readable version range description."""
    parts = []
    if start_inc:
        parts.append(f">= {start_inc}")
    if start_exc:
        parts.append(f"> {start_exc}")
    if end_inc:
        parts.append(f"<= {end_inc}")
    if end_exc:
        parts.append(f"< {end_exc}")
    return " and ".join(parts) if parts else "unspecified range"


def _confidence_rank(confidence: str) -> int:
    """Numeric rank for confidence comparison."""
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def _serialize_vulns(vulns: list[NVDVulnerability]) -> str:
    """Serialize NVDVulnerability list to JSON for caching."""
    return json.dumps(
        [
            {
                "cve_id": v.cve_id,
                "description": v.description,
                "cvss_v3_score": v.cvss_v3_score,
                "cvss_v3_vector": v.cvss_v3_vector,
                "cvss_v2_score": v.cvss_v2_score,
                "severity": v.severity,
                "published": v.published,
                "modified": v.modified,
                "references": v.references,
                "cpe_matches": v.cpe_matches,
                "weaknesses": v.weaknesses,
                "source_url": v.source_url,
            }
            for v in vulns
        ]
    )


def _deserialize_vulns(data: str) -> list[NVDVulnerability]:
    """Deserialize cached JSON back to NVDVulnerability list."""
    items = json.loads(data)
    return [
        NVDVulnerability(
            cve_id=item["cve_id"],
            description=item.get("description", ""),
            cvss_v3_score=item.get("cvss_v3_score"),
            cvss_v3_vector=item.get("cvss_v3_vector"),
            cvss_v2_score=item.get("cvss_v2_score"),
            severity=item.get("severity", "unknown"),
            published=item.get("published", ""),
            modified=item.get("modified", ""),
            references=item.get("references", []),
            cpe_matches=item.get("cpe_matches", []),
            weaknesses=item.get("weaknesses", []),
            source_url=item.get("source_url", ""),
        )
        for item in items
    ]
