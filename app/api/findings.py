"""
Findings API endpoints for AEGIS-Recon.

GET /api/findings/{scan_id}         — Get findings for a scan (triggers enrichment if needed)
GET /api/findings/{scan_id}/enrich  — Trigger CVE enrichment for a scan
GET /api/findings/detail/{finding_id} — Get a single finding detail
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.config import get_settings
from app.core.auth import require_api_key
from app.core.logging import get_logger
from app.core.ratelimit import limit_api_rate, limit_scan_rate
from app.db.repository import (
    get_finding,
    get_findings_for_scan,
    get_scan,
    get_services_for_scan,
    save_finding,
)
from app.intel.cache import cache_get, cache_get_stale, cache_set
from app.intel.kev import KEVCatalog, fetch_kev_catalog, parse_kev_from_cache
from app.intel.matcher import match_service_cves
from app.risk.scoring import calculate_risk

logger = get_logger(__name__)
router = APIRouter()


@router.get("/findings/{scan_id}", dependencies=[Depends(limit_api_rate)])
async def get_scan_findings(scan_id: str) -> dict[str, Any]:
    """Get all findings for a scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings_for_scan(scan_id)
    return {"scan_id": scan_id, "findings": findings, "count": len(findings)}


@router.post(
    "/findings/{scan_id}/enrich", dependencies=[Depends(require_api_key), Depends(limit_scan_rate)]
)
async def enrich_scan(scan_id: str) -> dict[str, Any]:
    """
    Trigger CVE enrichment for a scan.

    Looks up each service against NVD, enriches with KEV,
    scores risk, and stores findings.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    settings = get_settings()
    services = get_services_for_scan(scan_id)

    if not services:
        return {"scan_id": scan_id, "message": "No services to enrich.", "findings_created": 0}

    # Load KEV catalog (with caching)
    kev_catalog = _load_kev_catalog(settings.kev_cache_ttl)

    findings_created = 0

    for svc in services:
        product = svc.get("product", "")
        version = svc.get("version", "")

        if not product:
            continue

        # Parse CPE list
        cpe_list = []
        cpe_raw = svc.get("cpe", "[]")
        try:
            cpe_list = json.loads(cpe_raw) if isinstance(cpe_raw, str) else cpe_raw
        except json.JSONDecodeError:
            pass

        # Match CVEs
        try:
            matches = match_service_cves(
                product=product,
                version=version,
                cpe_list=cpe_list,
                api_key=settings.nvd_api_key,
                rate_limit=settings.nvd_rate_limit,
                nvd_cache_ttl=settings.nvd_cache_ttl,
                kev_catalog=kev_catalog,
            )
        except Exception as e:
            logger.warning("enrichment_error", service_id=svc["id"], error=str(e))
            continue

        # Score and store each match
        for match in matches:
            risk = calculate_risk(
                cvss_score=match.cvss_score,
                cvss_severity=match.severity,
                confidence=match.confidence,
                evidence_type=match.evidence_type,
                is_kev=match.is_kev,
                service_name=svc.get("service_name", ""),
                port=svc.get("port", 0),
                match_method=match.match_method,
            )

            finding = {
                "service_id": svc["id"],
                "scan_id": scan_id,
                "cve_id": match.cve_id,
                "title": match.title,
                "description": match.description[:2000],
                "cvss_score": match.cvss_score,
                "cvss_vector": match.cvss_vector,
                "severity": match.severity,
                "confidence": match.confidence,
                "evidence_type": match.evidence_type,
                "evidence_detail": match.evidence_detail,
                "source": match.source,
                "source_url": match.source_url,
                "is_kev": 1 if match.is_kev else 0,
                "kev_due_date": match.kev_due_date,
                "priority_score": risk.priority_score,
                "priority_factors": risk.factors,
                "match_detail": match.match_method,
                "intel_timestamp": match.intel_timestamp,
            }

            try:
                save_finding(finding)
                findings_created += 1
            except Exception as e:
                logger.warning("finding_save_error", cve_id=match.cve_id, error=str(e))

    logger.info("enrichment_complete", scan_id=scan_id, findings=findings_created)

    return {
        "scan_id": scan_id,
        "message": f"Enrichment complete. {findings_created} findings created.",
        "findings_created": findings_created,
    }


@router.get("/findings/detail/{finding_id}", dependencies=[Depends(limit_api_rate)])
async def get_finding_detail(finding_id: str) -> dict[str, Any]:
    """Get detailed information about a single finding."""
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding}


def _load_kev_catalog(cache_ttl: int) -> KEVCatalog | None:
    """Load KEV catalog with caching."""
    cache_key = "kev:catalog"

    # Try fresh cache
    cached = cache_get(cache_key)
    if cached:
        try:
            return parse_kev_from_cache(cached)
        except Exception as e:
            logger.debug("kev_cache_parse_failed", error=str(e))

    # Try live download
    try:
        catalog = fetch_kev_catalog()
        import json

        # Cache the raw data
        cache_set(
            cache_key,
            "kev",
            json.dumps(
                {
                    "title": catalog.title,
                    "catalogVersion": catalog.catalog_version,
                    "dateReleased": catalog.date_released,
                    "count": catalog.count,
                    "vulnerabilities": [
                        {
                            "cveID": e.cve_id,
                            "vendorProject": e.vendor,
                            "product": e.product,
                            "vulnerabilityName": e.vulnerability_name,
                            "dateAdded": e.date_added,
                            "dueDate": e.due_date,
                            "shortDescription": e.short_description,
                            "requiredAction": e.required_action,
                            "knownRansomwareCampaignUse": e.known_ransomware_use,
                        }
                        for e in catalog.entries.values()
                    ],
                }
            ),
            cache_ttl,
        )
        return catalog
    except Exception as e:
        logger.warning("kev_download_failed", error=str(e))

    # Try stale cache as last resort
    stale_data, _ = cache_get_stale(cache_key)
    if stale_data:
        try:
            logger.warning("kev_using_stale_cache")
            return parse_kev_from_cache(stale_data)
        except Exception as e:
            logger.debug("kev_stale_cache_parse_failed", error=str(e))

    return None
