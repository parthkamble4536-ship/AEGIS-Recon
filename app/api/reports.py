"""
Reports API endpoints for AEGIS-Recon.

GET /api/reports/{scan_id}/json     — Generate JSON report
GET /api/reports/{scan_id}/html     — Generate HTML report
GET /api/reports/{scan_id}/analysis — Get AI or deterministic analysis
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse

from app.ai.fallback import generate_deterministic_analysis
from app.ai.provider import get_ai_provider
from app.config import get_settings
from app.core.auth import require_api_key
from app.core.logging import get_logger
from app.core.ratelimit import limit_api_rate
from app.db.repository import (
    get_findings_for_scan,
    get_hosts_for_scan,
    get_scan,
    get_services_for_scan,
)
from app.reports.builder import build_html_report, build_json_report

logger = get_logger(__name__)
router = APIRouter()


@router.get(
    "/reports/{scan_id}/json", dependencies=[Depends(require_api_key), Depends(limit_api_rate)]
)
async def get_json_report(scan_id: str) -> dict[str, Any]:
    """Generate and return a JSON report for a scan."""
    scan, hosts, services, findings = _load_scan_data(scan_id)

    analysis = _get_analysis(scan, services, findings)

    return build_json_report(scan, hosts, services, findings, analysis)


@router.get(
    "/reports/{scan_id}/html",
    response_class=HTMLResponse,
    dependencies=[Depends(require_api_key), Depends(limit_api_rate)],
)
async def get_html_report(scan_id: str) -> HTMLResponse:
    """Generate and return an HTML report for a scan."""
    scan, hosts, services, findings = _load_scan_data(scan_id)

    analysis = _get_analysis(scan, services, findings)

    html = build_html_report(scan, hosts, services, findings, analysis)
    return HTMLResponse(content=html)


@router.get(
    "/reports/{scan_id}/analysis", dependencies=[Depends(require_api_key), Depends(limit_api_rate)]
)
async def get_analysis(scan_id: str) -> dict[str, Any]:
    """Get AI or deterministic analysis for a scan."""
    scan, hosts, services, findings = _load_scan_data(scan_id)
    analysis = _get_analysis(scan, services, findings)
    return {"scan_id": scan_id, "analysis": analysis}


def _load_scan_data(scan_id: str) -> tuple[dict, list, list, list]:
    """Load all scan data or raise 404."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = get_hosts_for_scan(scan_id)
    services = get_services_for_scan(scan_id)
    findings = get_findings_for_scan(scan_id)

    return scan, hosts, services, findings


def _get_analysis(scan: dict, services: list, findings: list) -> dict[str, Any]:
    """
    Get analysis — tries configured AI provider first if enabled,
    with automatic and transparent fallback to deterministic analysis.
    """
    settings = get_settings()

    scan_context = {
        "target": scan.get("target", "unknown"),
        "profile": scan.get("profile", "unknown"),
        "scan_time": scan.get("start_time", "unknown"),
        "service_count": len(services),
    }

    if settings.ai_enabled:
        provider = get_ai_provider()
        if provider and provider.is_available():
            try:
                logger.info("running_ai_analysis", provider=settings.ai_provider)
                return provider.analyze_findings(findings, scan_context)
            except Exception as e:
                logger.warning("ai_analysis_failed_fallback_to_deterministic", error=str(e))

    return generate_deterministic_analysis(findings, scan_context)
