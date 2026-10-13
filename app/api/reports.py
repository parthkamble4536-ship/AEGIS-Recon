"""
Reports API endpoints for AEGIS-Recon.

GET /api/reports/{scan_id}/json     — Generate JSON report
GET /api/reports/{scan_id}/html     — Generate HTML report
GET /api/reports/{scan_id}/analysis — Get AI or deterministic analysis
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.core.logging import get_logger
from app.db.repository import (
    get_findings_for_scan,
    get_hosts_for_scan,
    get_scan,
    get_services_for_scan,
)
from app.reports.builder import build_html_report, build_json_report
from app.ai.fallback import generate_deterministic_analysis

logger = get_logger(__name__)
router = APIRouter()


@router.get("/reports/{scan_id}/json")
async def get_json_report(scan_id: str) -> dict[str, Any]:
    """Generate and return a JSON report for a scan."""
    scan, hosts, services, findings = _load_scan_data(scan_id)

    analysis = _get_analysis(scan, services, findings)

    report = build_json_report(scan, hosts, services, findings, analysis)
    return report


@router.get("/reports/{scan_id}/html", response_class=HTMLResponse)
async def get_html_report(scan_id: str) -> HTMLResponse:
    """Generate and return an HTML report for a scan."""
    scan, hosts, services, findings = _load_scan_data(scan_id)

    analysis = _get_analysis(scan, services, findings)

    html = build_html_report(scan, hosts, services, findings, analysis)
    return HTMLResponse(content=html)


@router.get("/reports/{scan_id}/analysis")
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


def _get_analysis(
    scan: dict, services: list, findings: list
) -> dict[str, Any]:
    """
    Get analysis — tries AI if enabled, falls back to deterministic.

    For MVP, always uses deterministic fallback.
    AI provider integration will be added when API key is configured.
    """
    settings = get_settings()

    scan_context = {
        "target": scan.get("target", "unknown"),
        "profile": scan.get("profile", "unknown"),
        "scan_time": scan.get("start_time", "unknown"),
        "service_count": len(services),
    }

    # For now, always use deterministic fallback
    # AI integration will check settings.ai_enabled in Week 2 refinement
    analysis = generate_deterministic_analysis(findings, scan_context)

    return analysis
