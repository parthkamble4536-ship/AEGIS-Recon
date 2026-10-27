"""
Scan API endpoints for AEGIS-Recon.

POST /api/scans  — Start a new scan (validates target, runs Nmap, parses, enriches)
GET  /api/scans  — List all scans
GET  /api/scans/{scan_id} — Get scan details with hosts and services
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.auth import require_api_key
from app.core.errors import AllowlistLoadError
from app.core.logging import get_logger
from app.core.ratelimit import limit_api_rate, limit_scan_rate
from app.core.validation import Allowlist, validate_ports, validate_profile, validate_target
from app.db.repository import (
    get_all_scans,
    get_hosts_for_scan,
    get_scan,
    get_services_for_scan,
    save_parsed_scan,
    save_scan,
)
from app.parser.nmap_xml import parse_nmap_xml
from app.scanner.runner import run_scan

logger = get_logger(__name__)
router = APIRouter()


class ScanRequest(BaseModel):
    """Request body for starting a new scan."""

    target: str = Field(..., description="Target IP, CIDR, or hostname (must be in allowlist)")
    profile: str = Field(default="quick", description="Scan profile: quick, standard, thorough")
    ports: str | None = Field(
        default=None, description="Optional port specification (e.g., '22,80,443')"
    )


class ScanResponse(BaseModel):
    """Response for a scan operation."""

    scan_id: str
    target: str
    profile: str
    status: str
    message: str


@router.post(
    "/scans",
    response_model=ScanResponse,
    dependencies=[Depends(require_api_key), Depends(limit_scan_rate)],
)
async def create_scan(request: ScanRequest) -> ScanResponse:
    """
    Start a new scan.

    Validates the target against the allowlist, runs Nmap,
    parses results, and stores them in the database.
    """
    settings = get_settings()

    # Load allowlist
    try:
        allowlist = Allowlist.from_yaml(settings.allowlist_path_resolved)
    except AllowlistLoadError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Validate inputs
    target = validate_target(request.target, allowlist)
    profile = validate_profile(request.profile, allowlist)
    ports = validate_ports(request.ports)

    # Run scan
    result = run_scan(
        target,
        profile,
        nmap_path=settings.nmap_path,
        timeout=settings.nmap_timeout,
        ports=ports,
    )

    # Save scan record
    save_scan(result)

    # Parse and store results if we have XML
    if result.xml_output:
        try:
            parsed = parse_nmap_xml(result.xml_output)
            save_parsed_scan(result.scan_id, parsed)
        except Exception as e:
            logger.error("parse_failed_after_scan", scan_id=result.scan_id, error=str(e))

    # Run enrichment in the background could be done here,
    # but for MVP we do it synchronously on the findings endpoint
    status_msg = {
        "completed": "Scan completed successfully.",
        "timeout": f"Scan timed out after {settings.nmap_timeout}s. Partial results may be available.",
        "failed": f"Scan failed: {result.error_message or 'unknown error'}",
    }

    return ScanResponse(
        scan_id=result.scan_id,
        target=target,
        profile=profile,
        status=result.status,
        message=status_msg.get(result.status, "Unknown status."),
    )


@router.get("/scans", dependencies=[Depends(limit_api_rate)])
async def list_scans(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List all scans, newest first."""
    scans = get_all_scans(limit=min(limit, 100), offset=offset)
    return {"scans": scans, "count": len(scans)}


@router.get("/scans/{scan_id}", dependencies=[Depends(limit_api_rate)])
async def get_scan_detail(scan_id: str) -> dict[str, Any]:
    """Get full scan details including hosts and services."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = get_hosts_for_scan(scan_id)
    services = get_services_for_scan(scan_id)

    return {
        "scan": scan,
        "hosts": hosts,
        "services": services,
    }
