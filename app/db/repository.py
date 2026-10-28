"""
Data access layer (repository pattern) for AEGIS-Recon.

All SQL is parameterized — no string interpolation of user data into queries.
Each function does one thing and returns typed results.
"""

from __future__ import annotations

import json
import sqlite3
import uuid

from app.core.logging import get_logger
from app.db.database import get_db
from app.parser.nmap_xml import ParsedHost, ParsedScan, ParsedService
from app.scanner.runner import ScanResult

logger = get_logger(__name__)


# ── Scan Operations ──────────────────────────────────────


def save_scan(result: ScanResult) -> str:
    """
    Save a scan result to the database.

    Args:
        result: ScanResult from the scanner runner.

    Returns:
        The scan ID.
    """
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, target, profile, status, start_time, end_time,
                               nmap_version, command_args, error_message,
                               hosts_up, hosts_down, hosts_total)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.scan_id,
                result.target,
                result.profile,
                result.status,
                result.start_time.isoformat(),
                result.end_time.isoformat() if result.end_time else None,
                result.nmap_version,
                json.dumps(result.command_args),
                result.error_message,
                0,
                0,
                0,  # Updated after parsing
            ),
        )
    logger.info("scan_saved", scan_id=result.scan_id)
    return result.scan_id


def update_scan_stats(scan_id: str, parsed: ParsedScan) -> None:
    """Update scan statistics after parsing."""
    with get_db() as conn:
        conn.execute(
            """
            UPDATE scans SET hosts_up = ?, hosts_down = ?, hosts_total = ?,
                             end_time = COALESCE(?, end_time)
            WHERE id = ?
            """,
            (
                parsed.hosts_up,
                parsed.hosts_down,
                parsed.hosts_total,
                parsed.end_time.isoformat() if parsed.end_time else None,
                scan_id,
            ),
        )


def get_scan(scan_id: str) -> dict | None:
    """Get a scan by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_all_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    """Get all scans ordered by creation time (newest first)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Host Operations ──────────────────────────────────────


def save_host(scan_id: str, host: ParsedHost) -> str:
    """
    Save a parsed host and its services to the database.

    Args:
        scan_id: The parent scan ID.
        host: ParsedHost from the XML parser.

    Returns:
        The host ID.
    """
    host_id = str(uuid.uuid4())

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO hosts (id, scan_id, ip, hostnames, status, os_matches)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                host_id,
                scan_id,
                host.ip,
                json.dumps(host.hostnames),
                host.status,
                json.dumps(host.os_matches),
            ),
        )

        # Save each service
        for service in host.services:
            save_service(conn, host_id, scan_id, service)

    logger.info(
        "host_saved",
        host_id=host_id,
        ip=host.ip,
        services_count=len(host.services),
    )
    return host_id


def save_service(conn: sqlite3.Connection, host_id: str, scan_id: str, service: ParsedService) -> str:
    """Save a single service (called within a transaction)."""
    service_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO services (id, host_id, scan_id, port, protocol, state,
                              service_name, product, version, extra_info,
                              cpe, banner, scripts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            service_id,
            host_id,
            scan_id,
            service.port,
            service.protocol,
            service.state,
            service.service_name,
            service.product,
            service.version,
            service.extra_info,
            json.dumps(service.cpe),
            service.banner,
            json.dumps(service.scripts),
        ),
    )
    return service_id


def get_hosts_for_scan(scan_id: str) -> list[dict]:
    """Get all hosts discovered in a scan."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ? ORDER BY ip",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_services_for_host(host_id: str) -> list[dict]:
    """Get all services for a host."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port",
            (host_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_services_for_scan(scan_id: str) -> list[dict]:
    """Get all services discovered in a scan."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, h.ip, h.hostnames
            FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.scan_id = ?
            ORDER BY h.ip, s.port
            """,
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Finding Operations (used in Week 2) ──────────────────


def save_finding(finding: dict) -> str:
    """
    Save a vulnerability finding.

    Args:
        finding: Dict with keys matching the findings table columns.

    Returns:
        The finding ID.
    """
    finding_id = str(finding.get("id") or uuid.uuid4())

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO findings (id, service_id, scan_id, cve_id, title,
                                  description, cvss_score, cvss_vector, severity,
                                  confidence, evidence_type, evidence_detail,
                                  source, source_url, is_kev, kev_due_date,
                                  priority_score, priority_factors, match_detail,
                                  intel_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                finding["service_id"],
                finding["scan_id"],
                finding.get("cve_id"),
                finding.get("title"),
                finding.get("description"),
                finding.get("cvss_score"),
                finding.get("cvss_vector"),
                finding.get("severity"),
                finding.get("confidence", "low"),
                finding.get("evidence_type", "hypothesis"),
                finding.get("evidence_detail"),
                finding.get("source"),
                finding.get("source_url"),
                finding.get("is_kev", 0),
                finding.get("kev_due_date"),
                finding.get("priority_score"),
                json.dumps(finding.get("priority_factors", [])),
                finding.get("match_detail"),
                finding.get("intel_timestamp"),
            ),
        )
    return finding_id


def get_findings_for_scan(scan_id: str) -> list[dict]:
    """Get all findings for a scan."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT f.*, s.port, s.protocol, s.service_name, s.product, s.version,
                   h.ip, h.hostnames
            FROM findings f
            JOIN services s ON f.service_id = s.id
            JOIN hosts h ON s.host_id = h.id
            WHERE f.scan_id = ?
            ORDER BY f.priority_score DESC NULLS LAST, f.cvss_score DESC NULLS LAST
            """,
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_finding(finding_id: str) -> dict | None:
    """Get a single finding by ID."""
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT f.*, s.port, s.protocol, s.service_name, s.product, s.version,
                   h.ip, h.hostnames
            FROM findings f
            JOIN services s ON f.service_id = s.id
            JOIN hosts h ON s.host_id = h.id
            WHERE f.id = ?
            """,
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None


# ── Pipeline Helper ──────────────────────────────────────


def save_parsed_scan(scan_id: str, parsed: ParsedScan) -> dict:
    """
    Save a complete parsed scan (hosts + services) to the database.

    This is the main entry point after scanning and parsing.

    Args:
        scan_id: The scan ID (already saved via save_scan).
        parsed: ParsedScan from the XML parser.

    Returns:
        Summary dict with counts.
    """
    total_hosts = 0
    total_services = 0

    for host in parsed.hosts:
        save_host(scan_id, host)
        total_hosts += 1
        total_services += len(host.services)

    update_scan_stats(scan_id, parsed)

    logger.info(
        "parsed_scan_saved",
        scan_id=scan_id,
        hosts=total_hosts,
        services=total_services,
    )

    return {
        "scan_id": scan_id,
        "hosts_saved": total_hosts,
        "services_saved": total_services,
    }
