"""
Scan diff engine for AEGIS-Recon.

Compares two scans to detect:
- New findings (appeared since last scan)
- Resolved findings (no longer present)
- Persistent findings (unchanged)
- Changed findings (present in both but something changed)
- New/removed services

Findings are keyed by (host_ip, port, protocol, cve_id) for stable comparison.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.db.database import get_db
from app.diff.models import DiffEntry, FindingState, ScanDiff

logger = get_logger(__name__)

# Fields that, when changed, mark a finding as CHANGED rather than PERSISTENT
TRACKED_CHANGE_FIELDS = [
    "cvss_score",
    "severity",
    "priority_score",
    "is_kev",
    "confidence",
    "evidence_type",
]


def _get_scan_findings(scan_id: str) -> list[dict[str, Any]]:
    """
    Retrieve all findings for a scan, joined with host/service info.

    Returns a list of dicts with keys:
        finding_id, cve_id, host_ip, port, protocol, service_name,
        cvss_score, severity, priority_score, is_kev, confidence, evidence_type
    """
    with get_db() as conn:
        conn.row_factory = None  # use tuple rows, convert manually
        rows = conn.execute(
            """
            SELECT
                f.id AS finding_id,
                f.cve_id,
                h.ip AS host_ip,
                s.port,
                s.protocol,
                s.service_name,
                f.cvss_score,
                f.severity,
                f.priority_score,
                f.is_kev,
                f.confidence,
                f.evidence_type
            FROM findings f
            JOIN services s ON f.service_id = s.id
            JOIN hosts h ON s.host_id = h.id
            WHERE f.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

    columns = [
        "finding_id", "cve_id", "host_ip", "port", "protocol",
        "service_name", "cvss_score", "severity", "priority_score",
        "is_kev", "confidence", "evidence_type",
    ]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _get_scan_services(scan_id: str) -> list[dict[str, Any]]:
    """Retrieve all services for a scan, joined with host info."""
    with get_db() as conn:
        conn.row_factory = None
        rows = conn.execute(
            """
            SELECT
                s.id AS service_id,
                h.ip AS host_ip,
                s.port,
                s.protocol,
                s.service_name,
                s.product,
                s.version,
                s.state
            FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

    columns = ["service_id", "host_ip", "port", "protocol", "service_name", "product", "version", "state"]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _make_finding_key(finding: dict[str, Any]) -> tuple[str, int, str, str]:
    """Create a stable key for a finding: (host_ip, port, protocol, cve_id)."""
    return (
        finding["host_ip"] or "",
        finding["port"] or 0,
        finding["protocol"] or "tcp",
        finding["cve_id"] or "",
    )


def _make_service_key(service: dict[str, Any]) -> tuple[str, int, str]:
    """Create a stable key for a service: (host_ip, port, protocol)."""
    return (
        service["host_ip"] or "",
        service["port"] or 0,
        service["protocol"] or "tcp",
    )


def compare_scans(scan_a_id: str, scan_b_id: str) -> ScanDiff:
    """
    Compare two scans and return a ScanDiff.

    Args:
        scan_a_id: Baseline scan (older/previous).
        scan_b_id: Current scan (newer/current).

    Returns:
        ScanDiff with categorized findings and services.
    """
    logger.info("diff_started", scan_a=scan_a_id, scan_b=scan_b_id)

    findings_a = _get_scan_findings(scan_a_id)
    findings_b = _get_scan_findings(scan_b_id)

    # Index by stable key
    index_a: dict[tuple, dict[str, Any]] = {_make_finding_key(f): f for f in findings_a}
    index_b: dict[tuple, dict[str, Any]] = {_make_finding_key(f): f for f in findings_b}

    keys_a = set(index_a)
    keys_b = set(index_b)

    diff = ScanDiff(scan_a_id=scan_a_id, scan_b_id=scan_b_id)

    # NEW: in B but not A
    for key in keys_b - keys_a:
        fb = index_b[key]
        diff.new_findings.append(
            DiffEntry(
                cve_id=fb["cve_id"] or "",
                host_ip=fb["host_ip"] or "",
                port=fb["port"] or 0,
                protocol=fb["protocol"] or "tcp",
                service_name=fb["service_name"] or "",
                state=FindingState.NEW,
                scan_a_id=scan_a_id,
                scan_b_id=scan_b_id,
                finding_a_id=None,
                finding_b_id=fb["finding_id"],
                priority_score_a=None,
                priority_score_b=fb.get("priority_score"),
            )
        )

    # RESOLVED: in A but not B
    for key in keys_a - keys_b:
        fa = index_a[key]
        diff.resolved_findings.append(
            DiffEntry(
                cve_id=fa["cve_id"] or "",
                host_ip=fa["host_ip"] or "",
                port=fa["port"] or 0,
                protocol=fa["protocol"] or "tcp",
                service_name=fa["service_name"] or "",
                state=FindingState.RESOLVED,
                scan_a_id=scan_a_id,
                scan_b_id=scan_b_id,
                finding_a_id=fa["finding_id"],
                finding_b_id=None,
                priority_score_a=fa.get("priority_score"),
                priority_score_b=None,
            )
        )

    # PERSISTENT or CHANGED: in both
    for key in keys_a & keys_b:
        fa = index_a[key]
        fb = index_b[key]
        changes: dict[str, tuple[Any, Any]] = {}
        for field_name in TRACKED_CHANGE_FIELDS:
            val_a = fa.get(field_name)
            val_b = fb.get(field_name)
            if val_a != val_b:
                changes[field_name] = (val_a, val_b)

        state = FindingState.CHANGED if changes else FindingState.PERSISTENT
        diff_entry = DiffEntry(
            cve_id=fa["cve_id"] or "",
            host_ip=fa["host_ip"] or "",
            port=fa["port"] or 0,
            protocol=fa["protocol"] or "tcp",
            service_name=fa["service_name"] or "",
            state=state,
            scan_a_id=scan_a_id,
            scan_b_id=scan_b_id,
            finding_a_id=fa["finding_id"],
            finding_b_id=fb["finding_id"],
            changes=changes,
            priority_score_a=fa.get("priority_score"),
            priority_score_b=fb.get("priority_score"),
        )
        if state == FindingState.CHANGED:
            diff.changed_findings.append(diff_entry)
        else:
            diff.persistent_findings.append(diff_entry)

    # Service diff
    services_a = _get_scan_services(scan_a_id)
    services_b = _get_scan_services(scan_b_id)
    svc_keys_a = {_make_service_key(s): s for s in services_a}
    svc_keys_b = {_make_service_key(s): s for s in services_b}

    diff.new_services = [svc_keys_b[k] for k in set(svc_keys_b) - set(svc_keys_a)]
    diff.removed_services = [svc_keys_a[k] for k in set(svc_keys_a) - set(svc_keys_b)]

    logger.info(
        "diff_completed",
        scan_a=scan_a_id,
        scan_b=scan_b_id,
        new=len(diff.new_findings),
        resolved=len(diff.resolved_findings),
        persistent=len(diff.persistent_findings),
        changed=len(diff.changed_findings),
    )
    return diff


def diff_to_dict(diff: ScanDiff) -> dict[str, Any]:
    """Serialize a ScanDiff to a JSON-serializable dict."""

    def entry_to_dict(e: DiffEntry) -> dict[str, Any]:
        return {
            "cve_id": e.cve_id,
            "host_ip": e.host_ip,
            "port": e.port,
            "protocol": e.protocol,
            "service_name": e.service_name,
            "state": e.state,
            "scan_a_id": e.scan_a_id,
            "scan_b_id": e.scan_b_id,
            "finding_a_id": e.finding_a_id,
            "finding_b_id": e.finding_b_id,
            "changes": {k: list(v) for k, v in e.changes.items()},
            "priority_score_a": e.priority_score_a,
            "priority_score_b": e.priority_score_b,
        }

    return {
        "summary": diff.summary,
        "new_findings": [entry_to_dict(e) for e in diff.new_findings],
        "resolved_findings": [entry_to_dict(e) for e in diff.resolved_findings],
        "persistent_findings": [entry_to_dict(e) for e in diff.persistent_findings],
        "changed_findings": [entry_to_dict(e) for e in diff.changed_findings],
        "new_services": diff.new_services,
        "removed_services": diff.removed_services,
    }
