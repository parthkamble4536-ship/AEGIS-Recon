"""
Data models for scan diff and vulnerability lifecycle tracking.

Tracks what changed between two scans:
- NEW findings (appeared in scan B, not in scan A)
- RESOLVED findings (in scan A, not in scan B)
- PERSISTENT findings (in both scans, unchanged)
- CHANGED findings (in both scans, but something changed: severity, version, etc.)

Also tracks finding lifecycle states for analyst workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingState(StrEnum):
    """State of a finding across two scans."""

    NEW = "new"
    PERSISTENT = "persistent"
    RESOLVED = "resolved"
    CHANGED = "changed"


class FindingStatus(StrEnum):
    """Analyst lifecycle status of a finding."""

    NEW = "new"
    TRIAGED = "triaged"
    VERIFIED = "verified"
    REMEDIATION_PLANNED = "remediation_planned"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class AnalystDecision(StrEnum):
    """Formal analyst decision on a finding."""

    PENDING = "pending"
    VERIFY = "verify"
    FALSE_POSITIVE = "false_positive"
    ACCEPT_RISK = "accept_risk"
    REMEDIATE = "remediate"
    SNOOZE = "snooze"


class FalsePositiveReason(StrEnum):
    """Structured reasons for false-positive classification."""

    INCORRECT_VERSION = "incorrect_version"
    BACKPORTED_PATCH = "backported_patch"
    NOT_APPLICABLE = "not_applicable"
    COMPENSATING_CONTROL = "compensating_control"
    DUPLICATE = "duplicate"
    OTHER = "other"


@dataclass
class DiffEntry:
    """
    A single entry in a scan diff representing one finding's change status.

    Attributes:
        cve_id: The CVE identifier.
        host_ip: IP address of the affected host.
        port: Port number of the affected service.
        protocol: Protocol (tcp/udp).
        service_name: Name of the service.
        state: Whether the finding is NEW, PERSISTENT, RESOLVED, or CHANGED.
        scan_a_id: Source scan ID (baseline).
        scan_b_id: Target scan ID (current).
        finding_a_id: Finding ID in scan A (None if NEW).
        finding_b_id: Finding ID in scan B (None if RESOLVED).
        changes: Dict of field name → (old_value, new_value) for CHANGED entries.
        priority_score_a: Priority score in scan A (None if NEW).
        priority_score_b: Priority score in scan B (None if RESOLVED).
    """

    cve_id: str
    host_ip: str
    port: int
    protocol: str
    service_name: str
    state: FindingState
    scan_a_id: str
    scan_b_id: str
    finding_a_id: str | None = None
    finding_b_id: str | None = None
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    priority_score_a: float | None = None
    priority_score_b: float | None = None


@dataclass
class ScanDiff:
    """
    Full diff result between two scans.

    Attributes:
        scan_a_id: Baseline scan ID.
        scan_b_id: Current scan ID.
        new_findings: Findings that appeared in scan B but not scan A.
        resolved_findings: Findings in scan A that are no longer in scan B.
        persistent_findings: Findings present and unchanged in both scans.
        changed_findings: Findings present in both but with differences.
        new_services: Services discovered in scan B but not scan A.
        removed_services: Services in scan A that disappeared from scan B.
        summary: Human-readable summary dict.
    """

    scan_a_id: str
    scan_b_id: str
    new_findings: list[DiffEntry] = field(default_factory=list)
    resolved_findings: list[DiffEntry] = field(default_factory=list)
    persistent_findings: list[DiffEntry] = field(default_factory=list)
    changed_findings: list[DiffEntry] = field(default_factory=list)
    new_services: list[dict[str, Any]] = field(default_factory=list)
    removed_services: list[dict[str, Any]] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        """Return a human-readable summary of the diff."""
        return {
            "scan_a_id": self.scan_a_id,
            "scan_b_id": self.scan_b_id,
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
            "persistent_findings": len(self.persistent_findings),
            "changed_findings": len(self.changed_findings),
            "new_services": len(self.new_services),
            "removed_services": len(self.removed_services),
            "total_active": len(self.new_findings)
            + len(self.persistent_findings)
            + len(self.changed_findings),
        }
