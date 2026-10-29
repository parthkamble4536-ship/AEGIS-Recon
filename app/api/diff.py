"""
API endpoints for scan diff and finding lifecycle management.

Routes:
    GET   /api/scans/{scan_id}/diff?baseline={scan_a_id}  — Compare two scans
    PATCH /api/findings/{finding_id}/status               — Update analyst status
    PATCH /api/findings/{finding_id}/decision             — Record analyst decision
    PATCH /api/findings/{finding_id}/remediation          — Set remediation guidance
    GET   /api/findings/{finding_id}/history              — Status/decision history
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.core.logging import get_logger
from app.diff.engine import compare_scans, diff_to_dict
from app.diff.models import AnalystDecision, FalsePositiveReason, FindingStatus
from app.diff.remediation import update_finding_remediation
from app.diff.repository import (
    get_finding_status_history,
    update_finding_decision,
    update_finding_status,
)

router = APIRouter()
logger = get_logger(__name__)


# ── Request Bodies ────────────────────────────────────────────────────────────


class StatusUpdateRequest(BaseModel):
    """Body for PATCH /api/findings/{id}/status."""

    status: str
    changed_by: str = "analyst"
    reason: str = ""


class DecisionRequest(BaseModel):
    """Body for PATCH /api/findings/{id}/decision."""

    decision: str
    decision_reason: str = ""
    decided_by: str = "analyst"
    false_positive_reason: str | None = None


class RemediationRequest(BaseModel):
    """Body for PATCH /api/findings/{id}/remediation."""

    vendor: str = ""
    fixed_version: str = ""
    advisory_url: str = ""
    recommended_action: str = ""
    updated_by: str = "analyst"


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/scans/{scan_id}/diff", tags=["diff"])
def get_scan_diff(
    scan_id: str,
    baseline: str = Query(..., description="ID of the baseline scan to compare against"),
) -> dict[str, Any]:
    """
    Compare scan_id (current) against baseline (older) and return a diff.

    The diff shows:
    - new_findings: appeared in current scan, not in baseline
    - resolved_findings: in baseline, no longer in current scan
    - persistent_findings: unchanged in both
    - changed_findings: present in both but severity/score/etc changed
    - new_services / removed_services
    """
    try:
        diff = compare_scans(scan_a_id=baseline, scan_b_id=scan_id)
    except Exception as exc:
        logger.error("diff_error", scan_id=scan_id, baseline=baseline, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Diff computation failed: {exc}") from exc

    return diff_to_dict(diff)


@router.patch("/findings/{finding_id}/status", tags=["lifecycle"])
def patch_finding_status(finding_id: str, body: StatusUpdateRequest) -> dict[str, Any]:
    """
    Update the analyst lifecycle status of a finding.

    Valid statuses: new, triaged, verified, remediation_planned,
                    remediated, closed, false_positive, accepted_risk
    """
    valid = {s.value for s in FindingStatus}
    if body.status not in valid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status {body.status!r}. Must be one of: {sorted(valid)}",
        )

    result = update_finding_status(
        finding_id=finding_id,
        status=body.status,
        changed_by=body.changed_by,
        reason=body.reason,
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
    return result


@router.patch("/findings/{finding_id}/decision", tags=["lifecycle"])
def patch_finding_decision(finding_id: str, body: DecisionRequest) -> dict[str, Any]:
    """
    Record the analyst's formal decision on a finding.

    Valid decisions: pending, verify, false_positive, accept_risk, remediate, snooze

    When decision is false_positive, provide a false_positive_reason:
        incorrect_version, backported_patch, not_applicable,
        compensating_control, duplicate, other
    """
    valid_decisions = {d.value for d in AnalystDecision}
    if body.decision not in valid_decisions:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid decision {body.decision!r}. Must be one of: {sorted(valid_decisions)}",
        )

    if body.false_positive_reason is not None:
        valid_fp = {r.value for r in FalsePositiveReason}
        if body.false_positive_reason not in valid_fp:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid false_positive_reason {body.false_positive_reason!r}. Must be one of: {sorted(valid_fp)}",
            )

    result = update_finding_decision(
        finding_id=finding_id,
        decision=body.decision,
        decision_reason=body.decision_reason,
        decided_by=body.decided_by,
        false_positive_reason=body.false_positive_reason,
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
    return result


@router.get("/findings/{finding_id}/history", tags=["lifecycle"])
def get_finding_history(finding_id: str) -> list[dict[str, Any]]:
    """
    Return the status and decision history for a finding, in chronological order.

    Each entry includes: timestamp, action, user_id, detail.
    """
    return get_finding_status_history(finding_id)


@router.patch("/findings/{finding_id}/remediation", tags=["lifecycle"])
def patch_finding_remediation(finding_id: str, body: RemediationRequest) -> dict[str, Any]:
    """
    Set remediation guidance for a finding.

    All fields must come from trusted sources (vendor advisories, NVD, CISA KEV).
    Do NOT pass AI-generated text directly — this endpoint is for verified
    remediation information only.

    Fields:
        vendor: Vendor providing the fix (e.g., "Apache Software Foundation")
        fixed_version: Version that resolves the issue (e.g., "2.15.0")
        advisory_url: URL to the official advisory
        recommended_action: Human-readable remediation step
    """
    result = update_finding_remediation(
        finding_id=finding_id,
        vendor=body.vendor,
        fixed_version=body.fixed_version,
        advisory_url=body.advisory_url,
        recommended_action=body.recommended_action,
        updated_by=body.updated_by,
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
    return result

