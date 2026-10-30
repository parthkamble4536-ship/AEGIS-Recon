"""
Repository functions for finding lifecycle management.

Handles:
- Updating finding status (analyst workflow)
- Updating analyst decision and reason
- Fetching status history from audit_log
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.db.database import get_db
from app.diff.models import AnalystDecision, FindingStatus

logger = get_logger(__name__)

_VALID_STATUS = {s.value for s in FindingStatus}
_VALID_DECISION = {d.value for d in AnalystDecision}


def update_finding_status(
    finding_id: str,
    status: str,
    changed_by: str = "analyst",
    reason: str = "",
) -> dict[str, Any] | None:
    """
    Update the lifecycle status of a finding.

    Args:
        finding_id: UUID of the finding.
        status: New FindingStatus value.
        changed_by: Who made the change (user/system identifier).
        reason: Optional reason for the status change.

    Returns:
        Updated finding dict, or None if not found.
    """
    if status not in _VALID_STATUS:
        raise ValueError(f"Invalid status: {status!r}. Must be one of {sorted(_VALID_STATUS)}")

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE findings SET analyst_status = ?, status_changed_at = ?, status_changed_by = ? WHERE id = ?",
            (status, now, changed_by, finding_id),
        )
        if cursor.rowcount == 0:
            return None

        # Write audit log entry
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, user_id, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                now,
                changed_by,
                "finding_status_changed",
                finding_id,
                json.dumps({"new_status": status, "reason": reason}),
            ),
        )
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    if row is None:
        return None
    return dict(row)


def update_finding_decision(
    finding_id: str,
    decision: str,
    decision_reason: str = "",
    decided_by: str = "analyst",
    false_positive_reason: str | None = None,
) -> dict[str, Any] | None:
    """
    Record the analyst's formal decision on a finding.

    Args:
        finding_id: UUID of the finding.
        decision: AnalystDecision value.
        decision_reason: Free-text explanation.
        decided_by: Who made the decision.
        false_positive_reason: Structured FalsePositiveReason if applicable.

    Returns:
        Updated finding dict, or None if not found.
    """
    if decision not in _VALID_DECISION:
        raise ValueError(
            f"Invalid decision: {decision!r}. Must be one of {sorted(_VALID_DECISION)}"
        )

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Auto-map decision to status
    decision_status_map = {
        AnalystDecision.VERIFY: FindingStatus.TRIAGED,
        AnalystDecision.FALSE_POSITIVE: FindingStatus.FALSE_POSITIVE,
        AnalystDecision.ACCEPT_RISK: FindingStatus.ACCEPTED_RISK,
        AnalystDecision.REMEDIATE: FindingStatus.REMEDIATION_PLANNED,
        AnalystDecision.SNOOZE: FindingStatus.TRIAGED,
        AnalystDecision.PENDING: FindingStatus.NEW,
    }
    auto_status = decision_status_map.get(AnalystDecision(decision), FindingStatus.TRIAGED).value

    with get_db() as conn:
        cursor = conn.execute(
            """UPDATE findings
               SET analyst_decision = ?,
                   decision_reason = ?,
                   decided_by = ?,
                   decided_at = ?,
                   false_positive_reason = ?,
                   analyst_status = ?,
                   status_changed_at = ?,
                   status_changed_by = ?
               WHERE id = ?""",
            (
                decision,
                decision_reason,
                decided_by,
                now,
                false_positive_reason,
                auto_status,
                now,
                decided_by,
                finding_id,
            ),
        )
        if cursor.rowcount == 0:
            return None

        # Audit trail
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, user_id, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                now,
                decided_by,
                "finding_decision_recorded",
                finding_id,
                json.dumps(
                    {
                        "decision": decision,
                        "reason": decision_reason,
                        "false_positive_reason": false_positive_reason,
                    }
                ),
            ),
        )
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    if row is None:
        return None
    return dict(row)


def get_finding_status_history(finding_id: str) -> list[dict[str, Any]]:
    """
    Retrieve audit log entries related to a specific finding.

    Returns a list of audit events in chronological order.
    """
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, user_id, action, target, detail
            FROM audit_log
            WHERE target = ?
              AND action IN ('finding_status_changed', 'finding_decision_recorded')
            ORDER BY timestamp ASC
            """,
            (finding_id,),
        ).fetchall()

    result = []
    for row in rows:
        entry = {
            "id": row[0],
            "timestamp": row[1],
            "user_id": row[2],
            "action": row[3],
            "target": row[4],
        }
        try:
            entry["detail"] = json.loads(row[5]) if row[5] else {}
        except (json.JSONDecodeError, TypeError):
            entry["detail"] = {}
        result.append(entry)
    return result
