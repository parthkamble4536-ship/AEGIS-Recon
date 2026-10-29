"""
Remediation guidance repository for AEGIS-Recon Phase 7.

Updates remediation fields on findings.
Sources must be trusted references only — NEVER AI-fabricated text.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.db.database import get_db

logger = get_logger(__name__)


def update_finding_remediation(
    finding_id: str,
    vendor: str = "",
    fixed_version: str = "",
    advisory_url: str = "",
    recommended_action: str = "",
    updated_by: str = "analyst",
) -> dict[str, Any] | None:
    """
    Update the remediation guidance fields for a finding.

    All remediation data must come from trusted sources
    (vendor advisories, NVD references, CISA KEV).
    Never pass AI-generated text directly into these fields.

    Args:
        finding_id: UUID of the finding.
        vendor: Vendor providing the fix.
        fixed_version: Version that resolves the vulnerability.
        advisory_url: URL to the official security advisory.
        recommended_action: Human-readable remediation action.
        updated_by: Who is setting the remediation info.

    Returns:
        Updated finding dict as a plain dict, or None if not found.
    """
    with get_db() as conn:
        cursor = conn.execute(
            """UPDATE findings
               SET remediation_vendor = ?,
                   remediation_fixed_version = ?,
                   remediation_advisory_url = ?,
                   remediation_recommended_action = ?
               WHERE id = ?""",
            (vendor or None, fixed_version or None, advisory_url or None,
             recommended_action or None, finding_id),
        )
        if cursor.rowcount == 0:
            return None

        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    if row is None:
        return None

    logger.info("remediation_updated", finding_id=finding_id, updated_by=updated_by)
    return dict(row)
