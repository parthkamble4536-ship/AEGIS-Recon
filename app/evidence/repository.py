"""
Evidence repository for AEGIS-Recon Phase 6.

CRUD operations for the `evidence` table in SQLite.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.db.database import get_db
from app.evidence.models import Evidence, EvidenceSource, EvidenceType

logger = get_logger(__name__)


def create_evidence(evidence: Evidence) -> Evidence:
    """Persist an Evidence record to the database."""
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO evidence (
                evidence_id, finding_id, evidence_type, source,
                source_reference, collected_at, content_hash, description, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.evidence_id,
                evidence.finding_id,
                evidence.evidence_type.value,
                evidence.source.value,
                evidence.source_reference,
                evidence.collected_at,
                evidence.content_hash,
                evidence.description,
                evidence.raw_data,
            ),
        )
    logger.debug("evidence_created", evidence_id=evidence.evidence_id, finding_id=evidence.finding_id)
    return evidence


def get_evidence(evidence_id: str) -> Evidence | None:
    """Retrieve a single Evidence record by ID."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT evidence_id, finding_id, evidence_type, source, source_reference, "
            "collected_at, content_hash, description, raw_data FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()

    if row is None:
        return None
    return _row_to_evidence(row)


def list_evidence_for_finding(finding_id: str) -> list[Evidence]:
    """Return all evidence records for a given finding, oldest first."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT evidence_id, finding_id, evidence_type, source, source_reference, "
            "collected_at, content_hash, description, raw_data "
            "FROM evidence WHERE finding_id = ? ORDER BY collected_at ASC",
            (finding_id,),
        ).fetchall()

    return [_row_to_evidence(row) for row in rows]


def delete_evidence(evidence_id: str) -> bool:
    """Delete an evidence record. Returns True if deleted."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))
    return cursor.rowcount > 0


def _row_to_evidence(row: tuple[Any, ...]) -> Evidence:
    """Convert a DB row tuple to an Evidence dataclass."""
    return Evidence(
        evidence_id=row[0],
        finding_id=row[1],
        evidence_type=EvidenceType(row[2]),
        source=EvidenceSource(row[3]),
        source_reference=row[4] or "",
        collected_at=row[5] or "",
        content_hash=row[6] or "",
        description=row[7] or "",
        raw_data=row[8],
    )
