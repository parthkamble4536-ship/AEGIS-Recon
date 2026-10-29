"""
API endpoints for evidence and provenance (Phase 6).

Routes:
    GET  /api/findings/{finding_id}/evidence   — All evidence for a finding
    POST /api/findings/{finding_id}/evidence   — Add analyst evidence
    GET  /api/findings/{finding_id}/why        — "Why did AEGIS flag this?" explanation
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.logging import get_logger
from app.evidence.models import Evidence, EvidenceSource, EvidenceType
from app.evidence.repository import create_evidence, list_evidence_for_finding
from app.evidence.service import explain_why_flagged

router = APIRouter()
logger = get_logger(__name__)


class EvidenceCreateRequest(BaseModel):
    """Body for POST /api/findings/{id}/evidence (analyst-added evidence)."""

    evidence_type: str
    source: str = "analyst"
    source_reference: str = ""
    description: str
    raw_data: str | None = None


@router.get("/findings/{finding_id}/evidence", tags=["evidence"])
def get_finding_evidence(finding_id: str) -> list[dict[str, Any]]:
    """Return all evidence records for a finding, oldest first."""
    items = list_evidence_for_finding(finding_id)
    return [
        {
            "evidence_id": e.evidence_id,
            "finding_id": e.finding_id,
            "evidence_type": e.evidence_type.value,
            "source": e.source.value,
            "source_reference": e.source_reference,
            "collected_at": e.collected_at,
            "content_hash": e.content_hash,
            "description": e.description,
        }
        for e in items
    ]


@router.post("/findings/{finding_id}/evidence", tags=["evidence"], status_code=201)
def add_finding_evidence(finding_id: str, body: EvidenceCreateRequest) -> dict[str, Any]:
    """Add an analyst-supplied evidence record to a finding."""
    valid_types = {t.value for t in EvidenceType}
    if body.evidence_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid evidence_type {body.evidence_type!r}. Must be one of: {sorted(valid_types)}",
        )

    valid_sources = {s.value for s in EvidenceSource}
    if body.source not in valid_sources:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid source {body.source!r}. Must be one of: {sorted(valid_sources)}",
        )

    import hashlib
    content = f"{body.source}:{finding_id}:{body.description}"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=EvidenceType(body.evidence_type),
        source=EvidenceSource(body.source),
        source_reference=body.source_reference,
        collected_at=now,
        content_hash=content_hash,
        description=body.description,
        raw_data=body.raw_data,
    )

    try:
        created = create_evidence(evidence)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save evidence: {exc}") from exc

    return {
        "evidence_id": created.evidence_id,
        "finding_id": created.finding_id,
        "evidence_type": created.evidence_type.value,
        "source": created.source.value,
        "source_reference": created.source_reference,
        "collected_at": created.collected_at,
        "content_hash": created.content_hash,
        "description": created.description,
    }


@router.get("/findings/{finding_id}/why", tags=["evidence"])
def get_why_flagged(finding_id: str) -> dict[str, Any]:
    """
    Return a human-readable explanation of why AEGIS flagged this finding.

    Shows all evidence sources, their types, and a combined explanation.
    """
    return explain_why_flagged(finding_id)
