"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.db.database import get_connection

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Health check — verifies the API and database are operational."""
    db_ok = False
    try:
        conn = get_connection()
        conn.execute("SELECT 1")
        db_ok = True
    except Exception:
        pass

    return {
        "status": "healthy" if db_ok else "degraded",
        "service": "aegis-recon",
        "version": "1.0.0",
        "database": "connected" if db_ok else "disconnected",
    }
