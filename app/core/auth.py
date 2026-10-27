"""
API Key authentication for AEGIS-Recon.

Design principles:
- Constant-time comparison via secrets.compare_digest (prevents timing attacks).
- Single shared key loaded from settings (no DB lookup on hot path).
- If API_KEY is not set in .env, auth is DISABLED (local dev convenience).
- Health endpoint is always public — it reveals no sensitive data.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """
    FastAPI dependency — enforces API key authentication.

    Usage:
        @router.post("/scans", dependencies=[Depends(require_api_key)])

    If API_KEY is blank in settings, the check is skipped entirely so
    developers can run without configuration.  Once set, all protected
    endpoints require the exact key in the `X-API-Key` header.
    """
    settings = get_settings()
    configured_key = settings.api_key

    # Auth disabled when no key is configured (local dev mode)
    if not configured_key:
        return

    if x_api_key is None:
        logger.warning("auth_missing_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Constant-time comparison prevents timing oracle attacks
    if not secrets.compare_digest(x_api_key, configured_key):
        logger.warning(
            "auth_invalid_key", partial=x_api_key[:4] + "****" if len(x_api_key) > 4 else "****"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
