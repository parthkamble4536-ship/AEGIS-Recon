"""
Intelligence cache for AEGIS-Recon.

Caches NVD and KEV API responses in the intel_cache DB table
to reduce external API calls and enable offline operation.

Design:
- Cache key is source + query parameter (e.g., "nvd:cpe:/a:apache:http_server:2.2.8").
- TTL-based expiry (configurable per source).
- Stale data is served with a warning rather than making a failed request.
- Cache can be queried to check freshness for reproducibility metadata.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.logging import get_logger
from app.db.database import get_db

logger = get_logger(__name__)


def cache_get(cache_key: str) -> str | None:
    """
    Retrieve a cached response if it exists and hasn't expired.

    Args:
        cache_key: Cache key (e.g., "nvd:cpe:/a:apache:http_server:2.2.8").

    Returns:
        Cached JSON string, or None if not found or expired.
    """
    now = datetime.now(UTC).isoformat()

    with get_db() as conn:
        row = conn.execute(
            "SELECT response_data, fetched_at, expires_at FROM intel_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()

    if row is None:
        return None

    if row["expires_at"] < now:
        logger.debug("cache_expired", key=cache_key)
        return None

    logger.debug("cache_hit", key=cache_key, fetched_at=row["fetched_at"])
    return row["response_data"]


def cache_get_stale(cache_key: str) -> tuple[str | None, str | None]:
    """
    Retrieve cached response even if expired (for fallback).

    Returns:
        Tuple of (response_data, fetched_at) or (None, None).
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT response_data, fetched_at FROM intel_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()

    if row is None:
        return None, None

    return row["response_data"], row["fetched_at"]


def cache_set(
    cache_key: str,
    source: str,
    response_data: str,
    ttl_seconds: int,
) -> None:
    """
    Store a response in the cache.

    Args:
        cache_key: Cache key.
        source: Source identifier ("nvd", "kev").
        response_data: JSON string to cache.
        ttl_seconds: Time-to-live in seconds.
    """
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=ttl_seconds)

    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO intel_cache (cache_key, source, response_data, fetched_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                cache_key,
                source,
                response_data,
                now.isoformat(),
                expires.isoformat(),
            ),
        )

    logger.debug("cache_set", key=cache_key, ttl=ttl_seconds)


def cache_clear_expired() -> int:
    """
    Remove all expired cache entries.

    Returns:
        Number of entries removed.
    """
    now = datetime.now(UTC).isoformat()

    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM intel_cache WHERE expires_at < ?",
            (now,),
        )
        count = cursor.rowcount

    if count > 0:
        logger.info("cache_cleared_expired", removed=count)

    return count


def get_cache_timestamp(cache_key: str) -> str | None:
    """
    Get the retrieval timestamp for a cached entry (for reproducibility).

    Returns:
        ISO timestamp string or None.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT fetched_at FROM intel_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()

    return row["fetched_at"] if row else None
