"""
In-memory sliding-window rate limiter for AEGIS-Recon.

Design:
- Sliding-window per client IP.
- Separate limits for scan creation (expensive) vs read endpoints (cheap).
- Thread-safe using a simple dict with timestamps; suitable for single-process
  deployments.  For multi-process, replace with a Redis backend.
- Returns standard HTTP 429 with Retry-After header.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.core.logging import get_logger

logger = get_logger(__name__)


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter keyed by client IP."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # ip -> deque of timestamps (float, seconds since epoch)
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, client_ip: str) -> tuple[bool, int]:
        """
        Check if the request is within rate limit.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        window = self._windows[client_ip]

        # Evict expired timestamps
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - window[0])) + 1
            return False, retry_after

        window.append(now)
        return True, 0


# Global limiter instances
# Scan creation: max 10 scans per 60-second window per IP
_scan_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)

# General API reads: max 120 requests per 60-second window per IP
_api_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For if present."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the leftmost (original client) IP
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def limit_scan_rate(request: Request) -> None:
    """
    FastAPI dependency for scan creation endpoints.
    Max 10 scans per 60 seconds per client IP.
    """
    ip = _get_client_ip(request)
    allowed, retry_after = _scan_limiter.is_allowed(ip)
    if not allowed:
        logger.warning(
            "rate_limit_exceeded", endpoint="scan", client_ip=ip, retry_after=retry_after
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


def limit_api_rate(request: Request) -> None:
    """
    FastAPI dependency for general read endpoints.
    Max 120 requests per 60 seconds per client IP.
    """
    ip = _get_client_ip(request)
    allowed, retry_after = _api_limiter.is_allowed(ip)
    if not allowed:
        logger.warning("rate_limit_exceeded", endpoint="api", client_ip=ip, retry_after=retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
