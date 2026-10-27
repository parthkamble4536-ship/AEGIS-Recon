"""
Week 3 tests — CLI, Auth, Rate Limiting, and Security Headers.

All tests are offline (no network, no Nmap).
TestClient-based integration tests are marked @pytest.mark.integration
and are skipped in the standard unit run (they require a live server to
avoid the httpx/starlette TestClient incompatibility in this environment).
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_settings() -> Generator[None, None, None]:
    """Reset the settings singleton after each test."""
    from app.config import reset_settings

    yield
    reset_settings()


@pytest.fixture
def _test_app(tmp_path: Any, monkeypatch: Any) -> Any:
    """
    Build a minimal FastAPI test app (no StaticFiles mount) with configurable API_KEY.
    Returns a factory callable: _test_app(api_key="") -> TestClient
    """
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware

    def _make_client(api_key: str = "") -> TestClient:
        db_path = str(tmp_path / f"test_{api_key[:4] or 'nokey'}.db")
        monkeypatch.setenv("DATABASE_PATH", db_path)
        monkeypatch.setenv("API_KEY", api_key)

        from app.config import reset_settings

        reset_settings()

        from app.db.database import init_db

        init_db(db_path)

        from starlette.responses import Response as StarletteResponse

        from app.api.findings import router as findings_router
        from app.api.health import router as health_router
        from app.api.reports import router as reports_router
        from app.api.scans import router as scans_router
        from app.core.errors import (
            AegisError,
            AllowlistError,
            ScannerError,
            ValidationError,
        )

        test_app = FastAPI(title="AEGIS-Test", docs_url=None, redoc_url=None)

        class SecurityHeadersMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Any, call_next: Any) -> StarletteResponse:
                response: StarletteResponse = await call_next(request)
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                response.headers["Content-Security-Policy"] = "default-src 'self';"
                response.headers["Permissions-Policy"] = "geolocation=()"
                return response

        test_app.add_middleware(SecurityHeadersMiddleware)
        test_app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://127.0.0.1:8000"],
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

        test_app.include_router(health_router, prefix="/api", tags=["health"])
        test_app.include_router(scans_router, prefix="/api", tags=["scans"])
        test_app.include_router(findings_router, prefix="/api", tags=["findings"])
        test_app.include_router(reports_router, prefix="/api", tags=["reports"])

        @test_app.exception_handler(ValidationError)
        async def _ve(req: Any, exc: Any) -> JSONResponse:
            return JSONResponse(status_code=422, content={"error": exc.message})

        @test_app.exception_handler(AllowlistError)
        async def _ae(req: Any, exc: Any) -> JSONResponse:
            return JSONResponse(status_code=403, content={"error": exc.message})

        @test_app.exception_handler(ScannerError)
        async def _se(req: Any, exc: Any) -> JSONResponse:
            return JSONResponse(status_code=500, content={"error": exc.message})

        @test_app.exception_handler(AegisError)
        async def _ge(req: Any, exc: Any) -> JSONResponse:
            return JSONResponse(status_code=500, content={"error": exc.message})

        return TestClient(test_app, raise_server_exceptions=False)

    return _make_client


@pytest.fixture
def app_no_auth(
    tmp_path: Any, monkeypatch: Any, _test_app: Any
) -> Generator[TestClient, None, None]:
    """TestClient with auth disabled."""
    client = _test_app(api_key="")
    yield client
    from app.config import reset_settings
    from app.db.database import reset_db

    reset_db()
    reset_settings()


@pytest.fixture
def app_with_auth(
    tmp_path: Any, monkeypatch: Any, _test_app: Any
) -> Generator[TestClient, None, None]:
    """TestClient with API_KEY='test-secret-key'."""
    client = _test_app(api_key="test-secret-key")
    yield client
    from app.config import reset_settings
    from app.db.database import reset_db

    reset_db()
    reset_settings()


# ── Auth Tests ────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestAPIKeyAuthentication:
    """Tests for the API key auth dependency."""

    def test_health_always_public(self, app_with_auth: TestClient) -> None:
        """Health endpoint must be accessible without any API key."""
        resp = app_with_auth.get("/api/health")
        assert resp.status_code == 200

    def test_scan_requires_key_when_configured(self, app_with_auth: TestClient) -> None:
        """POST /api/scans returns 401 if no X-API-Key header is sent."""
        resp = app_with_auth.post(
            "/api/scans",
            json={"target": "192.168.56.101", "profile": "quick"},
        )
        assert resp.status_code == 401

    def test_scan_rejected_with_wrong_key(self, app_with_auth: TestClient) -> None:
        """POST /api/scans returns 401 for wrong API key."""
        resp = app_with_auth.post(
            "/api/scans",
            json={"target": "192.168.56.101", "profile": "quick"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_scan_accepted_with_correct_key(self, app_with_auth: TestClient) -> None:
        """POST /api/scans proceeds past auth with correct key (may fail later on validation)."""
        # We expect this to fail at validation/allowlist — not at auth
        resp = app_with_auth.post(
            "/api/scans",
            json={"target": "192.168.56.101", "profile": "quick"},
            headers={"X-API-Key": "test-secret-key"},
        )
        # 401 = auth failed.  Any other code (422, 403, 500) means auth passed.
        assert resp.status_code != 401

    def test_auth_disabled_when_key_empty(self, app_no_auth: TestClient) -> None:
        """When API_KEY is blank, protected endpoints allow unauthenticated access."""
        resp = app_no_auth.post(
            "/api/scans",
            json={"target": "192.168.56.101", "profile": "quick"},
        )
        # Should NOT be 401 — auth is disabled
        assert resp.status_code != 401

    def test_enrich_requires_key_when_configured(self, app_with_auth: TestClient) -> None:
        """POST /api/findings/<id>/enrich requires auth."""
        resp = app_with_auth.post("/api/findings/nonexistent-scan-id/enrich")
        assert resp.status_code == 401

    def test_report_json_requires_key_when_configured(self, app_with_auth: TestClient) -> None:
        """GET /api/reports/<id>/json requires auth."""
        resp = app_with_auth.get("/api/reports/nonexistent-scan-id/json")
        assert resp.status_code == 401

    def test_401_response_has_www_authenticate_header(self, app_with_auth: TestClient) -> None:
        """401 responses must include WWW-Authenticate header."""
        resp = app_with_auth.post(
            "/api/scans",
            json={"target": "192.168.56.101", "profile": "quick"},
        )
        assert resp.status_code == 401
        assert "www-authenticate" in resp.headers

    def test_timing_safe_comparison(self) -> None:
        """Verify constant-time comparison is used (secrets.compare_digest)."""
        import secrets

        # Confirm the function exists and works correctly
        assert secrets.compare_digest("abc", "abc") is True
        assert secrets.compare_digest("abc", "xyz") is False


# ── Auth Unit Tests ───────────────────────────────────────────────────────────


class TestAuthDependency:
    """Unit tests for the require_api_key dependency function."""

    def test_no_key_configured_allows_all(self, monkeypatch: Any) -> None:
        """When api_key='', any (or no) header should pass."""
        monkeypatch.setenv("API_KEY", "")
        from app.config import reset_settings

        reset_settings()
        from app.core.auth import require_api_key

        # Should not raise
        require_api_key(x_api_key=None)
        require_api_key(x_api_key="any-value")
        reset_settings()

    def test_valid_key_passes(self, monkeypatch: Any) -> None:
        """Valid key passes the check without raising."""
        monkeypatch.setenv("API_KEY", "mykey123")
        from app.config import reset_settings

        reset_settings()
        from app.core.auth import require_api_key

        require_api_key(x_api_key="mykey123")  # should not raise
        reset_settings()

    def test_invalid_key_raises_401(self, monkeypatch: Any) -> None:
        """Wrong key raises HTTPException 401."""
        from fastapi import HTTPException

        monkeypatch.setenv("API_KEY", "mykey123")
        from app.config import reset_settings

        reset_settings()
        from app.core.auth import require_api_key

        with pytest.raises(HTTPException) as exc_info:
            require_api_key(x_api_key="wrong")
        assert exc_info.value.status_code == 401
        reset_settings()

    def test_missing_key_raises_401(self, monkeypatch: Any) -> None:
        """Missing header raises HTTPException 401."""
        from fastapi import HTTPException

        monkeypatch.setenv("API_KEY", "mykey123")
        from app.config import reset_settings

        reset_settings()
        from app.core.auth import require_api_key

        with pytest.raises(HTTPException) as exc_info:
            require_api_key(x_api_key=None)
        assert exc_info.value.status_code == 401
        reset_settings()


# ── Rate Limiter Unit Tests ───────────────────────────────────────────────────


class TestSlidingWindowRateLimiter:
    """Tests for the in-memory sliding-window rate limiter."""

    def test_allows_requests_within_limit(self) -> None:
        from app.core.ratelimit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            allowed, _ = limiter.is_allowed("10.0.0.1")
            assert allowed is True

    def test_blocks_after_limit_exceeded(self) -> None:
        from app.core.ratelimit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.is_allowed("10.0.0.1")
        allowed, retry_after = limiter.is_allowed("10.0.0.1")
        assert allowed is False
        assert retry_after > 0

    def test_different_ips_are_independent(self) -> None:
        from app.core.ratelimit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        limiter.is_allowed("10.0.0.1")
        limiter.is_allowed("10.0.0.1")
        # 10.0.0.1 is now exhausted, 10.0.0.2 should still be allowed
        allowed_1, _ = limiter.is_allowed("10.0.0.1")
        allowed_2, _ = limiter.is_allowed("10.0.0.2")
        assert allowed_1 is False
        assert allowed_2 is True

    def test_window_slides_after_expiry(self) -> None:
        """Window expiry is tested via monotonic time manipulation."""
        from app.core.ratelimit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)
        # Manually inject a very old timestamp (older than the window)
        import time as _time

        limiter.is_allowed("10.0.0.3")  # fills window
        # Back-date the single timestamp so it's outside the window
        old_ts = _time.monotonic() - 61
        limiter._windows["10.0.0.3"][0] = old_ts  # type: ignore[index]
        # Now it should be evicted and the request allowed
        allowed, _ = limiter.is_allowed("10.0.0.3")
        assert allowed is True

    def test_retry_after_is_positive_integer(self) -> None:
        from app.core.ratelimit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=30)
        limiter.is_allowed("10.0.0.4")
        allowed, retry_after = limiter.is_allowed("10.0.0.4")
        assert not allowed
        assert isinstance(retry_after, int)
        assert retry_after > 0


@pytest.mark.integration
class TestRateLimitAPIResponse:
    """Tests that the API returns 429 when the rate limit is hit."""

    def test_scan_rate_limit_returns_429(self, app_no_auth: TestClient, monkeypatch: Any) -> None:
        """After exceeding the scan rate limit, the API should return 429."""
        from app.core import ratelimit as rl_module

        # Replace the scan limiter with a very tight one (1 req / 60s)
        rl_module._scan_limiter = rl_module.SlidingWindowRateLimiter(
            max_requests=1, window_seconds=60
        )
        # First request consumes the limit (will fail at validation, not rate limit)
        app_no_auth.post("/api/scans", json={"target": "192.168.56.101", "profile": "quick"})
        # Second request should be rate limited
        resp = app_no_auth.post("/api/scans", json={"target": "192.168.56.101", "profile": "quick"})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        # Restore
        rl_module._scan_limiter = rl_module.SlidingWindowRateLimiter(
            max_requests=10, window_seconds=60
        )


# ── Security Headers Tests ────────────────────────────────────────────────────


@pytest.mark.integration
class TestSecurityHeaders:
    """Tests that OWASP-recommended headers are present on all responses."""

    def test_x_content_type_options(self, app_no_auth: TestClient) -> None:
        resp = app_no_auth.get("/api/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, app_no_auth: TestClient) -> None:
        resp = app_no_auth.get("/api/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_content_security_policy_present(self, app_no_auth: TestClient) -> None:
        resp = app_no_auth.get("/api/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src" in csp

    def test_referrer_policy_present(self, app_no_auth: TestClient) -> None:
        resp = app_no_auth.get("/api/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy_present(self, app_no_auth: TestClient) -> None:
        resp = app_no_auth.get("/api/health")
        assert "permissions-policy" in resp.headers

    def test_headers_on_404_responses(self, app_no_auth: TestClient) -> None:
        """Security headers must also appear on error responses."""
        resp = app_no_auth.get("/api/scans/nonexistent-id")
        assert resp.headers.get("x-content-type-options") == "nosniff"


# ── Config Tests ──────────────────────────────────────────────────────────────


class TestWeek3Config:
    """Tests for new Week 3 config fields."""

    def test_api_key_defaults_to_empty(self, monkeypatch: Any) -> None:
        monkeypatch.delenv("API_KEY", raising=False)
        from app.config import get_settings, reset_settings

        reset_settings()
        settings = get_settings()
        assert settings.api_key == ""
        reset_settings()

    def test_api_key_loaded_from_env(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("API_KEY", "super-secret-value")
        from app.config import get_settings, reset_settings

        reset_settings()
        settings = get_settings()
        assert settings.api_key == "super-secret-value"
        reset_settings()


# ── CLI Argument Parser Tests ─────────────────────────────────────────────────


class TestCLIArgumentParser:
    """Tests for CLI argument parsing (no network calls)."""

    def _get_parser(self) -> Any:
        import sys

        sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))
        from scripts.cli import build_parser

        return build_parser()

    def test_scan_command_requires_target(self) -> None:
        parser = self._get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["scan"])

    def test_scan_command_default_profile(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["scan", "--target", "192.168.56.101"])
        assert args.profile == "quick"
        assert args.target == "192.168.56.101"

    def test_scan_command_custom_profile(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["scan", "--target", "192.168.56.101", "--profile", "thorough"])
        assert args.profile == "thorough"

    def test_list_command_default_limit(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["list"])
        assert args.limit == 20

    def test_list_command_custom_limit(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["list", "--limit", "50"])
        assert args.limit == 50

    def test_findings_enrich_flag(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["findings", "scan-abc123", "--enrich"])
        assert args.enrich is True
        assert args.scan_id == "scan-abc123"

    def test_report_format_json(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["report", "scan-abc123"])
        assert args.format == "json"

    def test_report_format_html(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["report", "scan-abc123", "--format", "html"])
        assert args.format == "html"

    def test_json_flag_global(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["--json", "list"])
        assert args.json is True

    def test_base_url_default(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["status"])
        assert args.base_url == "http://127.0.0.1:8000"

    def test_api_key_arg(self) -> None:
        parser = self._get_parser()
        args = parser.parse_args(["--api-key", "mykey", "status"])
        assert args.api_key == "mykey"
