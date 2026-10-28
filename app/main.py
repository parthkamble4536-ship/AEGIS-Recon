"""
FastAPI application factory for AEGIS-Recon.

Creates and configures the FastAPI app with:
- API routers (scans, findings, reports, health)
- Static file serving for the dashboard
- CORS for local development
- Startup/shutdown events for DB init
- Exception handlers for typed errors
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from app.config import get_settings
from app.core.errors import (
    AegisError,
    AllowlistError,
    DatabaseError,
    IntelError,
    ScannerError,
    ValidationError,
)
from app.core.logging import get_logger, setup_logging
from app.db.database import close_db, init_db

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """App startup and shutdown events."""
    settings = get_settings()
    setup_logging(settings.log_level)
    init_db(settings.database_path)
    logger.info("app_started", host=settings.api_host, port=settings.api_port)
    yield
    close_db()
    logger.info("app_stopped")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    get_settings()

    app = FastAPI(
        title="AEGIS-Recon",
        description="Evidence-based reconnaissance and vulnerability intelligence API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ── Security Headers Middleware ────────────────────────────────────────
    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        """Add OWASP-recommended security headers to every response."""

        async def dispatch(self, request: Request, call_next: Any) -> StarletteResponse:
            response: StarletteResponse = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = (
                "0"  # Deprecated but harmless; CSP is the real guard
            )
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
                "connect-src 'self';"
            )
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

    app.add_middleware(SecurityHeadersMiddleware)

    # CORS — local dev only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    # Register API routers
    from app.api.findings import router as findings_router
    from app.api.health import router as health_router
    from app.api.reports import router as reports_router
    from app.api.scans import router as scans_router

    app.include_router(health_router, prefix="/api", tags=["health"])
    app.include_router(scans_router, prefix="/api", tags=["scans"])
    app.include_router(findings_router, prefix="/api", tags=["findings"])
    app.include_router(reports_router, prefix="/api", tags=["reports"])

    # Serve dashboard static files
    web_dir = Path(__file__).parent.parent / "web"
    if web_dir.exists():
        app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="dashboard")

    # Exception handlers
    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(AllowlistError)
    async def allowlist_error_handler(request: Request, exc: AllowlistError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error": "not_authorized",
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(ScannerError)
    async def scanner_error_handler(request: Request, exc: ScannerError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "scanner_error",
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(IntelError)
    async def intel_error_handler(request: Request, exc: IntelError) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={
                "error": "intel_error",
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(DatabaseError)
    async def database_error_handler(request: Request, exc: DatabaseError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "database_error",
                "message": exc.message,
            },
        )

    @app.exception_handler(AegisError)
    async def aegis_error_handler(request: Request, exc: AegisError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": exc.message,
            },
        )

    return app


# App instance for uvicorn
app = create_app()
