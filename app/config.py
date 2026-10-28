"""
AEGIS-Recon application settings.

All configuration is loaded from environment variables (via .env file).
Secrets never have default values — they must be explicitly set.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _detect_default_nmap_path() -> str:
    """Auto-detect Nmap on Windows if installed in default directories."""
    if os.name == "nt":
        for path in (
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ):
            if os.path.isfile(path):
                return path
    return "nmap"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── General ──────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ── Nmap ─────────────────────────────────────────────
    nmap_path: str = Field(default_factory=_detect_default_nmap_path)
    nmap_timeout: int = Field(default=300, ge=10, le=3600)

    # ── Database ─────────────────────────────────────────
    database_path: str = "data/aegis_recon.db"

    # ── Allowlist ────────────────────────────────────────
    allowlist_path: str = "config/allowlist.yaml"

    # ── NVD API ──────────────────────────────────────────
    nvd_api_key: str = ""
    nvd_rate_limit: int = Field(default=5, ge=1, le=50)
    nvd_cache_ttl: int = Field(default=86400, ge=60)

    # ── CISA KEV ─────────────────────────────────────────
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
    )
    kev_cache_ttl: int = Field(default=3600, ge=60)

    # ── AI / LLM ─────────────────────────────────────────
    ai_enabled: bool = False
    ai_provider: Literal["gemini", "anthropic", "none"] = "none"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"
    anthropic_api_key: str = ""
    ai_max_tokens: int = Field(default=1024, ge=64, le=4096)
    ai_temperature: float = Field(default=0.2, ge=0.0, le=1.0)

    # ── API Server ───────────────────────────────────────
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1024, le=65535)

    # ── Authentication ───────────────────────────────────
    # Leave blank to disable auth (local dev mode).
    # Set a strong random value in production (e.g., `python -c "import secrets; print(secrets.token_hex(32))"`)
    api_key: str = ""

    @field_validator("nmap_path")
    @classmethod
    def validate_nmap_path(cls, v: str) -> str:
        """Ensure nmap_path is not empty and doesn't contain shell metacharacters."""
        if not v.strip():
            raise ValueError("nmap_path must not be empty")
        # Block shell injection in the configured nmap path itself
        dangerous = set(";|<>&`$\n\r")
        if any(c in v for c in dangerous):
            raise ValueError("nmap_path contains dangerous characters")
        return v.strip()

    @property
    def database_path_resolved(self) -> Path:
        """Return the database path as a resolved Path object."""
        return Path(self.database_path).resolve()

    @property
    def allowlist_path_resolved(self) -> Path:
        """Return the allowlist path as a resolved Path object."""
        return Path(self.allowlist_path).resolve()


# Singleton — import this wherever settings are needed
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset settings singleton (for testing)."""
    global _settings
    _settings = None
