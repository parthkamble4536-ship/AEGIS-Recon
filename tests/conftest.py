"""
Shared test fixtures for AEGIS-Recon.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.core.validation import Allowlist, AllowlistEntry
from app.db.database import init_db, reset_db


@pytest.fixture
def sample_allowlist() -> Allowlist:
    """An allowlist with typical lab targets."""
    return Allowlist(
        entries=[
            AllowlistEntry("ip", "192.168.56.101", "Metasploitable 2"),
            AllowlistEntry("ip", "192.168.56.102", "Secondary target"),
            AllowlistEntry("hostname", "dvwa.local", "DVWA container"),
        ],
        allowed_profiles=["quick", "standard", "thorough"],
        max_concurrent_scans=2,
    )


@pytest.fixture
def allowlist_with_cidr() -> Allowlist:
    """An allowlist that includes a CIDR range."""
    import ipaddress

    return Allowlist(
        entries=[
            AllowlistEntry("ip", "192.168.56.101", "Metasploitable 2"),
            AllowlistEntry(
                "cidr",
                "10.0.0.0/24",
                "Lab subnet",
                network=ipaddress.ip_network("10.0.0.0/24"),
            ),
        ],
        allowed_profiles=["quick", "standard"],
    )


@pytest.fixture
def empty_allowlist() -> Allowlist:
    """An allowlist with no entries."""
    return Allowlist(entries=[], allowed_profiles=["quick"])


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def metasploitable_xml(fixtures_dir: Path) -> str:
    """Raw XML content from the Metasploitable 2 scan fixture."""
    return (fixtures_dir / "metasploitable2_scan.xml").read_text(encoding="utf-8")


@pytest.fixture
def empty_scan_xml(fixtures_dir: Path) -> str:
    """Raw XML content from the empty/host-down scan fixture."""
    return (fixtures_dir / "empty_scan.xml").read_text(encoding="utf-8")


@pytest.fixture
def temp_db():
    """
    Initialize a temporary SQLite database for testing.
    Cleans up after the test.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        init_db(db_path)
        yield db_path
        reset_db()
