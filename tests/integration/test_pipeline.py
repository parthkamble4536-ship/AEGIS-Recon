"""
Integration test: Full Week 1 pipeline.

Scan (mocked) → Parse XML → Store in DB → Query results.
Tests the complete flow without requiring a real Nmap installation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.db.database import init_db, reset_db
from app.db.repository import (
    get_hosts_for_scan,
    get_scan,
    get_services_for_scan,
    save_parsed_scan,
    save_scan,
)
from app.parser.nmap_xml import parse_nmap_xml
from app.scanner.runner import ScanResult


@pytest.fixture
def integration_db(tmp_path):
    """Fresh DB for integration tests."""
    db_path = str(tmp_path / "integration_test.db")
    init_db(db_path)
    yield db_path
    reset_db()


class TestScanParseStorePipeline:
    """Integration: scanner result → parser → DB → query."""

    def test_full_pipeline_with_metasploitable_fixture(
        self, integration_db: str, metasploitable_xml: str
    ) -> None:
        """
        Simulates: scan returns XML → parse it → store → query everything back.
        This is the core Week 1 acceptance test.
        """
        # Step 1: Simulate a completed scan
        scan_result = ScanResult(
            scan_id="integration-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            xml_output=metasploitable_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2023, 10, 12, 12, 0, 35, tzinfo=UTC),
            nmap_version="7.94",
            command_args=["-sS", "-sV", "--top-ports", "100", "-T4", "--open"],
            exit_code=0,
        )
        save_scan(scan_result)

        # Step 2: Parse the XML output
        parsed = parse_nmap_xml(metasploitable_xml)
        assert len(parsed.hosts) == 1
        assert parsed.hosts_up == 1

        # Step 3: Store parsed data
        summary = save_parsed_scan("integration-001", parsed)
        assert summary["hosts_saved"] == 1
        assert summary["services_saved"] == 10

        # Step 4: Query and verify everything

        # Scan record
        scan = get_scan("integration-001")
        assert scan is not None
        assert scan["target"] == "192.168.56.101"
        assert scan["status"] == "completed"
        assert scan["hosts_up"] == 1

        # Hosts
        hosts = get_hosts_for_scan("integration-001")
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.56.101"
        assert hosts[0]["status"] == "up"

        # Parse stored hostnames
        hostnames = json.loads(hosts[0]["hostnames"])
        assert "metasploitable.localdomain" in hostnames

        # Parse stored OS matches
        os_matches = json.loads(hosts[0]["os_matches"])
        assert len(os_matches) >= 1
        assert "Linux" in os_matches[0]["name"]

        # Services
        services = get_services_for_scan("integration-001")
        assert len(services) == 10

        # Verify specific services
        ports = {s["port"]: s for s in services}

        # FTP
        assert 21 in ports
        assert ports[21]["service_name"] == "ftp"
        assert ports[21]["product"] == "vsftpd"
        assert ports[21]["version"] == "2.3.4"
        ftp_cpes = json.loads(ports[21]["cpe"])
        assert "cpe:/a:vsftpd:vsftpd:2.3.4" in ftp_cpes

        # SSH
        assert 22 in ports
        assert ports[22]["service_name"] == "ssh"
        assert ports[22]["product"] == "OpenSSH"

        # HTTP
        assert 80 in ports
        assert ports[80]["product"] == "Apache httpd"
        assert ports[80]["version"] == "2.2.8"

        # MySQL
        assert 3306 in ports
        assert ports[3306]["product"] == "MySQL"

        # PostgreSQL
        assert 5432 in ports

    def test_empty_scan_pipeline(self, integration_db: str, empty_scan_xml: str) -> None:
        """Test pipeline with a host-down scan (no services)."""
        scan_result = ScanResult(
            scan_id="integration-empty-001",
            target="192.168.56.200",
            profile="quick",
            status="completed",
            xml_output=empty_scan_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2023, 10, 12, 12, 0, 6, tzinfo=UTC),
            exit_code=0,
        )
        save_scan(scan_result)

        parsed = parse_nmap_xml(empty_scan_xml)
        save_parsed_scan("integration-empty-001", parsed)

        # Host was scanned but was down — still stored
        scan = get_scan("integration-empty-001")
        assert scan is not None
        assert scan["hosts_down"] == 1

        services = get_services_for_scan("integration-empty-001")
        assert len(services) == 0

    def test_failed_scan_stored(self, integration_db: str) -> None:
        """Test that a failed scan is still recorded in the DB."""
        scan_result = ScanResult(
            scan_id="integration-fail-001",
            target="192.168.56.101",
            profile="quick",
            status="failed",
            error_message="Host seems down",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2023, 10, 12, 12, 0, 5, tzinfo=UTC),
            exit_code=1,
        )
        save_scan(scan_result)

        scan = get_scan("integration-fail-001")
        assert scan is not None
        assert scan["status"] == "failed"
        assert scan["error_message"] == "Host seems down"

    def test_multiple_scans_independent(self, integration_db: str, metasploitable_xml: str) -> None:
        """Verify two scans don't pollute each other's data."""
        for i in range(2):
            scan_id = f"multi-{i}"
            scan_result = ScanResult(
                scan_id=scan_id,
                target="192.168.56.101",
                profile="quick",
                status="completed",
                start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
                exit_code=0,
            )
            save_scan(scan_result)
            parsed = parse_nmap_xml(metasploitable_xml)
            save_parsed_scan(scan_id, parsed)

        # Each scan should have its own set of hosts/services
        services_0 = get_services_for_scan("multi-0")
        services_1 = get_services_for_scan("multi-1")
        assert len(services_0) == 10
        assert len(services_1) == 10

        # Different service IDs
        ids_0 = {s["id"] for s in services_0}
        ids_1 = {s["id"] for s in services_1}
        assert ids_0.isdisjoint(ids_1)
