"""
Unit tests for database operations.

Uses a temporary SQLite database per test to ensure isolation.
Covers: init, save scan, save parsed data, queries, findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from app.db.database import get_db, init_db, reset_db
from app.db.repository import (
    get_all_scans,
    get_findings_for_scan,
    get_hosts_for_scan,
    get_scan,
    get_services_for_host,
    get_services_for_scan,
    save_finding,
    save_parsed_scan,
    save_scan,
)
from app.parser.nmap_xml import ParsedHost, ParsedScan, ParsedService
from app.scanner.runner import ScanResult


class TestDatabaseInit:
    """Test database initialization."""

    def test_init_creates_tables(self, temp_db: str) -> None:
        with get_db() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            table_names = [t["name"] for t in tables]

        assert "scans" in table_names
        assert "hosts" in table_names
        assert "services" in table_names
        assert "findings" in table_names
        assert "intel_cache" in table_names
        assert "audit_log" in table_names
        assert "reports" in table_names

    def test_init_creates_indexes(self, temp_db: str) -> None:
        with get_db() as conn:
            indexes = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            ).fetchall()
            index_names = [i["name"] for i in indexes]

        assert "idx_hosts_scan_id" in index_names
        assert "idx_services_host_id" in index_names
        assert "idx_findings_cve_id" in index_names

    def test_foreign_keys_enabled(self, temp_db: str) -> None:
        with get_db() as conn:
            result = conn.execute("PRAGMA foreign_keys").fetchone()
            assert result[0] == 1


class TestSaveScan:
    """Test scan CRUD operations."""

    def _make_scan_result(self, scan_id: str = "test-scan-001") -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2023, 10, 12, 12, 0, 35, tzinfo=timezone.utc),
            nmap_version="7.94",
            command_args=["-sS", "-sV", "--top-ports", "100", "192.168.56.101"],
            exit_code=0,
        )

    def test_save_and_retrieve_scan(self, temp_db: str) -> None:
        result = self._make_scan_result()
        save_scan(result)

        scan = get_scan("test-scan-001")
        assert scan is not None
        assert scan["target"] == "192.168.56.101"
        assert scan["profile"] == "quick"
        assert scan["status"] == "completed"
        assert scan["nmap_version"] == "7.94"

    def test_get_nonexistent_scan(self, temp_db: str) -> None:
        scan = get_scan("nonexistent")
        assert scan is None

    def test_get_all_scans(self, temp_db: str) -> None:
        save_scan(self._make_scan_result("scan-1"))
        save_scan(self._make_scan_result("scan-2"))

        scans = get_all_scans()
        assert len(scans) == 2

    def test_get_all_scans_limit(self, temp_db: str) -> None:
        for i in range(5):
            save_scan(self._make_scan_result(f"scan-{i}"))

        scans = get_all_scans(limit=3)
        assert len(scans) == 3


class TestSaveParsedScan:
    """Test saving complete parsed scan data."""

    def _make_parsed_scan(self) -> ParsedScan:
        return ParsedScan(
            scanner="nmap",
            scanner_version="7.94",
            hosts_up=1,
            hosts_down=0,
            hosts_total=1,
            hosts=[
                ParsedHost(
                    ip="192.168.56.101",
                    hostnames=["metasploitable.localdomain"],
                    status="up",
                    os_matches=[{"name": "Linux 2.6", "accuracy": "95"}],
                    services=[
                        ParsedService(
                            port=21,
                            protocol="tcp",
                            state="open",
                            service_name="ftp",
                            product="vsftpd",
                            version="2.3.4",
                            cpe=["cpe:/a:vsftpd:vsftpd:2.3.4"],
                        ),
                        ParsedService(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service_name="ssh",
                            product="OpenSSH",
                            version="4.7p1",
                            cpe=["cpe:/a:openbsd:openssh:4.7p1"],
                        ),
                        ParsedService(
                            port=80,
                            protocol="tcp",
                            state="open",
                            service_name="http",
                            product="Apache httpd",
                            version="2.2.8",
                            cpe=["cpe:/a:apache:http_server:2.2.8"],
                        ),
                    ],
                ),
            ],
        )

    def test_save_parsed_scan(self, temp_db: str) -> None:
        # First save the scan record
        scan_result = ScanResult(
            scan_id="test-parsed-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        )
        save_scan(scan_result)

        # Then save parsed data
        parsed = self._make_parsed_scan()
        summary = save_parsed_scan("test-parsed-001", parsed)

        assert summary["hosts_saved"] == 1
        assert summary["services_saved"] == 3

    def test_hosts_are_queryable(self, temp_db: str) -> None:
        scan_result = ScanResult(
            scan_id="test-hosts-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        )
        save_scan(scan_result)
        save_parsed_scan("test-hosts-001", self._make_parsed_scan())

        hosts = get_hosts_for_scan("test-hosts-001")
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.56.101"
        assert "metasploitable" in hosts[0]["hostnames"]

    def test_services_are_queryable(self, temp_db: str) -> None:
        scan_result = ScanResult(
            scan_id="test-svc-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        )
        save_scan(scan_result)
        save_parsed_scan("test-svc-001", self._make_parsed_scan())

        services = get_services_for_scan("test-svc-001")
        assert len(services) == 3
        ports = [s["port"] for s in services]
        assert 21 in ports
        assert 22 in ports
        assert 80 in ports

    def test_service_details_stored(self, temp_db: str) -> None:
        scan_result = ScanResult(
            scan_id="test-detail-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        )
        save_scan(scan_result)
        save_parsed_scan("test-detail-001", self._make_parsed_scan())

        services = get_services_for_scan("test-detail-001")
        ftp = next(s for s in services if s["port"] == 21)
        assert ftp["service_name"] == "ftp"
        assert ftp["product"] == "vsftpd"
        assert ftp["version"] == "2.3.4"
        cpes = json.loads(ftp["cpe"])
        assert "cpe:/a:vsftpd:vsftpd:2.3.4" in cpes


class TestSaveFinding:
    """Test vulnerability finding storage."""

    def test_save_and_query_finding(self, temp_db: str) -> None:
        # Setup: scan → host → service
        scan_result = ScanResult(
            scan_id="test-finding-001",
            target="192.168.56.101",
            profile="quick",
            status="completed",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        )
        save_scan(scan_result)

        parsed = ParsedScan(
            hosts=[
                ParsedHost(
                    ip="192.168.56.101",
                    status="up",
                    services=[
                        ParsedService(
                            port=21, protocol="tcp", state="open",
                            service_name="ftp", product="vsftpd", version="2.3.4",
                        ),
                    ],
                ),
            ],
        )
        save_parsed_scan("test-finding-001", parsed)

        # Get the service ID
        services = get_services_for_scan("test-finding-001")
        service_id = services[0]["id"]

        # Save a finding
        finding_id = save_finding({
            "service_id": service_id,
            "scan_id": "test-finding-001",
            "cve_id": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 backdoor",
            "description": "vsftpd 2.3.4 downloaded between 2011-06-30 and 2011-07-01 contains a backdoor.",
            "cvss_score": 9.8,
            "severity": "critical",
            "confidence": "high",
            "evidence_type": "external_intelligence",
            "evidence_detail": "Exact version match: vsftpd 2.3.4 matches CVE-2011-2523 affected version.",
            "source": "NVD",
            "is_kev": 0,
            "priority_score": 95.0,
            "priority_factors": ["CVSS 9.8", "Exact version match", "Known backdoor"],
        })

        # Query findings
        findings = get_findings_for_scan("test-finding-001")
        assert len(findings) == 1
        f = findings[0]
        assert f["cve_id"] == "CVE-2011-2523"
        assert f["confidence"] == "high"
        assert f["evidence_type"] == "external_intelligence"
        assert f["cvss_score"] == 9.8
        assert f["ip"] == "192.168.56.101"
        assert f["port"] == 21
