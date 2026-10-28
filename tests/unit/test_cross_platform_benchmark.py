"""
Cross-Platform Evaluation & Benchmarking Tests.

Empirically validates AEGIS-Recon across multiple distinct target environments:
1. Metasploitable 2 (Ubuntu 8.04 Linux 2.6 Baseline)
2. Metasploitable 3 Windows (Windows Server 2016 Enterprise Stack)
3. Metasploitable 3 Linux (Ubuntu 14.04 Web / Middleware Stack)
4. VulnHub Kioptrix Level 1 (RedHat Linux CTF / Hardened Target)

Proves:
- Ground-truth parsing recall across diverse operating systems
- Windows CPE vs. Linux CPE normalization
- 6-Factor risk scoring and CISA KEV prioritization differentiation
- Pipeline throughput and processing latency
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from app.db.database import init_db, reset_db
from app.db.repository import save_parsed_scan, save_scan
from app.parser.nmap_xml import parse_nmap_xml
from app.risk.scoring import calculate_risk
from app.scanner.runner import ScanResult

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def benchmark_db(tmp_path: Any) -> Any:
    """Isolated SQLite database for benchmark execution."""
    db_path = str(tmp_path / "benchmark.db")
    init_db(db_path)
    yield db_path
    reset_db()


class TestCrossPlatformParsing:
    """Verify ground-truth XML parsing across all target OS families."""

    def test_metasploitable2_parsing(self) -> None:
        xml = (FIXTURES_DIR / "metasploitable2_scan.xml").read_text(encoding="utf-8")
        parsed = parse_nmap_xml(xml)
        assert parsed.hosts_up == 1
        services = parsed.hosts[0].services
        assert len(services) == 10
        # Check classic legacy daemons
        ports = {s.port for s in services}
        assert {21, 22, 23, 25, 80, 139, 445, 3306, 5432, 8080}.issubset(ports)

    def test_metasploitable3_windows_parsing(self) -> None:
        xml = (FIXTURES_DIR / "metasploitable3_win_scan.xml").read_text(encoding="utf-8")
        parsed = parse_nmap_xml(xml)
        assert parsed.hosts_up == 1
        services = parsed.hosts[0].services
        assert len(services) == 11

        # Check enterprise Windows stack
        port_to_service = {s.port: s for s in services}
        assert port_to_service[80].product == "Microsoft IIS httpd"
        assert port_to_service[445].product.startswith("Windows Server 2016")
        assert port_to_service[8484].product == "Jenkins"
        assert port_to_service[9200].product == "Elasticsearch REST API"

        # Check Windows CPE normalization
        iis_cpes = port_to_service[80].cpe
        assert any("cpe:/a:microsoft:internet_information_server" in c for c in iis_cpes)
        smb_cpes = port_to_service[445].cpe
        assert any("cpe:/o:microsoft:windows_server_2016" in c for c in smb_cpes)

    def test_metasploitable3_linux_parsing(self) -> None:
        xml = (FIXTURES_DIR / "metasploitable3_linux_scan.xml").read_text(encoding="utf-8")
        parsed = parse_nmap_xml(xml)
        assert parsed.hosts_up == 1
        services = parsed.hosts[0].services
        assert len(services) == 9

        # Check Linux Web/Middleware stack
        port_to_service = {s.port: s for s in services}
        assert port_to_service[21].product == "ProFTPD"
        assert port_to_service[631].product == "CUPS"
        assert port_to_service[6697].product == "UnrealIRCd"

    def test_kioptrix_parsing(self) -> None:
        xml = (FIXTURES_DIR / "kioptrix_scan.xml").read_text(encoding="utf-8")
        parsed = parse_nmap_xml(xml)
        assert parsed.hosts_up == 1
        services = parsed.hosts[0].services
        assert len(services) == 6

        # Check CTF / non-standard ports
        port_to_service = {s.port: s for s in services}
        assert port_to_service[80].product == "Apache httpd"
        assert "mod_ssl/2.8.4" in port_to_service[80].extra_info
        assert port_to_service[139].product == "Samba smbd"
        assert port_to_service[1024].product == "Linux rpc.statd"


class TestCrossPlatformPipelineAndRiskScoring:
    """End-to-end pipeline ingestion and 6-factor risk scoring across targets."""

    def test_pipeline_ingest_all_targets(self, benchmark_db: Any) -> None:
        start_time = time.perf_counter()

        targets = [
            ("metasploitable2_scan.xml", "192.168.56.101", "bench-m2"),
            ("metasploitable3_win_scan.xml", "192.168.56.102", "bench-m3w"),
            ("metasploitable3_linux_scan.xml", "192.168.56.103", "bench-m3l"),
            ("kioptrix_scan.xml", "192.168.56.104", "bench-kioptrix"),
        ]

        total_services = 0
        for xml_file, ip, scan_id in targets:
            xml = (FIXTURES_DIR / xml_file).read_text(encoding="utf-8")
            parsed = parse_nmap_xml(xml)

            scan_result = ScanResult(
                scan_id=scan_id,
                target=ip,
                profile="standard",
                status="completed",
                xml_output=xml,
            )
            save_scan(scan_result)
            summary = save_parsed_scan(scan_id, parsed)
            total_services += summary["services_saved"]

        elapsed = time.perf_counter() - start_time

        # All 4 environments (36 services) ingested in under 2 seconds
        assert total_services == 36
        assert elapsed < 2.0

    def test_cisa_kev_prioritization_across_targets(self) -> None:
        """Verify that CISA KEV vulnerabilities receive higher priority scores."""
        # 1. Metasploitable 3 Windows: MS17-010 EternalBlue (KEV) vs. GlassFish Path Traversal (Non-KEV)
        eternal_blue = calculate_risk(
            cvss_score=9.8,
            cvss_severity="critical",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            service_name="microsoft-ds",
            port=445,
        )

        glassfish_traversal = calculate_risk(
            cvss_score=7.5,
            cvss_severity="high",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=False,
            service_name="http",
            port=4848,
        )

        assert eternal_blue.priority_score > glassfish_traversal.priority_score
        assert eternal_blue.priority_score >= 80.0

        # 2. Kioptrix: Samba trans2open (KEV) vs OpenSSH AFS overflow (Non-KEV)
        samba_trans2open = calculate_risk(
            cvss_score=10.0,
            cvss_severity="critical",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            service_name="netbios-ssn",
            port=139,
        )

        openssh_overflow = calculate_risk(
            cvss_score=7.5,
            cvss_severity="high",
            confidence="medium",
            evidence_type="hypothesis",
            is_kev=False,
            service_name="ssh",
            port=22,
        )

        assert samba_trans2open.priority_score > openssh_overflow.priority_score
        assert samba_trans2open.priority_score >= 80.0
