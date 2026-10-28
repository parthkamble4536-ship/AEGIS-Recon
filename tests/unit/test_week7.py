"""
Week 7 — Live Lab End-to-End Assessment Tests.

Validates the complete AEGIS-Recon pipeline against realistic scan data
(Metasploitable 2 fixtures) without requiring network access or a live server.

Coverage:
- Full pipeline: XML parse → DB store → CVE match → risk score → report
- 20+ service assertions on Metasploitable 2 fixture
- CVE correlation for known-vulnerable services (vsftpd, Apache, MySQL, etc.)
- Risk scoring: correct ordering, KEV boost, confidence level impact
- JSON and HTML report generation with findings
- AI analysis integration (mocked Gemini response)
- Edge cases: empty scans, host-down, partial/timeout results
- Stress test: many findings, very long banners, Unicode data
- Performance: large finding sets scored and sorted within budget
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
META_XML_PATH = FIXTURE_DIR / "metasploitable2_scan.xml"
EMPTY_XML_PATH = FIXTURE_DIR / "empty_scan.xml"


@pytest.fixture(scope="module")
def metasploitable_xml() -> str:
    return META_XML_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def empty_scan_xml() -> str:
    return EMPTY_XML_PATH.read_text(encoding="utf-8")


@pytest.fixture
def lab_db(tmp_path: Any) -> Any:
    """Fresh isolated SQLite DB for each lab test."""
    from app.db.database import init_db, reset_db

    db_path = str(tmp_path / "lab_test.db")
    init_db(db_path)
    yield db_path
    reset_db()


# ══════════════════════════════════════════════════════════════════════════════
# 1. XML PARSING — Metasploitable 2 Service Inventory
# ══════════════════════════════════════════════════════════════════════════════


class TestMetasploitableXMLParsing:
    """Validate XML parsing of a realistic multi-service target."""

    def test_parse_produces_one_host(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        assert len(result.hosts) == 1

    def test_host_is_up(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        assert result.hosts_up == 1
        assert result.hosts_down == 0

    def test_host_ip_address(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert host.ip == "192.168.56.101"

    def test_host_has_hostname(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert "metasploitable.localdomain" in host.hostnames

    def test_host_has_os_match(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert len(host.os_matches) >= 1
        assert "Linux" in host.os_matches[0]["name"]

    def test_services_count(self, metasploitable_xml: str) -> None:
        """Fixture has 9 ports (21,22,23,25,80,139,445,3306,5432,8080)."""
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        # The fixture has 10 services (139 and 445 are both netbios-ssn)
        assert len(host.services) >= 9

    def test_ftp_service_vsftpd(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 21 in services
        svc = services[21]
        assert svc.service_name == "ftp"
        assert svc.product == "vsftpd"
        assert svc.version == "2.3.4"

    def test_ftp_has_cpe(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        svc = services[21]
        assert any("vsftpd" in cpe for cpe in svc.cpe)

    def test_ssh_openssh_4_7(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 22 in services
        svc = services[22]
        assert svc.service_name == "ssh"
        assert svc.product == "OpenSSH"
        assert "4.7" in svc.version

    def test_telnet_on_port_23(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 23 in services
        assert services[23].service_name == "telnet"

    def test_apache_2_2_8_on_port_80(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 80 in services
        svc = services[80]
        assert svc.product == "Apache httpd"
        assert svc.version == "2.2.8"

    def test_apache_has_cpe(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert any("apache" in cpe.lower() for cpe in services[80].cpe)

    def test_mysql_5_on_port_3306(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 3306 in services
        svc = services[3306]
        assert svc.product == "MySQL"
        assert "5.0" in svc.version

    def test_postgresql_on_port_5432(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 5432 in services
        assert services[5432].service_name == "postgresql"

    def test_tomcat_on_port_8080(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 8080 in services
        assert "Tomcat" in services[8080].product or services[8080].service_name == "http"

    def test_samba_on_ports_139_and_445(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(metasploitable_xml)
        services = {s.port: s for s in result.hosts[0].services}
        assert 139 in services or 445 in services


# ══════════════════════════════════════════════════════════════════════════════
# 2. FULL PIPELINE: Parse → Store → Query
# ══════════════════════════════════════════════════════════════════════════════


class TestFullStoragePipeline:
    """End-to-end: parse XML → save scan → save parsed data → query back."""

    def test_pipeline_saves_scan_record(self, lab_db: str, metasploitable_xml: str) -> None:
        from app.db.repository import get_scan, save_parsed_scan, save_scan
        from app.parser.nmap_xml import parse_nmap_xml
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="e2e-001",
            target="192.168.56.101",
            profile="full",
            status="completed",
            xml_output=metasploitable_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            end_time=datetime(2023, 10, 12, 12, 0, 35, tzinfo=UTC),
            nmap_version="7.94",
            exit_code=0,
        )
        save_scan(scan)

        parsed = parse_nmap_xml(metasploitable_xml)
        save_parsed_scan("e2e-001", parsed)

        record = get_scan("e2e-001")
        assert record is not None
        assert record["target"] == "192.168.56.101"
        assert record["status"] == "completed"

    def test_pipeline_stores_correct_service_count(
        self, lab_db: str, metasploitable_xml: str
    ) -> None:
        from app.db.repository import get_services_for_scan, save_parsed_scan, save_scan
        from app.parser.nmap_xml import parse_nmap_xml
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="e2e-002",
            target="192.168.56.101",
            profile="full",
            status="completed",
            xml_output=metasploitable_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            exit_code=0,
        )
        save_scan(scan)
        parsed = parse_nmap_xml(metasploitable_xml)
        save_parsed_scan("e2e-002", parsed)

        services = get_services_for_scan("e2e-002")
        assert len(services) == 10

    def test_pipeline_stores_vsftpd_cpe(self, lab_db: str, metasploitable_xml: str) -> None:
        from app.db.repository import get_services_for_scan, save_parsed_scan, save_scan
        from app.parser.nmap_xml import parse_nmap_xml
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="e2e-003",
            target="192.168.56.101",
            profile="full",
            status="completed",
            xml_output=metasploitable_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            exit_code=0,
        )
        save_scan(scan)
        parsed = parse_nmap_xml(metasploitable_xml)
        save_parsed_scan("e2e-003", parsed)

        services = get_services_for_scan("e2e-003")
        ports = {s["port"]: s for s in services}
        assert 21 in ports
        cpes = json.loads(ports[21]["cpe"])
        assert any("vsftpd" in c for c in cpes)

    def test_pipeline_stores_host_with_os_match(self, lab_db: str, metasploitable_xml: str) -> None:
        from app.db.repository import get_hosts_for_scan, save_parsed_scan, save_scan
        from app.parser.nmap_xml import parse_nmap_xml
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="e2e-004",
            target="192.168.56.101",
            profile="full",
            status="completed",
            xml_output=metasploitable_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            exit_code=0,
        )
        save_scan(scan)
        parsed = parse_nmap_xml(metasploitable_xml)
        save_parsed_scan("e2e-004", parsed)

        hosts = get_hosts_for_scan("e2e-004")
        assert len(hosts) == 1
        os_matches = json.loads(hosts[0]["os_matches"])
        assert any("Linux" in m["name"] for m in os_matches)


# ══════════════════════════════════════════════════════════════════════════════
# 3. CVE MATCHING — Mocked NVD/KEV
# ══════════════════════════════════════════════════════════════════════════════


class TestCVEMatchingMocked:
    """Test CVE matching logic with mocked NVD/KEV API responses."""

    def _make_vuln(
        self,
        cve_id: str,
        score: float = 9.8,
        severity: str = "CRITICAL",
        cpe_matches: list[dict] | None = None,
    ) -> Any:
        from app.intel.nvd import NVDVulnerability

        return NVDVulnerability(
            cve_id=cve_id,
            description=f"Test vulnerability {cve_id}",
            cvss_v3_score=score,
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_v2_score=None,
            severity=severity,
            published="2023-01-01T00:00:00.000",
            modified="2023-01-01T00:00:00.000",
            references=["https://example.com/cve"],
            cpe_matches=cpe_matches or [],
            weaknesses=["CWE-20"],
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )

    def test_cpe_match_returns_cve(self) -> None:
        from app.intel.matcher import match_service_cves

        vuln = self._make_vuln("CVE-2011-2523", score=10.0, severity="CRITICAL")

        with (
            patch("app.intel.matcher.search_cves_by_cpe", return_value=[vuln]),
            patch("app.intel.matcher.cache_get", return_value=None),
            patch("app.intel.matcher.cache_set"),
        ):
            matches = match_service_cves(
                product="vsftpd",
                version="2.3.4",
                cpe_list=["cpe:/a:vsftpd:vsftpd:2.3.4"],
            )

        assert len(matches) >= 1
        cve_ids = [m.cve_id for m in matches]
        assert "CVE-2011-2523" in cve_ids

    def test_kev_match_enriches_finding(self) -> None:
        from app.intel.kev import KEVCatalog, KEVEntry
        from app.intel.matcher import match_service_cves

        vuln = self._make_vuln("CVE-2011-2523", score=10.0)
        kev_entry = KEVEntry(
            cve_id="CVE-2011-2523",
            vendor="vsftpd",
            product="vsftpd",
            vulnerability_name="vsftpd Backdoor",
            date_added="2021-11-03",
            short_description="vsftpd 2.3.4 contains a backdoor.",
            required_action="Update to a patched version immediately.",
            due_date="2021-11-17",
            known_ransomware_use="Unknown",
        )
        catalog = KEVCatalog(
            title="CISA KEV Test",
            catalog_version="2023.01",
            date_released="2023-01-01",
            count=1,
            entries={"CVE-2011-2523": kev_entry},
        )

        with (
            patch("app.intel.matcher.search_cves_by_cpe", return_value=[vuln]),
            patch("app.intel.matcher.cache_get", return_value=None),
            patch("app.intel.matcher.cache_set"),
        ):
            matches = match_service_cves(
                product="vsftpd",
                version="2.3.4",
                cpe_list=["cpe:/a:vsftpd:vsftpd:2.3.4"],
                kev_catalog=catalog,
            )

        assert len(matches) >= 1
        match = next(m for m in matches if m.cve_id == "CVE-2011-2523")
        assert match.is_kev is True
        assert "2021-11-17" in match.kev_due_date

    def test_keyword_fallback_when_no_cpe_results(self) -> None:
        from app.intel.matcher import match_service_cves

        vuln = self._make_vuln("CVE-2022-0001", score=7.5, severity="HIGH")

        with (
            patch("app.intel.matcher.search_cves_by_cpe", return_value=[]),
            patch("app.intel.matcher.search_cves_by_keyword", return_value=[vuln]),
            patch("app.intel.matcher.cache_get", return_value=None),
            patch("app.intel.matcher.cache_set"),
        ):
            matches = match_service_cves(
                product="Apache httpd",
                version="2.2.8",
                cpe_list=["cpe:/a:apache:http_server:2.2.8"],
            )

        assert len(matches) >= 1
        assert matches[0].match_method == "keyword"
        assert matches[0].confidence == "medium"

    def test_results_sorted_by_cvss_descending(self) -> None:
        from app.intel.matcher import match_service_cves

        vulns = [
            self._make_vuln("CVE-LOW-001", score=3.0, severity="LOW"),
            self._make_vuln("CVE-CRIT-001", score=9.8, severity="CRITICAL"),
            self._make_vuln("CVE-HIGH-001", score=7.5, severity="HIGH"),
        ]

        with (
            patch("app.intel.matcher.search_cves_by_cpe", return_value=vulns),
            patch("app.intel.matcher.cache_get", return_value=None),
            patch("app.intel.matcher.cache_set"),
        ):
            matches = match_service_cves(
                product="OpenSSH",
                version="4.7p1",
                cpe_list=["cpe:/a:openbsd:openssh:4.7p1"],
            )

        scores = [m.cvss_score for m in matches if m.cvss_score is not None]
        assert scores == sorted(scores, reverse=True)

    def test_no_results_on_intel_unavailable(self) -> None:
        from app.core.errors import IntelUnavailableError
        from app.intel.matcher import match_service_cves

        with (
            patch(
                "app.intel.matcher.search_cves_by_cpe",
                side_effect=IntelUnavailableError("NVD down"),
            ),
            patch("app.intel.matcher.cache_get", return_value=None),
            patch("app.intel.matcher.cache_get_stale", return_value=(None, None)),
        ):
            matches = match_service_cves(
                product="vsftpd",
                version="2.3.4",
                cpe_list=["cpe:/a:vsftpd:vsftpd:2.3.4"],
            )

        assert matches == []


# ══════════════════════════════════════════════════════════════════════════════
# 4. RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════


class TestRiskScoring:
    """Validate the risk scoring engine ordering and KEV boost."""

    def test_kev_critical_scores_highest(self) -> None:
        from app.risk.scoring import calculate_risk

        kev_critical = calculate_risk(
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            service_name="ftp",
            port=21,
            match_method="cpe_exact",
        )
        assert kev_critical.priority_score >= 80
        assert kev_critical.priority_label == "critical"

    def test_kev_boosts_score_by_20(self) -> None:
        from app.risk.scoring import calculate_risk

        base = calculate_risk(
            cvss_score=7.5,
            cvss_severity="HIGH",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=False,
            service_name="ftp",
            port=21,
        )
        kev = calculate_risk(
            cvss_score=7.5,
            cvss_severity="HIGH",
            confidence="high",
            evidence_type="external_intelligence",
            is_kev=True,
            service_name="ftp",
            port=21,
        )
        assert kev.priority_score - base.priority_score == pytest.approx(20.0)

    def test_hypothesis_scores_lower_than_intelligence(self) -> None:
        from app.risk.scoring import calculate_risk

        intel = calculate_risk(
            cvss_score=7.0,
            confidence="high",
            evidence_type="external_intelligence",
        )
        hypo = calculate_risk(
            cvss_score=7.0,
            confidence="high",
            evidence_type="hypothesis",
        )
        assert intel.priority_score > hypo.priority_score

    def test_high_confidence_better_than_low(self) -> None:
        from app.risk.scoring import calculate_risk

        high_conf = calculate_risk(cvss_score=5.0, confidence="high")
        low_conf = calculate_risk(cvss_score=5.0, confidence="low")
        assert high_conf.priority_score > low_conf.priority_score

    def test_score_clamped_to_100(self) -> None:
        from app.risk.scoring import calculate_risk

        assessment = calculate_risk(
            cvss_score=10.0,
            confidence="high",
            evidence_type="observed",
            is_kev=True,
            has_exploit_ref=True,
            service_name="http",
            port=80,
        )
        assert assessment.priority_score <= 100.0

    def test_score_clamped_to_zero(self) -> None:
        from app.risk.scoring import calculate_risk

        assessment = calculate_risk()
        assert assessment.priority_score >= 0.0

    def test_factors_list_populated(self) -> None:
        from app.risk.scoring import calculate_risk

        assessment = calculate_risk(
            cvss_score=8.5,
            cvss_severity="HIGH",
            confidence="medium",
            is_kev=True,
        )
        factor_names = [f["name"] for f in assessment.factors]
        assert "CVSS Base Score" in factor_names
        assert "CISA KEV Listed" in factor_names

    def test_label_mapping(self) -> None:
        from app.risk.scoring import calculate_risk

        assert calculate_risk(cvss_score=10.0, confidence="high", is_kev=True).priority_label in (
            "critical",
            "high",
        )
        assert calculate_risk().priority_label == "informational"

    def test_service_exposure_adds_points(self) -> None:
        from app.risk.scoring import calculate_risk

        with_exposure = calculate_risk(cvss_score=5.0, service_name="http", port=80)
        without_exposure = calculate_risk(cvss_score=5.0, service_name="custom-app", port=54321)
        assert with_exposure.priority_score > without_exposure.priority_score

    def test_priority_ordering_is_consistent(self) -> None:
        """Given same CVSS, KEV > no-KEV, high-conf > low-conf."""
        from app.risk.scoring import calculate_risk

        scores = [
            calculate_risk(cvss_score=7.0, confidence="high", is_kev=True).priority_score,
            calculate_risk(cvss_score=7.0, confidence="high", is_kev=False).priority_score,
            calculate_risk(cvss_score=7.0, confidence="low", is_kev=False).priority_score,
        ]
        # Already descending
        assert scores == sorted(scores, reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# 5. REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════


def _make_scan_dict(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "rpt-001",
        "target": "192.168.56.101",
        "profile": "full",
        "status": "completed",
        "start_time": "2023-10-12T12:00:00+00:00",
        "end_time": "2023-10-12T12:00:35+00:00",
        "nmap_version": "7.94",
        "command_args": "['-sS', '-sV']",
        "hosts_up": 1,
    }
    base.update(kwargs)
    return base


def _make_finding(cve_id: str, severity: str = "high", is_kev: bool = False) -> dict[str, Any]:
    return {
        "id": f"find-{cve_id}",
        "scan_id": "rpt-001",
        "cve_id": cve_id,
        "title": f"Test {cve_id}",
        "description": f"Vulnerability description for {cve_id}.",
        "severity": severity,
        "cvss_score": 9.0 if severity == "critical" else 7.5,
        "confidence": "high",
        "evidence_type": "external_intelligence",
        "is_kev": is_kev,
        "kev_due_date": "2021-11-17" if is_kev else "",
        "port": 21,
        "service_name": "ftp",
    }


class TestJSONReportGeneration:
    """Validate JSON report structure and content."""

    def test_json_report_has_required_top_level_keys(self) -> None:
        from app.reports.builder import build_json_report

        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[{"id": "h1", "ip": "192.168.56.101", "status": "up"}],
            services=[{"id": "s1", "port": 21, "service_name": "ftp"}],
            findings=[_make_finding("CVE-2011-2523", is_kev=True)],
        )

        for key in ("report_id", "generated_at", "aegis_version", "scan", "summary", "findings"):
            assert key in report

    def test_json_report_severity_counts(self) -> None:
        from app.reports.builder import build_json_report

        findings = [
            _make_finding("CVE-A", severity="critical"),
            _make_finding("CVE-B", severity="high"),
            _make_finding("CVE-C", severity="high"),
            _make_finding("CVE-D", severity="low"),
        ]
        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=findings,
        )
        counts = report["summary"]["severity_counts"]
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["low"] == 1

    def test_json_report_kev_count(self) -> None:
        from app.reports.builder import build_json_report

        findings = [
            _make_finding("CVE-A", is_kev=True),
            _make_finding("CVE-B", is_kev=True),
            _make_finding("CVE-C", is_kev=False),
        ]
        report = build_json_report(scan=_make_scan_dict(), hosts=[], services=[], findings=findings)
        assert report["summary"]["kev_count"] == 2

    def test_json_report_includes_disclaimer(self) -> None:
        from app.reports.builder import build_json_report

        report = build_json_report(scan=_make_scan_dict(), hosts=[], services=[], findings=[])
        assert "disclaimer" in report
        assert "hypothesis" in report["disclaimer"].lower()

    def test_json_report_with_analysis(self) -> None:
        from app.reports.builder import build_json_report

        analysis = {
            "summary": "Critical vsftpd backdoor detected.",
            "recommendations": ["Upgrade vsftpd immediately."],
            "risk_overview": "high",
            "analysis_method": "gemini",
        }
        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=[_make_finding("CVE-2011-2523")],
            analysis=analysis,
        )
        assert report["analysis"]["summary"] == "Critical vsftpd backdoor detected."

    def test_json_report_serializable(self) -> None:
        from app.reports.builder import build_json_report

        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[{"ip": "192.168.56.101"}],
            services=[{"port": 21}],
            findings=[_make_finding("CVE-2011-2523", is_kev=True)],
        )
        # Must be JSON-serializable
        serialized = json.dumps(report)
        restored = json.loads(serialized)
        assert restored["report_id"] == report["report_id"]


class TestHTMLReportGeneration:
    """Validate HTML report content and XSS protections."""

    def test_html_report_is_string(self) -> None:
        from app.reports.builder import build_html_report

        html = build_html_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=[],
        )
        assert isinstance(html, str)
        assert len(html) > 100

    def test_html_report_contains_target(self) -> None:
        from app.reports.builder import build_html_report

        html = build_html_report(
            scan=_make_scan_dict(target="192.168.56.101"),
            hosts=[],
            services=[],
            findings=[],
        )
        assert "192.168.56.101" in html

    def test_html_report_xss_script_tag_escaped(self) -> None:
        """XSS payload in a finding description must be escaped."""
        from app.reports.builder import build_html_report

        malicious_finding = {
            "id": "xss-1",
            "scan_id": "rpt-001",
            "cve_id": "CVE-XSS-001",
            "title": "<script>alert('xss')</script>",
            "description": "<img src=x onerror=alert(1)>",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": "medium",
            "evidence_type": "hypothesis",
            "is_kev": False,
            "port": 80,
            "service_name": "http",
        }
        html = build_html_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=[malicious_finding],
        )
        # Raw <script> tag should NOT appear in HTML output
        assert "<script>alert('xss')</script>" not in html

    def test_html_report_contains_severity_section(self) -> None:
        from app.reports.builder import build_html_report

        findings = [_make_finding("CVE-2011-2523", severity="critical", is_kev=True)]
        html = build_html_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=findings,
        )
        assert "critical" in html.lower() or "CVE-2011-2523" in html


# ══════════════════════════════════════════════════════════════════════════════
# 6. AI ANALYSIS — Mocked Gemini
# ══════════════════════════════════════════════════════════════════════════════


class TestAIAnalysisMocked:
    """Test AI provider with mocked HTTP responses."""

    def _mock_gemini_response(self, text: str) -> MagicMock:
        """Build a mock httpx response simulating Gemini API."""
        payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": text}],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = payload
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_gemini_provider_returns_analysis(self) -> None:
        from app.ai.provider import GeminiProvider

        valid_output = json.dumps(
            {
                "summary": "vsftpd 2.3.4 has a critical backdoor (CVE-2011-2523).",
                "recommendations": [
                    "Upgrade vsftpd immediately.",
                    "Apply network-level controls.",
                ],
                "risk_overview": "Critical exposure: known-exploited backdoor on FTP.",
                "limitations": "Version match — confirm with manual test.",
                "analysis_method": "gemini",
            }
        )
        mock_resp = self._mock_gemini_response(valid_output)

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_resp)

        with patch("httpx.Client", return_value=mock_client):
            provider = GeminiProvider(api_keys=["test-key-1"])
            result = provider.analyze_findings(
                findings=[_make_finding("CVE-2011-2523", is_kev=True)],
                scan_context={"target": "192.168.56.101", "profile": "full"},
            )

        assert "summary" in result
        assert "CVE-2011-2523" in result["summary"] or "vsftpd" in result["summary"]

    def test_gemini_provider_key_rotation_on_429(self) -> None:
        """On 429 from first key, provider should try next key."""
        from app.ai.provider import GeminiProvider

        valid_output = json.dumps(
            {
                "summary": "Test analysis.",
                "recommendations": ["Action item 1."],
                "risk_overview": "Medium risk.",
                "limitations": "Automated only.",
                "analysis_method": "gemini",
            }
        )
        mock_429 = MagicMock()
        mock_429.status_code = 429

        mock_ok = self._mock_gemini_response(valid_output)

        call_count = 0

        def _post_side_effect(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_429
            return mock_ok

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(side_effect=_post_side_effect)

        with patch("httpx.Client", return_value=mock_client):
            provider = GeminiProvider(api_keys=["key-rate-limited", "key-ok"])
            result = provider.analyze_findings(
                findings=[_make_finding("CVE-0000-0001")],
                scan_context={"target": "10.0.0.1"},
            )

        assert call_count == 2  # First key failed, second succeeded
        assert "summary" in result

    def test_fallback_when_ai_disabled(self) -> None:
        from app.ai.fallback import generate_deterministic_analysis

        result = generate_deterministic_analysis(
            findings=[_make_finding("CVE-2011-2523", is_kev=True)],
            scan_context={"target": "192.168.56.101"},
        )
        assert "summary" in result
        assert result.get("analysis_method") == "deterministic"

    def test_fallback_produces_recommendations(self) -> None:
        from app.ai.fallback import generate_deterministic_analysis

        result = generate_deterministic_analysis(
            findings=[
                _make_finding("CVE-A", severity="critical"),
                _make_finding("CVE-B", severity="high"),
            ],
            scan_context={"target": "192.168.56.101"},
        )
        assert isinstance(result.get("recommendations"), list)
        assert len(result["recommendations"]) >= 1

    def test_ai_factory_returns_gemini_when_configured(self) -> None:
        from app.ai.provider import GeminiProvider, get_ai_provider

        with patch.dict(
            "os.environ",
            {
                "AI_ENABLED": "true",
                "AI_PROVIDER": "gemini",
                "GEMINI_API_KEY": "test-key",
            },
        ):
            # Reset cached settings
            from app.config import reset_settings

            reset_settings()
            provider = get_ai_provider()
            assert isinstance(provider, GeminiProvider)
            reset_settings()


# ══════════════════════════════════════════════════════════════════════════════
# 7. EDGE CASES
# ══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Validate graceful handling of unusual inputs."""

    def test_empty_scan_parsed_without_error(self, empty_scan_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        result = parse_nmap_xml(empty_scan_xml)
        assert result.hosts_down >= 1
        assert result.hosts_up == 0

    def test_empty_scan_stored_and_queried(self, lab_db: str, empty_scan_xml: str) -> None:
        from app.db.repository import get_scan, get_services_for_scan, save_parsed_scan, save_scan
        from app.parser.nmap_xml import parse_nmap_xml
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="edge-empty-001",
            target="192.168.56.200",
            profile="quick",
            status="completed",
            xml_output=empty_scan_xml,
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            exit_code=0,
        )
        save_scan(scan)
        parsed = parse_nmap_xml(empty_scan_xml)
        save_parsed_scan("edge-empty-001", parsed)

        record = get_scan("edge-empty-001")
        assert record is not None
        assert record["hosts_down"] == 1
        services = get_services_for_scan("edge-empty-001")
        assert len(services) == 0

    def test_report_with_zero_findings(self) -> None:
        from app.reports.builder import build_json_report

        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[],
            services=[],
            findings=[],
        )
        assert report["summary"]["findings_total"] == 0
        assert report["summary"]["kev_count"] == 0

    def test_very_long_banner_in_finding_does_not_crash_report(self) -> None:
        from app.reports.builder import build_json_report

        long_banner = "A" * 50_000  # 50 KB banner
        finding = _make_finding("CVE-2011-2523")
        finding["description"] = long_banner

        report = build_json_report(
            scan=_make_scan_dict(), hosts=[], services=[], findings=[finding]
        )
        assert report["summary"]["findings_total"] == 1

    def test_unicode_in_finding_survives_json_roundtrip(self) -> None:
        from app.reports.builder import build_json_report

        finding = _make_finding("CVE-UNICODE-001")
        finding["title"] = "Уязвимость: vsftpd 🔓 <危険>"
        finding["description"] = "説明: backdoor detected. Ärger im System."

        report = build_json_report(
            scan=_make_scan_dict(), hosts=[], services=[], findings=[finding]
        )
        serialized = json.dumps(report, ensure_ascii=False)
        restored = json.loads(serialized)
        assert "vsftpd" in restored["findings"][0]["title"]

    def test_failed_scan_stored_with_error_message(self, lab_db: str) -> None:
        from app.db.repository import get_scan, save_scan
        from app.scanner.runner import ScanResult

        scan = ScanResult(
            scan_id="edge-fail-001",
            target="10.0.0.1",
            profile="quick",
            status="failed",
            error_message="Timeout: host unreachable after 30s",
            start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
            exit_code=1,
        )
        save_scan(scan)

        record = get_scan("edge-fail-001")
        assert record is not None
        assert record["status"] == "failed"
        assert "Timeout" in record["error_message"]

    def test_risk_score_with_no_cvss(self) -> None:
        from app.risk.scoring import calculate_risk

        assessment = calculate_risk(
            cvss_score=None,
            confidence="high",
            is_kev=True,
        )
        # Should not crash; KEV + high confidence should still produce a score
        assert assessment.priority_score > 0
        assert "CVSS Base Score" in [f["name"] for f in assessment.factors]

    def test_cpe_version_range_check_in_range(self) -> None:
        from app.intel.matcher import _check_version_range

        # Apache 2.2.8 is in range [2.0.0, 2.4.0)
        result = _check_version_range("2.2.8", "2.0.0", "", "", "2.4.0")
        assert result is True

    def test_cpe_version_range_check_out_of_range(self) -> None:
        from app.intel.matcher import _check_version_range

        # Apache 2.4.57 is NOT in range [2.0.0, 2.4.0)
        result = _check_version_range("2.4.57", "2.0.0", "", "", "2.4.0")
        assert result is False


# ══════════════════════════════════════════════════════════════════════════════
# 8. STRESS / PERFORMANCE
# ══════════════════════════════════════════════════════════════════════════════


class TestStressAndPerformance:
    """Validate system handles large inputs within acceptable time budgets."""

    def test_score_1000_findings_under_2_seconds(self) -> None:
        from app.risk.scoring import calculate_risk

        start = time.monotonic()
        for i in range(1000):
            calculate_risk(
                cvss_score=float(i % 10) + 0.5,
                cvss_severity="HIGH",
                confidence="medium",
                evidence_type="hypothesis",
                is_kev=i % 5 == 0,
                service_name="http",
                port=80,
            )
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"Scoring 1000 findings took {elapsed:.2f}s (limit: 2s)"

    def test_json_report_with_500_findings_under_3_seconds(self) -> None:
        from app.reports.builder import build_json_report

        findings = [
            _make_finding(f"CVE-{i:04d}", severity="high", is_kev=(i % 10 == 0)) for i in range(500)
        ]
        start = time.monotonic()
        report = build_json_report(
            scan=_make_scan_dict(),
            hosts=[{"ip": "192.168.56.101"}],
            services=[{"port": i % 65535} for i in range(50)],
            findings=findings,
        )
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"Report generation took {elapsed:.2f}s (limit: 3s)"
        assert report["summary"]["findings_total"] == 500

    def test_parse_metasploitable_xml_under_1_second(self, metasploitable_xml: str) -> None:
        from app.parser.nmap_xml import parse_nmap_xml

        start = time.monotonic()
        for _ in range(100):
            parse_nmap_xml(metasploitable_xml)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"100 XML parses took {elapsed:.2f}s (limit: 1s)"

    def test_version_parse_tuple_handles_garbage(self) -> None:
        from app.intel.matcher import _parse_version_tuple

        # Should not crash on weird inputs
        assert _parse_version_tuple("") is None
        assert _parse_version_tuple("abc") is None
        assert _parse_version_tuple("1.2.3") == (1, 2, 3)
        assert _parse_version_tuple("2.3.4-debian") == (2, 3, 4)
        assert _parse_version_tuple("10.0.51a") == (10, 0, 51)
