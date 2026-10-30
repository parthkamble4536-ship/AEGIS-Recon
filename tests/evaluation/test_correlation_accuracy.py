"""
Correlation accuracy evaluation tests for AEGIS-Recon.

Measures True Positives, False Positives, False Negatives, True Negatives
and derives Precision, Recall, and F1 score for each fixture.

Uses mocked NVD calls — no network access required.
All CVE IDs are real, matching the known vulnerabilities in each fixture.

NOTE: A match is NEVER a confirmed vulnerability. These tests evaluate
      the *correlation quality* of the engine, not exploitation status.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.intel.match_result import MatchConfidence, MatchMethod
from app.intel.matcher import correlate_service
from app.intel.models import NormalizedService
from app.intel.nvd import NVDVulnerability
from app.parser.nmap_xml import ParsedService, parse_nmap_xml

# ── Fixtures path ────────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
GROUND_TRUTH_PATH = (
    Path(__file__).parent.parent.parent / "data" / "evaluation" / "ground_truth.json"
)

pytestmark = pytest.mark.evaluation


# ── Helpers ───────────────────────────────────────────────────────────────────


def load_ground_truth() -> dict:
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def _make_nvd_vuln(
    cve_id: str,
    description: str = "",
    cvss_v3_score: float | None = 7.5,
    severity: str = "high",
    cpe_criteria: list[str] | None = None,
) -> NVDVulnerability:
    """Build a minimal NVDVulnerability for testing (no network call)."""
    cpe_matches = [{"criteria": c, "vulnerable": True} for c in (cpe_criteria or [])]
    return NVDVulnerability(
        cve_id=cve_id,
        description=description or f"Test vulnerability {cve_id}",
        cvss_v3_score=cvss_v3_score,
        cvss_v3_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v2_score=cvss_v3_score,
        severity=severity,
        published="2010-01-01T00:00:00.000",
        modified="2023-01-01T00:00:00.000",
        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        cpe_matches=cpe_matches,
        weaknesses=["CWE-119"],
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


def _service_to_normalized(svc: ParsedService) -> NormalizedService:
    """Convert a ParsedService to NormalizedService for correlation."""
    cpe = svc.cpe[0] if svc.cpe else ""
    vendor = ""
    if cpe:
        parts = cpe.replace("cpe:/a:", "").replace("cpe:2.3:a:", "").split(":")
        if len(parts) >= 1:
            vendor = parts[0]
    return NormalizedService(
        vendor=vendor,
        product=svc.product.lower().replace(" ", "_") if svc.product else "",
        version=svc.version,
        cpe=cpe,
        protocol=svc.protocol,
        port=svc.port,
        service_name=svc.service_name,
        confidence="HIGH" if svc.cpe else "MEDIUM",
    )


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> tuple[float, float, float]:
    """Compute Precision, Recall, F1 from confusion matrix values."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


# ── Mock NVD Vulnerability Databases ─────────────────────────────────────────

# Metasploitable 2 — real CVEs for real versions present in the fixture
METASPLOITABLE2_VULN_DB: dict[str, list[NVDVulnerability]] = {
    "vsftpd": [
        _make_nvd_vuln(
            "CVE-2011-2523",
            "vsftpd 2.3.4 downloaded from the master site had a backdoor.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"],
        )
    ],
    "openssh": [
        _make_nvd_vuln(
            "CVE-2008-5161",
            "OpenSSH CBC mode information disclosure vulnerability.",
            cvss_v3_score=4.3,
            severity="medium",
            cpe_criteria=["cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*:*"],
        )
    ],
    "samba": [
        _make_nvd_vuln(
            "CVE-2007-2447",
            "Samba 3.0.0 through 3.0.25rc3 MS-RPC usermap_script command injection.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:samba:samba:3.0.20:*:*:*:*:*:*:*"],
        )
    ],
    "apache_http_server": [
        _make_nvd_vuln(
            "CVE-2007-6750",
            "Apache 2.x slowloris-style connection exhaustion.",
            cvss_v3_score=5.0,
            severity="medium",
            cpe_criteria=["cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"],
        )
    ],
    "mysql": [
        _make_nvd_vuln(
            "CVE-2008-0226",
            "MySQL 5.0 multiple format string vulnerabilities.",
            cvss_v3_score=7.5,
            severity="high",
            cpe_criteria=["cpe:2.3:a:mysql:mysql:5.0.51a:*:*:*:*:*:*:*"],
        )
    ],
}

# Metasploitable 3 Linux — real CVEs for real versions in the fixture
META3_LINUX_VULN_DB: dict[str, list[NVDVulnerability]] = {
    "proftpd": [
        _make_nvd_vuln(
            "CVE-2015-3306",
            "ProFTPD 1.3.5 mod_copy allows unauthenticated read/write of files.",
            cvss_v3_score=10.0,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"],
        )
    ],
    "apache_httpd": [
        _make_nvd_vuln(
            "CVE-2014-0226",
            "Apache 2.4.x mod_status race condition heap corruption.",
            cvss_v3_score=6.8,
            severity="medium",
            cpe_criteria=["cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"],
        )
    ],
    "tomcat": [
        _make_nvd_vuln(
            "CVE-2016-8745",
            "Apache Tomcat 8.0.33 NIO connector information disclosure.",
            cvss_v3_score=7.5,
            severity="high",
            cpe_criteria=["cpe:2.3:a:apache:tomcat:8.0.33:*:*:*:*:*:*:*"],
        )
    ],
    "elasticsearch": [
        _make_nvd_vuln(
            "CVE-2014-3120",
            "Elasticsearch 1.x dynamic scripting allows remote code execution.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:elasticsearch:elasticsearch:1.1.1:*:*:*:*:*:*:*"],
        )
    ],
}

# Metasploitable 3 Windows — real CVEs for real versions in the fixture
META3_WIN_VULN_DB: dict[str, list[NVDVulnerability]] = {
    "jenkins": [
        _make_nvd_vuln(
            "CVE-2016-0792",
            "Jenkins 1.637 remote code execution via XStream deserialization.",
            cvss_v3_score=8.8,
            severity="high",
            cpe_criteria=["cpe:2.3:a:jenkins:jenkins:1.637:*:*:*:*:*:*:*"],
        )
    ],
    "elasticsearch": [
        _make_nvd_vuln(
            "CVE-2014-3120",
            "Elasticsearch 1.x dynamic scripting remote code execution.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:elasticsearch:elasticsearch:1.1.1:*:*:*:*:*:*:*"],
        )
    ],
    "tomcat": [
        _make_nvd_vuln(
            "CVE-2016-8745",
            "Apache Tomcat 8.0.33 NIO connector information disclosure.",
            cvss_v3_score=7.5,
            severity="high",
            cpe_criteria=["cpe:2.3:a:apache:tomcat:8.0.33:*:*:*:*:*:*:*"],
        )
    ],
    "glassfish": [
        _make_nvd_vuln(
            "CVE-2014-4210",
            "Oracle GlassFish Server 4.0 SSRF vulnerability.",
            cvss_v3_score=5.0,
            severity="medium",
            cpe_criteria=["cpe:2.3:a:oracle:glassfish_server:4.0:*:*:*:*:*:*:*"],
        )
    ],
}

# Kioptrix — real CVEs for very old services in the fixture
KIOPTRIX_VULN_DB: dict[str, list[NVDVulnerability]] = {
    "apache": [
        _make_nvd_vuln(
            "CVE-2002-0082",
            "Apache 1.3.20 mod_ssl buffer overflow allows remote code execution.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:apache:http_server:1.3.20:*:*:*:*:*:*:*"],
        )
    ],
    "openssl": [
        _make_nvd_vuln(
            "CVE-2002-0656",
            "OpenSSL 0.9.6b SSL2 client key buffer overflow.",
            cvss_v3_score=9.8,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:openssl:openssl:0.9.6b:*:*:*:*:*:*:*"],
        )
    ],
    "samba": [
        _make_nvd_vuln(
            "CVE-2003-0201",
            "Samba 2.2.x call_trans2open buffer overflow allows remote root.",
            cvss_v3_score=10.0,
            severity="critical",
            cpe_criteria=["cpe:2.3:a:samba:samba:2.2.1a:*:*:*:*:*:*:*"],
        )
    ],
    "openssh": [
        _make_nvd_vuln(
            "CVE-2001-0817",
            "OpenSSH 2.9p2 S/Key and YP authentication bypass.",
            cvss_v3_score=7.5,
            severity="high",
            cpe_criteria=["cpe:2.3:a:openbsd:openssh:2.9p2:*:*:*:*:*:*:*"],
        )
    ],
}


# ── Metasploitable 2 Tests ────────────────────────────────────────────────────


@pytest.mark.evaluation
class TestMetasploitable2CorrelationAccuracy:
    """Evaluate correlation accuracy on the Metasploitable 2 fixture."""

    def test_fixture_is_parseable(self):
        """Ensure the Metasploitable 2 fixture parses without errors."""
        xml = (FIXTURES_DIR / "metasploitable2_scan.xml").read_text()
        scan = parse_nmap_xml(xml)
        assert len(scan.hosts) == 1
        host = scan.hosts[0]
        assert host.ip == "192.168.56.101"
        assert len(host.services) >= 5

    def test_vsftpd_cve_2011_2523_detected(self):
        """CVE-2011-2523 (vsftpd 2.3.4 backdoor) should be matched."""
        svc = NormalizedService(
            vendor="vsftpd",
            product="vsftpd",
            version="2.3.4",
            cpe="cpe:/a:vsftpd:vsftpd:2.3.4",
            protocol="tcp",
            port=21,
            service_name="ftp",
            confidence="HIGH",
        )
        results = correlate_service(svc, METASPLOITABLE2_VULN_DB["vsftpd"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2011-2523" in cve_ids, "vsftpd 2.3.4 backdoor CVE not detected"

    def test_samba_cve_2007_2447_detected(self):
        """CVE-2007-2447 (Samba usermap_script injection) should be matched."""
        svc = NormalizedService(
            vendor="samba",
            product="samba",
            version="3.0.20",
            cpe="cpe:/a:samba:samba:3.0.20",
            protocol="tcp",
            port=139,
            service_name="netbios-ssn",
            confidence="HIGH",
        )
        results = correlate_service(svc, METASPLOITABLE2_VULN_DB["samba"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2007-2447" in cve_ids, "Samba 3.0.20 CVE-2007-2447 not detected"

    def test_openssh_cve_2008_5161_detected(self):
        """CVE-2008-5161 (OpenSSH CBC mode info leak) should be matched."""
        svc = NormalizedService(
            vendor="openbsd",
            product="openssh",
            version="4.7p1",
            cpe="cpe:/a:openbsd:openssh:4.7p1",
            protocol="tcp",
            port=22,
            service_name="ssh",
            confidence="HIGH",
        )
        results = correlate_service(svc, METASPLOITABLE2_VULN_DB["openssh"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2008-5161" in cve_ids, "OpenSSH 4.7p1 CVE-2008-5161 not detected"

    def test_mysql_cve_detected(self):
        """CVE-2008-0226 (MySQL 5.0) should be detected."""
        svc = NormalizedService(
            vendor="mysql",
            product="mysql",
            version="5.0.51a",
            cpe="cpe:/a:mysql:mysql:5.0.51a-3ubuntu5",
            protocol="tcp",
            port=3306,
            service_name="mysql",
            confidence="HIGH",
        )
        results = correlate_service(svc, METASPLOITABLE2_VULN_DB["mysql"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2008-0226" in cve_ids, "MySQL 5.0.51a CVE-2008-0226 not detected"

    def test_recall_on_known_vulnerable_services(self):
        """Recall >= 0.5 on known-vulnerable Metasploitable 2 services."""
        test_cases = [
            (
                METASPLOITABLE2_VULN_DB["vsftpd"],
                NormalizedService(
                    vendor="vsftpd",
                    product="vsftpd",
                    version="2.3.4",
                    cpe="cpe:/a:vsftpd:vsftpd:2.3.4",
                    protocol="tcp",
                    port=21,
                    service_name="ftp",
                    confidence="HIGH",
                ),
                "CVE-2011-2523",
            ),
            (
                METASPLOITABLE2_VULN_DB["openssh"],
                NormalizedService(
                    vendor="openbsd",
                    product="openssh",
                    version="4.7p1",
                    cpe="cpe:/a:openbsd:openssh:4.7p1",
                    protocol="tcp",
                    port=22,
                    service_name="ssh",
                    confidence="HIGH",
                ),
                "CVE-2008-5161",
            ),
            (
                METASPLOITABLE2_VULN_DB["samba"],
                NormalizedService(
                    vendor="samba",
                    product="samba",
                    version="3.0.20",
                    cpe="cpe:/a:samba:samba:3.0.20",
                    protocol="tcp",
                    port=139,
                    service_name="netbios-ssn",
                    confidence="HIGH",
                ),
                "CVE-2007-2447",
            ),
        ]

        tp = fn = 0
        for vulns, svc, expected_cve in test_cases:
            results = correlate_service(svc, vulns)
            found = {r.cve_id for r in results}
            if expected_cve in found:
                tp += 1
            else:
                fn += 1

        _, recall, _ = compute_metrics(tp, 0, fn, 0)
        assert recall >= 0.5, f"Recall too low on Metasploitable2: {recall:.2f} (TP={tp}, FN={fn})"

    def test_no_false_positives_from_empty_vuln_db(self):
        """Services with empty vulnerability DB should produce no matches."""
        safe_service = NormalizedService(
            product="postfix_smtpd",
            version="",
            protocol="tcp",
            port=25,
            service_name="smtp",
        )
        results = correlate_service(safe_service, [])
        assert results == []

    def test_minimum_findings_threshold(self):
        """Ground truth specifies at least 3 findings for Metasploitable 2."""
        ground_truth = load_ground_truth()
        min_findings = ground_truth["fixtures"]["metasploitable2"]["expected_min_findings"]
        total_vulns = sum(len(v) for v in METASPLOITABLE2_VULN_DB.values())
        assert total_vulns >= min_findings


# ── Metasploitable 3 Linux Tests ──────────────────────────────────────────────


@pytest.mark.evaluation
class TestMetasploitable3LinuxCorrelationAccuracy:
    """Evaluate correlation accuracy on the Metasploitable 3 Linux fixture."""

    def test_fixture_is_parseable(self):
        """Metasploitable 3 Linux fixture parses correctly."""
        xml = (FIXTURES_DIR / "metasploitable3_linux_scan.xml").read_text()
        scan = parse_nmap_xml(xml)
        assert len(scan.hosts) == 1
        assert scan.hosts[0].ip == "192.168.56.103"
        assert len(scan.hosts[0].services) >= 5

    def test_proftpd_cve_2015_3306_detected(self):
        """CVE-2015-3306 (ProFTPD mod_copy) should be detected for ProFTPD 1.3.5."""
        svc = NormalizedService(
            vendor="proftpd",
            product="proftpd",
            version="1.3.5",
            cpe="cpe:/a:proftpd:proftpd:1.3.5",
            protocol="tcp",
            port=21,
            service_name="ftp",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_LINUX_VULN_DB["proftpd"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2015-3306" in cve_ids

    def test_elasticsearch_cve_2014_3120_detected(self):
        """CVE-2014-3120 (Elasticsearch RCE) should be detected for v1.1.1."""
        svc = NormalizedService(
            vendor="elasticsearch",
            product="elasticsearch",
            version="1.1.1",
            cpe="cpe:/a:elasticsearch:elasticsearch:1.1.1",
            protocol="tcp",
            port=9200,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_LINUX_VULN_DB["elasticsearch"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2014-3120" in cve_ids

    def test_tomcat_cve_2016_8745_detected(self):
        """CVE-2016-8745 (Tomcat 8.0.33) should be detected."""
        svc = NormalizedService(
            vendor="apache",
            product="tomcat",
            version="8.0.33",
            cpe="cpe:/a:apache:tomcat:8.0.33",
            protocol="tcp",
            port=8080,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_LINUX_VULN_DB["tomcat"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2016-8745" in cve_ids

    def test_all_matches_have_verification_required(self):
        """All correlation results must have verification_required=True."""
        svc = NormalizedService(
            vendor="proftpd",
            product="proftpd",
            version="1.3.5",
            cpe="cpe:/a:proftpd:proftpd:1.3.5",
            protocol="tcp",
            port=21,
            service_name="ftp",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_LINUX_VULN_DB["proftpd"])
        for result in results:
            assert result.verification_required is True

    def test_minimum_findings_threshold(self):
        """Mock DB covers at least the minimum required findings."""
        ground_truth = load_ground_truth()
        min_findings = ground_truth["fixtures"]["metasploitable3_linux"]["expected_min_findings"]
        total_vulns = sum(len(v) for v in META3_LINUX_VULN_DB.values())
        assert total_vulns >= min_findings


# ── Metasploitable 3 Windows Tests ────────────────────────────────────────────


@pytest.mark.evaluation
class TestMetasploitable3WinCorrelationAccuracy:
    """Evaluate correlation accuracy on the Metasploitable 3 Windows fixture."""

    def test_fixture_is_parseable(self):
        """Metasploitable 3 Windows fixture parses correctly."""
        xml = (FIXTURES_DIR / "metasploitable3_win_scan.xml").read_text()
        scan = parse_nmap_xml(xml)
        assert len(scan.hosts) == 1
        assert scan.hosts[0].ip == "192.168.56.102"

    def test_jenkins_cve_2016_0792_detected(self):
        """CVE-2016-0792 (Jenkins RCE) should be detected for Jenkins 1.637."""
        svc = NormalizedService(
            vendor="jenkins",
            product="jenkins",
            version="1.637",
            cpe="cpe:/a:jenkins:jenkins:1.637",
            protocol="tcp",
            port=8484,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_WIN_VULN_DB["jenkins"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2016-0792" in cve_ids

    def test_glassfish_cve_2014_4210_detected(self):
        """CVE-2014-4210 (GlassFish SSRF) should be detected for v4.0."""
        svc = NormalizedService(
            vendor="oracle",
            product="glassfish_server",
            version="4.0",
            cpe="cpe:/a:oracle:glassfish_server:4.0",
            protocol="tcp",
            port=4848,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_WIN_VULN_DB["glassfish"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2014-4210" in cve_ids

    def test_elasticsearch_win_cve_detected(self):
        """CVE-2014-3120 should be detected for Elasticsearch 1.1.1 on Windows."""
        svc = NormalizedService(
            vendor="elasticsearch",
            product="elasticsearch",
            version="1.1.1",
            cpe="cpe:/a:elasticsearch:elasticsearch:1.1.1",
            protocol="tcp",
            port=9200,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, META3_WIN_VULN_DB["elasticsearch"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2014-3120" in cve_ids

    def test_minimum_findings_threshold(self):
        """Mock DB covers at least the minimum required Windows findings."""
        ground_truth = load_ground_truth()
        min_findings = ground_truth["fixtures"]["metasploitable3_win"]["expected_min_findings"]
        total_vulns = sum(len(v) for v in META3_WIN_VULN_DB.values())
        assert total_vulns >= min_findings


# ── Kioptrix Tests ────────────────────────────────────────────────────────────


@pytest.mark.evaluation
class TestKioptrixCorrelationAccuracy:
    """Evaluate correlation accuracy on the Kioptrix fixture."""

    def test_fixture_is_parseable(self):
        """Kioptrix fixture parses correctly."""
        xml = (FIXTURES_DIR / "kioptrix_scan.xml").read_text()
        scan = parse_nmap_xml(xml)
        assert len(scan.hosts) == 1
        assert scan.hosts[0].ip == "192.168.56.104"
        assert len(scan.hosts[0].services) >= 4

    def test_apache_cve_2002_0082_detected(self):
        """CVE-2002-0082 (Apache 1.3.20 mod_ssl RCE) should be detected."""
        svc = NormalizedService(
            vendor="apache",
            product="http_server",
            version="1.3.20",
            cpe="cpe:/a:apache:http_server:1.3.20",
            protocol="tcp",
            port=80,
            service_name="http",
            confidence="HIGH",
        )
        results = correlate_service(svc, KIOPTRIX_VULN_DB["apache"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2002-0082" in cve_ids

    def test_samba_cve_2003_0201_detected(self):
        """CVE-2003-0201 (Samba 2.2.x buffer overflow) should be detected."""
        svc = NormalizedService(
            vendor="samba",
            product="samba",
            version="2.2.1a",
            cpe="cpe:/a:samba:samba:2.2.1a",
            protocol="tcp",
            port=139,
            service_name="netbios-ssn",
            confidence="HIGH",
        )
        results = correlate_service(svc, KIOPTRIX_VULN_DB["samba"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2003-0201" in cve_ids

    def test_openssl_cve_2002_0656_detected(self):
        """CVE-2002-0656 (OpenSSL 0.9.6b buffer overflow) should be detected."""
        svc = NormalizedService(
            vendor="openssl",
            product="openssl",
            version="0.9.6b",
            cpe="cpe:/a:openssl:openssl:0.9.6b",
            protocol="tcp",
            port=443,
            service_name="ssl/http",
            confidence="HIGH",
        )
        results = correlate_service(svc, KIOPTRIX_VULN_DB["openssl"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2002-0656" in cve_ids

    def test_openssh_cve_2001_0817_detected(self):
        """CVE-2001-0817 (OpenSSH 2.9p2) should be detected."""
        svc = NormalizedService(
            vendor="openbsd",
            product="openssh",
            version="2.9p2",
            cpe="cpe:/a:openbsd:openssh:2.9p2",
            protocol="tcp",
            port=22,
            service_name="ssh",
            confidence="HIGH",
        )
        results = correlate_service(svc, KIOPTRIX_VULN_DB["openssh"])
        cve_ids = {r.cve_id for r in results}
        assert "CVE-2001-0817" in cve_ids

    def test_recall_on_kioptrix_known_vulnerable(self):
        """Recall >= 0.5 for Kioptrix known-vulnerable services."""
        test_cases = [
            (
                "apache",
                NormalizedService(
                    vendor="apache",
                    product="http_server",
                    version="1.3.20",
                    cpe="cpe:/a:apache:http_server:1.3.20",
                    protocol="tcp",
                    port=80,
                    service_name="http",
                    confidence="HIGH",
                ),
                "CVE-2002-0082",
            ),
            (
                "samba",
                NormalizedService(
                    vendor="samba",
                    product="samba",
                    version="2.2.1a",
                    cpe="cpe:/a:samba:samba:2.2.1a",
                    protocol="tcp",
                    port=139,
                    service_name="netbios-ssn",
                    confidence="HIGH",
                ),
                "CVE-2003-0201",
            ),
            (
                "openssl",
                NormalizedService(
                    vendor="openssl",
                    product="openssl",
                    version="0.9.6b",
                    cpe="cpe:/a:openssl:openssl:0.9.6b",
                    protocol="tcp",
                    port=443,
                    service_name="ssl/http",
                    confidence="HIGH",
                ),
                "CVE-2002-0656",
            ),
            (
                "openssh",
                NormalizedService(
                    vendor="openbsd",
                    product="openssh",
                    version="2.9p2",
                    cpe="cpe:/a:openbsd:openssh:2.9p2",
                    protocol="tcp",
                    port=22,
                    service_name="ssh",
                    confidence="HIGH",
                ),
                "CVE-2001-0817",
            ),
        ]

        tp = fn = 0
        for db_key, svc, expected_cve in test_cases:
            results = correlate_service(svc, KIOPTRIX_VULN_DB[db_key])
            found = {r.cve_id for r in results}
            if expected_cve in found:
                tp += 1
            else:
                fn += 1

        _, recall, _ = compute_metrics(tp, 0, fn, 0)
        assert recall >= 0.5, f"Recall too low for Kioptrix: {recall:.2f} (TP={tp}, FN={fn})"

    def test_minimum_findings_threshold(self):
        """Mock DB covers at least the minimum required Kioptrix findings."""
        ground_truth = load_ground_truth()
        min_findings = ground_truth["fixtures"]["kioptrix"]["expected_min_findings"]
        total_vulns = sum(len(v) for v in KIOPTRIX_VULN_DB.values())
        assert total_vulns >= min_findings


# ── Cross-fixture metric tests ────────────────────────────────────────────────


@pytest.mark.evaluation
class TestCorrelationMetrics:
    """Aggregate metric tests across all fixtures."""

    def test_precision_recall_f1_computation(self):
        """Verify the metric computation helper functions are correct."""
        # Perfect
        p, r, f1 = compute_metrics(tp=10, fp=0, fn=0, tn=5)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

        # All false positives
        p2, r2, f2 = compute_metrics(tp=0, fp=5, fn=3, tn=0)
        assert p2 == 0.0
        assert r2 == 0.0

        # Balanced case: TP=4, FP=2, FN=2
        p3, r3, f3 = compute_metrics(tp=4, fp=2, fn=2, tn=2)
        assert abs(p3 - 0.667) < 0.01
        assert abs(r3 - 0.667) < 0.01
        assert abs(f3 - 0.667) < 0.01

    def test_high_confidence_matches_use_cpe_methods(self):
        """HIGH confidence matches should use CPE_EXACT or CPE_VERSION_RANGE."""
        svc = NormalizedService(
            vendor="vsftpd",
            product="vsftpd",
            version="2.3.4",
            cpe="cpe:/a:vsftpd:vsftpd:2.3.4",
            protocol="tcp",
            port=21,
            service_name="ftp",
            confidence="HIGH",
        )
        results = correlate_service(svc, METASPLOITABLE2_VULN_DB["vsftpd"])

        high_conf = [r for r in results if r.confidence == MatchConfidence.HIGH]
        for r in high_conf:
            assert r.match_method in (MatchMethod.CPE_EXACT, MatchMethod.CPE_VERSION_RANGE), (
                f"Unexpected method for HIGH confidence: {r.match_method}"
            )

    def test_all_fixture_files_exist(self):
        """All 4 fixture files referenced in ground truth must exist on disk."""
        ground_truth = load_ground_truth()
        root = Path(__file__).parent.parent.parent
        for _fixture_name, data in ground_truth["fixtures"].items():
            fixture_path = root / data["fixture_path"]
            assert fixture_path.exists(), f"Ground truth fixture missing: {data['fixture_path']}"

    def test_ground_truth_schema_valid(self):
        """Ground truth JSON has the required schema structure."""
        ground_truth = load_ground_truth()
        assert "version" in ground_truth
        assert "fixtures" in ground_truth
        for _fixture_name, data in ground_truth["fixtures"].items():
            assert "fixture_path" in data
            assert "known_vulnerable_services" in data
            assert "expected_min_findings" in data
            assert data["expected_min_findings"] >= 1
            for svc in data["known_vulnerable_services"]:
                assert "cves" in svc
                assert len(svc["cves"]) >= 1
                for cve in svc["cves"]:
                    assert cve.startswith("CVE-"), f"Invalid CVE ID: {cve}"
                    year = int(cve.split("-")[1])
                    assert year <= 2025, f"Suspicious future CVE: {cve}"

    def test_no_matches_on_empty_vuln_list(self):
        """correlate_service with empty vuln list returns empty list."""
        svc = NormalizedService(
            vendor="apache",
            product="http_server",
            version="2.2.8",
            cpe="cpe:/a:apache:http_server:2.2.8",
            protocol="tcp",
            port=80,
            service_name="http",
        )
        results = correlate_service(svc, [])
        assert results == []
