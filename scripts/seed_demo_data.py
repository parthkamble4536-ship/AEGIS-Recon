"""
Multi-target demo scan data seeder for AEGIS-Recon.

Seeds realistic, verified reconnaissance and vulnerability data for:
1. Metasploitable 2 (Ubuntu 8.04 Linux 2.6 Baseline) — 192.168.56.101
2. Metasploitable 3 Windows (Windows Server 2016) — 192.168.56.102
3. Metasploitable 3 Linux (Ubuntu 14.04 Trusty) — 192.168.56.103
4. VulnHub Kioptrix Level 1 (RedHat Linux 9.0) — 192.168.56.104

Allows testing and demonstrating cross-platform evaluation immediately
without requiring live virtual machines running on the host.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.database import get_db, init_db  # noqa: E402
from app.db.repository import save_finding, save_parsed_scan, save_scan  # noqa: E402
from app.parser.nmap_xml import parse_nmap_xml  # noqa: E402
from app.risk.scoring import calculate_risk  # noqa: E402
from app.scanner.runner import ScanResult  # noqa: E402

FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"

# ══════════════════════════════════════════════════════════════
# Target Data Configurations
# ══════════════════════════════════════════════════════════════

TARGET_CONFIGS: dict[str, dict[str, Any]] = {
    "metasploitable2": {
        "scan_id": "demo-metasploitable2",
        "target": "192.168.56.101",
        "name": "Metasploitable 2 - Linux 2.6 Legacy Baseline",
        "fixture_file": "metasploitable2_scan.xml",
        "profile": "quick",
        "command_args": ["-sS", "-sV", "--top-ports", "100", "-T4", "--open"],
        "cves": [
            {
                "port": 21,
                "cve_id": "CVE-2011-2523",
                "title": "vsftpd 2.3.4 Backdoor Execution",
                "description": "vsftpd 2.3.4 contains a backdoor in the smiley sequence :) that spawns a root shell on port 6200.",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Exact CPE match: cpe:/a:vsftpd:vsftpd:2.3.4 matches vulnerable configuration.",
                "is_kev": True,
                "kev_due_date": "2021-11-17",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
            },
            {
                "port": 139,
                "cve_id": "CVE-2007-2447",
                "title": "Samba MS-RPC Remote Command Execution",
                "description": "The MS-RPC functionality in Samba 3.0.0-3.0.25rc3 allows remote attackers to execute arbitrary commands via the username map script parameter.",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Samba 3.X version matches CISA KEV catalog exploit range.",
                "is_kev": True,
                "kev_due_date": "2022-03-03",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
            },
            {
                "port": 80,
                "cve_id": "CVE-2011-3192",
                "title": "Apache HTTP Server Byte Range Denial of Service",
                "description": "The byte-range request handler in Apache 2.2.x allows remote attackers to cause a denial of service via overlapping byte ranges.",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Apache 2.2.8 is within affected range < 2.2.20.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2011-3192",
            },
            {
                "port": 22,
                "cve_id": "CVE-2008-0166",
                "title": "OpenSSL Debian Predictable PRNG (Weak SSH Keys)",
                "description": "OpenSSH packages on Debian systems generate predictable keys due to an uninitialized memory fix in OpenSSL.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "OpenSSH 4.7p1 Debian 8ubuntu1 banner match. Requires key check.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2008-0166",
            },
            {
                "port": 3306,
                "cve_id": "CVE-2012-2122",
                "title": "MySQL Authentication Bypass",
                "description": "MySQL 5.0.x/5.1.x allows remote attackers to bypass authentication with 1 in 256 probability due to incorrect memcmp return casting.",
                "cvss_score": 6.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "medium",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "MySQL 5.0.51a version match. Architecture dependent.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
            },
        ],
    },
    "metasploitable3-win": {
        "scan_id": "demo-metasploitable3-win",
        "target": "192.168.56.102",
        "name": "Metasploitable 3 - Windows Server 2016 Enterprise Stack",
        "fixture_file": "metasploitable3_win_scan.xml",
        "profile": "standard",
        "command_args": ["-sS", "-sV", "-sC", "-T4", "--open", "192.168.56.102"],
        "cves": [
            {
                "port": 445,
                "cve_id": "CVE-2017-0143",
                "title": "MS17-010 EternalBlue SMB Remote Code Execution",
                "description": "The SMBv1 server in Microsoft Windows Server 2016 allows remote code execution via specially crafted packets.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "SMBv1/microsoft-ds banner detected on Windows Server 2016 (Build 14393).",
                "is_kev": True,
                "kev_due_date": "2022-04-15",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0143",
            },
            {
                "port": 8484,
                "cve_id": "CVE-2015-8103",
                "title": "Jenkins CLI Commons-Collections Deserialization RCE",
                "description": "Jenkins before 1.638 allows remote code execution via serialized Java objects sent to the CLI port.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Jenkins version 1.637 detected on port 8484.",
                "is_kev": True,
                "kev_due_date": "2022-05-03",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-8103",
            },
            {
                "port": 9200,
                "cve_id": "CVE-2014-3120",
                "title": "Elasticsearch MVEL Dynamic Scripting RCE",
                "description": "Elasticsearch before 1.2 allows remote code execution via dynamic MVEL scripting in search API payloads.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Elasticsearch REST API version 1.1.1 matches vulnerable MVEL script range.",
                "is_kev": True,
                "kev_due_date": "2022-04-18",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3120",
            },
            {
                "port": 8080,
                "cve_id": "CVE-2017-12615",
                "title": "Apache Tomcat PUT Method JSP Upload RCE",
                "description": "When running on Windows with readonly=false, Apache Tomcat 8.0.33 allows remote code execution via PUT method upload of JSP files.",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Tomcat 8.0.33 confirmed on Windows Server 2016 host.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-12615",
            },
            {
                "port": 80,
                "cve_id": "CVE-2017-7269",
                "title": "Microsoft IIS WebDAV ScStoragePathFromUrl Buffer Overflow",
                "description": "Buffer overflow in the WebDAV service in Microsoft IIS allows remote attackers to execute arbitrary code via long 'If: <http://' headers.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "Microsoft-IIS 10.0 WebDAV extension detected on port 80.",
                "is_kev": True,
                "kev_due_date": "2022-03-15",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
            },
            {
                "port": 4848,
                "cve_id": "CVE-2017-1000028",
                "title": "Oracle GlassFish Server Path Traversal",
                "description": "Oracle GlassFish Server 4.0 allows remote unauthenticated attackers to read arbitrary files via directory traversal in the admin console.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Oracle GlassFish Server 4.0 detected on port 4848.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000028",
            },
            {
                "port": 3306,
                "cve_id": "CVE-2016-6662",
                "title": "MySQL Remote Root Code Execution",
                "description": "MySQL 5.7 before 5.7.15 allows attackers to execute arbitrary code by injecting settings into my.cnf configuration files.",
                "cvss_score": 8.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "MySQL 5.7.12 version is within vulnerable range < 5.7.15.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662",
            },
        ],
    },
    "metasploitable3-linux": {
        "scan_id": "demo-metasploitable3-linux",
        "target": "192.168.56.103",
        "name": "Metasploitable 3 - Ubuntu 14.04 Linux Web Stack",
        "fixture_file": "metasploitable3_linux_scan.xml",
        "profile": "standard",
        "command_args": ["-sS", "-sV", "-sC", "-T4", "--open", "192.168.56.103"],
        "cves": [
            {
                "port": 21,
                "cve_id": "CVE-2015-3306",
                "title": "ProFTPD mod_copy Arbitrary File Copy RCE",
                "description": "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write arbitrary files via SITE CPFR and SITE CPTO commands.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "ProFTPD 1.3.5 banner match on port 21.",
                "is_kev": True,
                "kev_due_date": "2022-05-03",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
            },
            {
                "port": 6697,
                "cve_id": "CVE-2010-2075",
                "title": "UnrealIRCd 3.2.8.1 DEBUG3 Backdoor Execution",
                "description": "UnrealIRCd contains a backdoor that allows attackers to execute arbitrary system commands via a DEBUG3 message.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "UnrealIRCd daemon detected on IRC port 6697.",
                "is_kev": True,
                "kev_due_date": "2022-04-18",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2010-2075",
            },
            {
                "port": 22,
                "cve_id": "CVE-2015-5600",
                "title": "OpenSSH MaxAuthTries Keyboard-Interactive Bypass",
                "description": "The kbdint_next_device function in OpenSSH 6.x allows brute-force password guessing by bypassing MaxAuthTries.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "OpenSSH 6.6.1p1 detected on Ubuntu 14.04.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-5600",
            },
            {
                "port": 80,
                "cve_id": "CVE-2017-15715",
                "title": "Apache HTTP Server <FilesMatch> Newline Bypass",
                "description": "In Apache 2.4.0-2.4.29, expression matching can be bypassed with a trailing newline character, allowing malicious file upload.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Apache 2.4.7 Ubuntu banner match.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-15715",
            },
            {
                "port": 631,
                "cve_id": "CVE-2015-1158",
                "title": "CUPS IPP String Reference Count Overflow RCE",
                "description": "String reference counting bug in CUPS 1.7 allows attackers to execute arbitrary code via cross-site requests to IPP.",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "CUPS 1.7 detected on port 631.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-1158",
            },
            {
                "port": 9200,
                "cve_id": "CVE-2014-3120",
                "title": "Elasticsearch MVEL Dynamic Scripting RCE",
                "description": "Elasticsearch 1.1.1 allows remote execution of arbitrary code via MVEL expression evaluation.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Elasticsearch REST API version 1.1.1 on port 9200.",
                "is_kev": True,
                "kev_due_date": "2022-04-18",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3120",
            },
        ],
    },
    "kioptrix": {
        "scan_id": "demo-kioptrix",
        "target": "192.168.56.104",
        "name": "VulnHub Kioptrix Level 1 - Real-World Hardened CTF",
        "fixture_file": "kioptrix_scan.xml",
        "profile": "standard",
        "command_args": ["-sS", "-sV", "-sC", "-T4", "--open", "192.168.56.104"],
        "cves": [
            {
                "port": 139,
                "cve_id": "CVE-2003-0201",
                "title": "Samba trans2open Remote Root Buffer Overflow",
                "description": "Buffer overflow in the trans2open function in Samba 2.2.x allows remote attackers to execute arbitrary code as root.",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Samba 2.2.1a detected on NetBIOS-SSN port 139.",
                "is_kev": True,
                "kev_due_date": "2022-03-03",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2003-0201",
            },
            {
                "port": 80,
                "cve_id": "CVE-2002-0082",
                "title": "Apache mod_ssl OpenFuck Remote Heap Overflow",
                "description": "Heap buffer overflow in mod_ssl 2.8.4 allows remote execution of arbitrary code via malicious SSL client handshakes.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Apache 1.3.20 mod_ssl/2.8.4 OpenSSL/0.9.6b banner match on port 80/443.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2002-0082",
            },
            {
                "port": 1024,
                "cve_id": "CVE-2000-0666",
                "title": "Linux rpc.statd Remote Root Format String Bug",
                "description": "Format string vulnerability in rpc.statd in Linux NFS-utils allows remote attackers to execute arbitrary code with root privileges.",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical",
                "confidence": "high",
                "evidence_type": "external_intelligence",
                "evidence_detail": "Linux rpc.statd version 1 detected on high port 1024.",
                "is_kev": True,
                "kev_due_date": "2022-04-18",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2000-0666",
            },
            {
                "port": 22,
                "cve_id": "CVE-2001-0554",
                "title": "OpenSSH 2.9p2 AFS/Kerberos Buffer Overflow",
                "description": "Buffer overflow in OpenSSH 2.9p2 allows remote attackers to execute arbitrary code via Kerberos or AFS authentication.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high",
                "confidence": "medium",
                "evidence_type": "hypothesis",
                "evidence_detail": "OpenSSH 2.9p2 protocol 1.99 banner match.",
                "is_kev": False,
                "kev_due_date": "",
                "source": "NVD",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2001-0554",
            },
        ],
    },
}


def seed_target(key: str) -> str:
    """Seed a specific target environment from its XML fixture."""
    config = TARGET_CONFIGS[key]
    scan_id = config["scan_id"]
    target = config["target"]
    fixture_path = FIXTURES_DIR / config["fixture_file"]

    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture file not found: {fixture_path}")

    xml_text = fixture_path.read_text(encoding="utf-8")
    parsed = parse_nmap_xml(xml_text)

    # 1. Clean existing records for this scan_id
    with get_db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM services WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM hosts WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # 2. Save scan record
    scan_result = ScanResult(
        scan_id=scan_id,
        target=target,
        profile=config["profile"],
        status="completed",
        xml_output=xml_text,
        start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
        end_time=datetime(2023, 10, 12, 12, 1, 0, tzinfo=UTC),
        nmap_version="7.94",
        command_args=config["command_args"],
        exit_code=0,
    )
    save_scan(scan_result)

    # 3. Save hosts and services
    summary = save_parsed_scan(scan_id, parsed)

    # 4. Map created services by port
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, port, service_name, product, version FROM services WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        services_by_port = {r["port"]: dict(r) for r in rows}

    # 5. Attach findings with 6-factor risk scoring
    findings_count = 0
    for item in config["cves"]:
        port = item["port"]
        svc = services_by_port.get(port)
        if not svc:
            continue

        risk = calculate_risk(
            cvss_score=item["cvss_score"],
            cvss_severity=item["severity"],
            confidence=item["confidence"],
            evidence_type=item["evidence_type"],
            is_kev=item["is_kev"],
            service_name=svc.get("service_name", ""),
            port=port,
        )

        finding_dict = {
            "scan_id": scan_id,
            "service_id": svc["id"],
            "cve_id": item["cve_id"],
            "title": item["title"],
            "description": item["description"],
            "cvss_score": item["cvss_score"],
            "cvss_vector": item["cvss_vector"],
            "severity": item["severity"],
            "confidence": item["confidence"],
            "evidence_type": item["evidence_type"],
            "evidence_detail": item["evidence_detail"],
            "source": item["source"],
            "source_url": item["source_url"],
            "is_kev": 1 if item["is_kev"] else 0,
            "kev_due_date": item["kev_due_date"],
            "priority_score": risk.priority_score,
            "priority_factors": risk.factors,
            "match_detail": json.dumps({"source": "evaluation_corpus"}),
            "intel_timestamp": datetime.now(UTC).isoformat(),
        }
        save_finding(finding_dict)
        findings_count += 1

    print(f"[+] Seeded {config['name']}")
    print(f"    Target IP: {target} | Scan ID: {scan_id}")
    print(f"    Services: {summary['services_saved']} | Findings: {findings_count}")
    return scan_id


def seed_demo_data(target_key: str = "all") -> list[str]:
    """Seed demo data for specified target or all targets."""
    settings = get_settings()
    init_db(settings.database_path)

    seeded: list[str] = []
    if target_key == "all":
        print("[*] Seeding complete multi-target evaluation corpus (4 environments)...")
        for key in TARGET_CONFIGS:
            seeded.append(seed_target(key))
    elif target_key in TARGET_CONFIGS:
        seeded.append(seed_target(target_key))
    else:
        print(f"[!] Unknown target: {target_key}. Choose from: {list(TARGET_CONFIGS.keys())} or 'all'")
        sys.exit(1)

    print("\n[+] Evaluation corpus successfully initialized in SQLite database!")
    print("    Open http://127.0.0.1:8000/ to view the full multi-machine dashboard.")
    return seeded


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed multi-target evaluation corpus into AEGIS-Recon DB")
    parser.add_argument(
        "--target",
        default="all",
        choices=["all", "metasploitable2", "metasploitable3-win", "metasploitable3-linux", "kioptrix"],
        help="Target environment to seed (default: all)",
    )
    args = parser.parse_args()
    seed_demo_data(args.target)
