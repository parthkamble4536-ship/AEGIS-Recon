"""
Seed realistic demo scan data into AEGIS-Recon SQLite database.

Allows testing the Web Dashboard (GUI) and CLI immediately without
requiring a live Nmap installation or external network scan.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.database import get_db, init_db  # noqa: E402
from app.db.repository import save_finding, save_parsed_scan, save_scan  # noqa: E402
from app.parser.nmap_xml import parse_nmap_xml  # noqa: E402
from app.risk.scoring import calculate_risk  # noqa: E402
from app.scanner.runner import ScanResult  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_XML = PROJECT_ROOT / "tests" / "fixtures" / "metasploitable2_scan.xml"


def seed_demo_data() -> str:
    settings = get_settings()
    init_db(settings.database_path)

    xml_text = FIXTURE_XML.read_text(encoding="utf-8")
    parsed = parse_nmap_xml(xml_text)

    scan_id = "demo-metasploitable2"

    # Clean existing demo scan if present
    with get_db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM services WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM hosts WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # 1. Save scan record
    scan_result = ScanResult(
        scan_id=scan_id,
        target="192.168.56.101",
        profile="quick",
        status="completed",
        xml_output=xml_text,
        start_time=datetime(2023, 10, 12, 12, 0, 0, tzinfo=UTC),
        end_time=datetime(2023, 10, 12, 12, 0, 35, tzinfo=UTC),
        nmap_version="7.94",
        command_args=["-sS", "-sV", "--top-ports", "100", "-T4", "--open"],
        exit_code=0,
    )
    save_scan(scan_result)

    # 2. Parse and save hosts & services
    summary = save_parsed_scan(scan_id, parsed)

    # 3. Retrieve created services to attach findings
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, port, service_name, product, version FROM services WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        services_by_port = {r["port"]: dict(r) for r in rows}

    # 4. Attach realistic vulnerability findings
    sample_cves = [
        {
            "port": 21,
            "cve_id": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 Backdoor Execution",
            "description": "vsftpd 2.3.4 contains a backdoor in the smile face :) smiley sequence that spawns a root shell on port 6200.",
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
            "port": 80,
            "cve_id": "CVE-2011-3192",
            "title": "Apache HTTP Server Byte Range Denial of Service",
            "description": "The byte-range request handler in Apache 2.2.x allows remote attackers to cause a denial of service via multiple overlapping ranges.",
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
            "description": "OpenSSH packages on Debian-derived systems generate predictable keys due to an improper OpenSSL patch.",
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
            "description": "MySQL 5.0.x/5.1.x allows remote attackers to bypass authentication with 1 in 256 chance due to memcmp casting bug.",
            "cvss_score": 6.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "medium",
            "confidence": "medium",
            "evidence_type": "hypothesis",
            "evidence_detail": "MySQL 5.0.51a version match. Timing/architecture dependent.",
            "is_kev": False,
            "kev_due_date": "",
            "source": "NVD",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
        },
    ]

    for item in sample_cves:
        port = item.pop("port")
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
            "match_detail": json.dumps({"source": "demo_seed"}),
            "intel_timestamp": datetime.now(UTC).isoformat(),
        }
        save_finding(finding_dict)

    print("[+] Successfully seeded demo data!")
    print("    Target: 192.168.56.101")
    print(f"    Scan ID: {scan_id}")
    print(f"    Services saved: {summary['services_saved']}")
    print(f"    Findings saved: {len(sample_cves)}")
    print("\n[>] You can now view this in the Web Dashboard at http://127.0.0.1:8000")
    print(f"    Or via CLI: python scripts/cli.py findings {scan_id}")
    return scan_id


if __name__ == "__main__":
    seed_demo_data()
