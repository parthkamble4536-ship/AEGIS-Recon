"""
Unit tests for the Nmap XML parser.

Tests cover:
- Full Metasploitable 2 XML fixture (hosts, services, CPE, OS, scripts)
- Empty/host-down scan
- Malformed XML
- Missing elements
- Edge cases (no version, unusual ports)
"""

from __future__ import annotations

import pytest

from app.core.errors import MalformedXMLError
from app.parser.nmap_xml import ParsedScan, parse_nmap_xml


class TestParseMetasploitableXML:
    """Parse the Metasploitable 2 scan fixture."""

    def test_parses_without_error(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        assert isinstance(result, ParsedScan)

    def test_scanner_metadata(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        assert result.scanner == "nmap"
        assert result.scanner_version == "7.94"
        assert "192.168.56.101" in result.scan_args

    def test_host_count(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        assert len(result.hosts) == 1
        assert result.hosts_up == 1
        assert result.hosts_down == 0
        assert result.hosts_total == 1

    def test_host_ip(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert host.ip == "192.168.56.101"
        assert host.status == "up"

    def test_hostnames(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert "metasploitable.localdomain" in host.hostnames

    def test_service_count(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert len(host.services) == 10

    def test_ftp_service(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        ftp = next(s for s in result.hosts[0].services if s.port == 21)
        assert ftp.service_name == "ftp"
        assert ftp.product == "vsftpd"
        assert ftp.version == "2.3.4"
        assert ftp.state == "open"
        assert ftp.protocol == "tcp"
        assert "cpe:/a:vsftpd:vsftpd:2.3.4" in ftp.cpe

    def test_ssh_service(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        ssh = next(s for s in result.hosts[0].services if s.port == 22)
        assert ssh.service_name == "ssh"
        assert ssh.product == "OpenSSH"
        assert "4.7p1" in ssh.version
        assert "cpe:/a:openbsd:openssh:4.7p1" in ssh.cpe

    def test_http_service_with_scripts(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        http = next(s for s in result.hosts[0].services if s.port == 80)
        assert http.service_name == "http"
        assert http.product == "Apache httpd"
        assert http.version == "2.2.8"
        assert "http-title" in http.scripts
        assert "Metasploitable2" in http.scripts["http-title"]

    def test_mysql_cpe(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        mysql = next(s for s in result.hosts[0].services if s.port == 3306)
        assert mysql.product == "MySQL"
        assert len(mysql.cpe) >= 1

    def test_os_detection(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        host = result.hosts[0]
        assert len(host.os_matches) >= 1
        assert "Linux" in host.os_matches[0]["name"]
        assert host.os_matches[0]["accuracy"] == "95"

    def test_timestamps(self, metasploitable_xml: str) -> None:
        result = parse_nmap_xml(metasploitable_xml)
        assert result.start_time is not None
        assert result.end_time is not None
        assert result.end_time > result.start_time

    def test_service_without_version(self, metasploitable_xml: str) -> None:
        """Telnet service in fixture has no version — should parse cleanly."""
        result = parse_nmap_xml(metasploitable_xml)
        telnet = next(s for s in result.hosts[0].services if s.port == 23)
        assert telnet.service_name == "telnet"
        assert telnet.version == ""  # No version is fine


class TestParseEmptyScan:
    """Parse a scan with no open ports (host down)."""

    def test_parses_without_error(self, empty_scan_xml: str) -> None:
        result = parse_nmap_xml(empty_scan_xml)
        assert isinstance(result, ParsedScan)

    def test_host_down(self, empty_scan_xml: str) -> None:
        result = parse_nmap_xml(empty_scan_xml)
        assert result.hosts_up == 0
        assert result.hosts_down == 1

    def test_no_services(self, empty_scan_xml: str) -> None:
        result = parse_nmap_xml(empty_scan_xml)
        # Host is present but has no services
        for host in result.hosts:
            assert len(host.services) == 0


class TestParseEdgeCases:
    """Edge cases and error handling."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(MalformedXMLError, match="Empty"):
            parse_nmap_xml("")

    def test_none_like_raises(self) -> None:
        with pytest.raises(MalformedXMLError, match="Empty"):
            parse_nmap_xml("   ")

    def test_invalid_xml_raises(self) -> None:
        with pytest.raises(MalformedXMLError, match="Invalid XML"):
            parse_nmap_xml("<not>valid<xml>")

    def test_non_nmap_xml_raises(self) -> None:
        with pytest.raises(MalformedXMLError, match="Unexpected root"):
            parse_nmap_xml('<?xml version="1.0"?><html><body>Not Nmap</body></html>')

    def test_minimal_valid_xml(self) -> None:
        xml = '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>'
        result = parse_nmap_xml(xml)
        assert result.scanner == "nmap"
        assert len(result.hosts) == 0

    def test_host_without_address(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host><status state="up"/></host>
        </nmaprun>"""
        result = parse_nmap_xml(xml)
        # Host without IP should be skipped
        assert len(result.hosts) == 0

    def test_port_with_no_service_info(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="12345">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(xml)
        assert len(result.hosts) == 1
        assert len(result.hosts[0].services) == 1
        svc = result.hosts[0].services[0]
        assert svc.port == 12345
        assert svc.service_name == ""
        assert svc.product == ""

    def test_banner_truncation(self) -> None:
        """Extremely long product names should be truncated."""
        long_product = "A" * 1000
        xml = f"""<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="{long_product}"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(xml)
        svc = result.hosts[0].services[0]
        assert len(svc.product) <= 512  # MAX_BANNER_LENGTH
