"""
Nmap XML output parser for AEGIS-Recon.

Parses Nmap's XML output (-oX) into structured Python dataclasses.
Uses xml.etree.ElementTree (stdlib) — no external XML libs needed.

Design:
- Extracts hosts, ports, services, versions, CPE strings, OS matches, and scripts.
- All extracted text (banners, service info) is treated as UNTRUSTED data.
- Parser never raises untyped exceptions — all errors are MalformedXMLError or ParserError.
- Empty/partial results produce valid (possibly empty) ParsedScan objects, not crashes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.errors import MalformedXMLError, ParserError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Maximum banner/version string length to store (prevents DoS via huge banners)
MAX_BANNER_LENGTH = 512


@dataclass
class ParsedService:
    """A single service detected on a port."""

    port: int
    protocol: str  # "tcp" or "udp"
    state: str  # "open", "closed", "filtered"
    service_name: str  # e.g., "http", "ssh"
    product: str = ""  # e.g., "Apache httpd"
    version: str = ""  # e.g., "2.4.49"
    extra_info: str = ""
    cpe: list[str] = field(default_factory=list)  # CPE URIs from Nmap
    banner: str = ""  # Raw service banner (truncated)
    scripts: dict[str, str] = field(default_factory=dict)  # Script ID → output


@dataclass
class ParsedHost:
    """A single host from the scan."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"  # "up", "down"
    os_matches: list[dict[str, str]] = field(default_factory=list)  # [{name, accuracy, cpe}]
    services: list[ParsedService] = field(default_factory=list)


@dataclass
class ParsedScan:
    """Complete parsed Nmap scan result."""

    scanner: str = "nmap"
    scanner_version: str = ""
    scan_args: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None
    hosts: list[ParsedHost] = field(default_factory=list)
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0


def parse_nmap_xml(xml_content: str) -> ParsedScan:
    """
    Parse Nmap XML output into structured data.

    Args:
        xml_content: Raw XML string from Nmap's -oX output.

    Returns:
        ParsedScan containing all hosts, services, and metadata.

    Raises:
        MalformedXMLError: If the XML is invalid or missing critical elements.
        ParserError: If an unexpected error occurs during parsing.
    """
    if not xml_content or not xml_content.strip():
        raise MalformedXMLError("Empty XML content.")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise MalformedXMLError(
            f"Invalid XML: {e}",
            detail="The Nmap output file is not valid XML.",
        ) from e

    # Verify this is Nmap XML
    if root.tag != "nmaprun":
        raise MalformedXMLError(
            f"Unexpected root element: '{root.tag}' (expected 'nmaprun').",
            detail="This does not appear to be Nmap XML output.",
        )

    try:
        scan = ParsedScan(
            scanner=root.get("scanner", "nmap"),
            scanner_version=root.get("version", ""),
            scan_args=root.get("args", ""),
            start_time=_parse_timestamp(root.get("start")),
        )

        # Parse run stats
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                scan.end_time = _parse_timestamp(finished.get("time"))

            hosts_elem = runstats.find("hosts")
            if hosts_elem is not None:
                scan.hosts_up = int(hosts_elem.get("up", 0))
                scan.hosts_down = int(hosts_elem.get("down", 0))
                scan.hosts_total = int(hosts_elem.get("total", 0))

        # Parse each host
        for host_elem in root.findall("host"):
            host = _parse_host(host_elem)
            if host is not None:
                scan.hosts.append(host)

        logger.info(
            "xml_parsed",
            hosts_found=len(scan.hosts),
            total_services=sum(len(h.services) for h in scan.hosts),
        )

        return scan

    except MalformedXMLError:
        raise
    except Exception as e:
        raise ParserError(
            f"Unexpected error parsing Nmap XML: {e}",
        ) from e


def _parse_host(host_elem: ET.Element) -> ParsedHost | None:
    """Parse a single <host> element."""
    # Get IP address
    ip = ""
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            ip = addr.get("addr", "")
            break

    if not ip:
        logger.debug("host_skipped_no_ip")
        return None

    # Host status
    status_elem = host_elem.find("status")
    status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    # Hostnames
    hostnames: list[str] = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name", "").strip()
            if name:
                hostnames.append(name[:MAX_BANNER_LENGTH])

    # OS detection
    os_matches: list[dict[str, str]] = []
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            match_info: dict[str, str] = {
                "name": osmatch.get("name", "")[:MAX_BANNER_LENGTH],
                "accuracy": osmatch.get("accuracy", "0"),
            }
            # Get CPE for OS
            for osclass in osmatch.findall("osclass"):
                for cpe in osclass.findall("cpe"):
                    if cpe.text:
                        match_info["cpe"] = cpe.text.strip()[:MAX_BANNER_LENGTH]
                        break
            os_matches.append(match_info)

    # Parse ports/services
    services: list[ParsedService] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            service = _parse_port(port_elem)
            if service is not None:
                services.append(service)

    return ParsedHost(
        ip=ip,
        hostnames=hostnames,
        status=status,
        os_matches=os_matches,
        services=services,
    )


def _parse_port(port_elem: ET.Element) -> ParsedService | None:
    """Parse a single <port> element."""
    try:
        port = int(port_elem.get("portid", 0))
    except (ValueError, TypeError):
        return None

    if port <= 0 or port > 65535:
        return None

    protocol = port_elem.get("protocol", "tcp")

    # Port state
    state_elem = port_elem.find("state")
    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

    # Service info
    service_elem = port_elem.find("service")
    service_name = ""
    product = ""
    version = ""
    extra_info = ""
    cpes: list[str] = []
    banner = ""

    if service_elem is not None:
        service_name = service_elem.get("name", "")[:MAX_BANNER_LENGTH]
        product = service_elem.get("product", "")[:MAX_BANNER_LENGTH]
        version = service_elem.get("version", "")[:MAX_BANNER_LENGTH]
        extra_info = service_elem.get("extrainfo", "")[:MAX_BANNER_LENGTH]

        # Extract CPE strings
        for cpe_elem in service_elem.findall("cpe"):
            if cpe_elem.text:
                cpes.append(cpe_elem.text.strip()[:MAX_BANNER_LENGTH])

        # Build a displayable banner from available info
        parts = [p for p in [product, version, extra_info] if p]
        banner = " ".join(parts)[:MAX_BANNER_LENGTH]

    # Script outputs
    scripts: dict[str, str] = {}
    for script_elem in port_elem.findall("script"):
        script_id = script_elem.get("id", "")
        script_output = script_elem.get("output", "")[:MAX_BANNER_LENGTH]
        if script_id:
            scripts[script_id] = script_output

    return ParsedService(
        port=port,
        protocol=protocol,
        state=state,
        service_name=service_name,
        product=product,
        version=version,
        extra_info=extra_info,
        cpe=cpes,
        banner=banner,
        scripts=scripts,
    )


def _parse_timestamp(ts: str | None) -> datetime | None:
    """Parse a Unix timestamp string into a UTC datetime."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None
