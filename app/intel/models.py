"""
Normalized service model for AEGIS-Recon correlation engine.

Provides a structured representation of a discovered service after
normalization from Nmap scan output, suitable for correlation against
CVE intelligence sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NormalizedService:
    """
    A service discovered by Nmap, normalized for vulnerability correlation.

    Fields are populated from Nmap XML output and used by the correlation
    engine to match against NVD CVE data with explicit confidence levels.
    """

    vendor: str = ""
    product: str = ""
    version: str = ""
    version_start: str = ""  # version range start (inclusive), if known
    version_end: str = ""  # version range end (inclusive), if known
    cpe: str = ""  # primary CPE URI (e.g. "cpe:/a:openbsd:openssh:7.2p2")
    protocol: str = ""  # "tcp" or "udp"
    port: int = 0
    service_name: str = ""  # Nmap service name (e.g. "ssh", "http")
    banner: str = ""  # raw banner if available
    confidence: str = "LOW"  # HIGH / MEDIUM / LOW — Nmap's own detection confidence
    extra_cpes: list[str] = field(default_factory=list)  # additional CPEs if multiple

