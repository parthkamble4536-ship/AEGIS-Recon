"""
Fixed Nmap scan profiles for AEGIS-Recon.

Each profile defines a safe, pre-validated set of Nmap arguments.
Users select a profile name; they never supply raw Nmap flags.
This prevents argument injection attacks.

Profile design:
- All profiles produce XML output (-oX).
- No aggressive timing below T3 to avoid detection issues.
- Service version detection (-sV) is on for standard+.
- OS detection (-O) only in thorough (needs root/admin).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """A fixed set of Nmap scan arguments."""

    name: str
    description: str
    # The nmap arguments (each element is one arg — never joined into a shell string)
    arguments: tuple[str, ...]
    # Whether this profile requires elevated privileges (root/admin)
    requires_privileged: bool = False
    # Estimated time multiplier relative to quick scan
    time_factor: float = 1.0


# ── Profile Definitions ─────────────────────────────────

QUICK = ScanProfile(
    name="quick",
    description="Fast TCP SYN scan of top 100 ports with service version detection.",
    arguments=(
        "-sS",          # TCP SYN scan (stealthier, needs raw sockets)
        "-sV",          # Service version detection
        "--top-ports", "100",
        "-T4",          # Aggressive timing
        "--open",       # Only show open ports
        "--max-retries", "1",
        "--host-timeout", "60s",
    ),
    requires_privileged=True,
    time_factor=1.0,
)

STANDARD = ScanProfile(
    name="standard",
    description="TCP SYN scan of top 1000 ports with version detection and default scripts.",
    arguments=(
        "-sS",          # TCP SYN scan
        "-sV",          # Service version detection
        "-sC",          # Default safe scripts
        "--top-ports", "1000",
        "-T3",          # Normal timing
        "--open",
        "--max-retries", "2",
        "--host-timeout", "120s",
    ),
    requires_privileged=True,
    time_factor=3.0,
)

THOROUGH = ScanProfile(
    name="thorough",
    description="Full TCP port scan with version, OS detection, and safe scripts.",
    arguments=(
        "-sS",          # TCP SYN scan
        "-sV",          # Service version detection
        "-sC",          # Default safe scripts
        "-O",           # OS detection
        "-p-",          # All 65535 ports
        "-T3",
        "--open",
        "--max-retries", "3",
        "--host-timeout", "300s",
        "--version-intensity", "5",
    ),
    requires_privileged=True,
    time_factor=10.0,
)


# Registry of all available profiles
PROFILES: dict[str, ScanProfile] = {
    "quick": QUICK,
    "standard": STANDARD,
    "thorough": THOROUGH,
}


def get_profile(name: str) -> ScanProfile | None:
    """
    Look up a scan profile by name.

    Args:
        name: Profile name (case-insensitive).

    Returns:
        The ScanProfile if found, None otherwise.
    """
    return PROFILES.get(name.lower())
