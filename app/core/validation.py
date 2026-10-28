"""
Target validation and allowlist enforcement for AEGIS-Recon.

This module is the FIRST security boundary: no input reaches the scanner
without passing through these validators. Every target, port, and profile
is checked against strict rules and the allowlist.

Design decisions:
- Allowlist is loaded from YAML at startup, not from user input.
- IP validation uses stdlib ipaddress (no regex for IPs).
- Hostnames are validated against a strict pattern (no wildcards, no URLs).
- Shell metacharacters are rejected before any other check.
- CIDR allowlist entries expand to cover individual IPs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.core.errors import AllowlistError, AllowlistLoadError, ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Characters that must NEVER appear in any user-supplied target string.
# This blocks shell injection even if a downstream component mishandles the value.
DANGEROUS_CHARS = set(";|&`$(){}[]!#><\\\"'^%")

# Hostname pattern: labels separated by dots, each 1-63 chars, alphanumeric + hyphens.
# No trailing dot, no leading/trailing hyphens per label.
_HOSTNAME_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$")

# Maximum target string length to prevent DoS via oversized inputs
MAX_TARGET_LENGTH = 253  # DNS max hostname length


@dataclass(frozen=True)
class AllowlistEntry:
    """A single entry in the target allowlist."""

    entry_type: str  # "ip", "cidr", "hostname"
    value: str
    description: str = ""
    # For CIDR entries, the parsed network for containment checks
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = field(default=None, repr=False)


@dataclass
class Allowlist:
    """Loaded allowlist configuration."""

    entries: list[AllowlistEntry] = field(default_factory=list)
    allowed_profiles: list[str] = field(default_factory=lambda: ["quick", "standard", "thorough"])
    max_concurrent_scans: int = 2

    @classmethod
    def from_yaml(cls, path: Path) -> Allowlist:
        """
        Load allowlist from a YAML file.

        Args:
            path: Path to the allowlist YAML file.

        Returns:
            Parsed Allowlist instance.

        Raises:
            AllowlistLoadError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise AllowlistLoadError(
                f"Allowlist file not found: {path}",
                detail="Create config/allowlist.yaml with your authorized targets.",
            )

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise AllowlistLoadError(
                f"Failed to parse allowlist YAML: {e}",
                detail="Check config/allowlist.yaml syntax.",
            ) from e

        if not isinstance(data, dict):
            raise AllowlistLoadError("Allowlist YAML must be a mapping at the top level.")

        entries: list[AllowlistEntry] = []
        for item in data.get("targets", []):
            if not isinstance(item, dict):
                continue

            desc = str(item.get("description", ""))

            if "ip" in item:
                ip_str = str(item["ip"]).strip()
                # Validate the allowlisted IP itself
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError as e:
                    raise AllowlistLoadError(f"Invalid IP in allowlist: {ip_str}") from e
                entries.append(AllowlistEntry("ip", ip_str, desc))

            elif "cidr" in item:
                cidr_str = str(item["cidr"]).strip()
                try:
                    network = ipaddress.ip_network(cidr_str, strict=False)
                except ValueError as e:
                    raise AllowlistLoadError(f"Invalid CIDR in allowlist: {cidr_str}") from e
                entries.append(AllowlistEntry("cidr", cidr_str, desc, network=network))

            elif "hostname" in item:
                hostname = str(item["hostname"]).strip().lower()
                entries.append(AllowlistEntry("hostname", hostname, desc))

        allowed_profiles = data.get("allowed_profiles", ["quick", "standard", "thorough"])
        max_concurrent = data.get("max_concurrent_scans", 2)

        logger.info(
            "allowlist_loaded",
            entry_count=len(entries),
            profiles=allowed_profiles,
        )

        return cls(
            entries=entries,
            allowed_profiles=[str(p) for p in allowed_profiles],
            max_concurrent_scans=int(max_concurrent),
        )


def validate_target(target: str, allowlist: Allowlist) -> str:
    """
    Validate and authorize a scan target.

    Checks in order:
    1. Not empty, not too long
    2. No dangerous shell metacharacters
    3. Valid IP address, CIDR range, or hostname format
    4. Target is in the allowlist

    Args:
        target: User-supplied target string.
        allowlist: Loaded allowlist to check against.

    Returns:
        The validated, normalized target string.

    Raises:
        ValidationError: If the target format is invalid.
        AllowlistError: If the target is not authorized.
    """
    # ── Step 1: Basic sanity ──────────────────────────────
    if not target or not target.strip():
        raise ValidationError("Target must not be empty.")

    target = target.strip()

    if len(target) > MAX_TARGET_LENGTH:
        raise ValidationError(f"Target too long ({len(target)} chars, max {MAX_TARGET_LENGTH}).")

    # ── Step 2: Reject dangerous characters ───────────────
    found_dangerous = DANGEROUS_CHARS.intersection(target)
    if found_dangerous:
        logger.warning(
            "dangerous_chars_in_target",
            target_preview=target[:20],
            chars=list(found_dangerous),
        )
        raise ValidationError(
            "Target contains invalid characters.",
            detail=f"Characters not allowed: {sorted(found_dangerous)}",
        )

    # ── Step 3: Determine target type and validate format ─
    target_type = _classify_target(target)

    # ── Step 4: Check allowlist ───────────────────────────
    _check_allowlist(target, target_type, allowlist)

    logger.info("target_validated", target=target, target_type=target_type)
    return target


def _classify_target(target: str) -> str:
    """
    Determine if the target is an IP, CIDR, or hostname and validate format.

    Returns:
        "ip", "cidr", or "hostname".

    Raises:
        ValidationError: If the format doesn't match any valid type.
    """
    # Try IP address first
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    # Try CIDR notation
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            # Reject overly broad scans
            if network.prefixlen < 24:
                raise ValidationError(
                    f"CIDR range too broad: /{network.prefixlen}. Minimum prefix is /24.",
                    detail="Narrow your scan scope to a /24 or smaller.",
                )
            return "cidr"
        except ValueError:
            raise ValidationError(f"Invalid CIDR notation: {target}")

    # Try hostname
    target_lower = target.lower()
    if _HOSTNAME_RE.match(target_lower):
        # Additional hostname safety checks
        if target_lower in ("localhost", "127.0.0.1"):
            raise ValidationError("Cannot scan localhost.")
        return "hostname"

    raise ValidationError(f"Target '{target}' is not a valid IP address, CIDR range, or hostname.")


def _check_allowlist(target: str, target_type: str, allowlist: Allowlist) -> None:
    """
    Verify the target is authorized in the allowlist.

    Raises:
        AllowlistError: If the target is not in the allowlist.
    """
    if not allowlist.entries:
        raise AllowlistError(
            "Allowlist is empty — no targets are authorized.",
            detail="Add targets to config/allowlist.yaml.",
        )

    target_lower = target.lower()

    for entry in allowlist.entries:
        if target_type == "ip" and entry.entry_type == "ip":
            if target == entry.value:
                return

        elif target_type == "ip" and entry.entry_type == "cidr":
            # Check if the IP falls within an allowed CIDR range
            if entry.network is not None:
                try:
                    if ipaddress.ip_address(target) in entry.network:
                        return
                except ValueError:
                    continue

        elif target_type == "cidr" and entry.entry_type == "cidr":
            # The target CIDR must be a subnet of an allowed CIDR
            if entry.network is not None:
                try:
                    target_net = ipaddress.ip_network(target, strict=False)
                    if (
                        target_net.version == entry.network.version
                        and target_net.network_address >= entry.network.network_address  # type: ignore[operator]
                        and target_net.broadcast_address <= entry.network.broadcast_address  # type: ignore[operator]
                    ):
                        return
                except ValueError:
                    continue

        elif target_type == "hostname" and entry.entry_type == "hostname":
            if target_lower == entry.value:
                return

    raise AllowlistError(
        f"Target '{target}' is not in the allowlist.",
        detail="Add this target to config/allowlist.yaml if you are authorized to scan it.",
    )


def validate_ports(ports: str | None) -> str | None:
    """
    Validate a port specification string (e.g., "22,80,443" or "1-1024").

    Args:
        ports: Port specification or None for default ports.

    Returns:
        Validated port string, or None.

    Raises:
        ValidationError: If the port specification is invalid.
    """
    if ports is None:
        return None

    ports = ports.strip()
    if not ports:
        return None

    # Only allow digits, commas, hyphens, and 'T:' / 'U:' protocol prefixes
    if not re.match(r"^[TU:,\d\-\s]+$", ports):
        raise ValidationError(
            "Port specification contains invalid characters.",
            detail="Use formats like '22,80,443' or '1-1024' or 'T:80,U:53'.",
        )

    # Validate individual port numbers
    # Strip protocol prefixes for validation
    clean = re.sub(r"[TU]:", "", ports)
    for part in clean.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValidationError(f"Invalid port range: {part}")
            try:
                low, high = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise ValidationError(f"Invalid port range: {part}")
            if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
                raise ValidationError(f"Port range out of bounds: {part}")
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValidationError(f"Invalid port number: {part}")
            if not 1 <= port <= 65535:
                raise ValidationError(f"Port out of range: {port}")

    return ports


def validate_profile(profile: str, allowlist: Allowlist) -> str:
    """
    Validate a scan profile name against allowed profiles.

    Args:
        profile: Profile name to validate.
        allowlist: Allowlist containing the allowed profile list.

    Returns:
        Validated profile name (lowercased).

    Raises:
        ValidationError: If the profile is not allowed.
    """
    profile = profile.strip().lower()

    if not profile:
        raise ValidationError("Scan profile must not be empty.")

    # Reject dangerous characters even in profile names
    if DANGEROUS_CHARS.intersection(profile):
        raise ValidationError("Profile name contains invalid characters.")

    if profile not in allowlist.allowed_profiles:
        raise ValidationError(
            f"Profile '{profile}' is not allowed.",
            detail=f"Allowed profiles: {', '.join(allowlist.allowed_profiles)}",
        )

    return profile
