"""
Nmap subprocess runner for AEGIS-Recon.

Security design:
- NEVER uses shell=True.
- Arguments come ONLY from validated profiles (frozen tuples).
- Target comes ONLY from the validator (allowlist-checked).
- Timeout enforced via subprocess timeout AND Nmap's --host-timeout.
- XML output written to a temp file, not piped (avoids buffer issues).
- All errors produce typed exceptions, never raw tracebacks.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.core.errors import (
    NmapNotFoundError,
    ScanExecutionError,
    ScannerError,
    ScanTimeoutError,
)
from app.core.logging import get_logger
from app.scanner.profiles import ScanProfile, get_profile

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of an Nmap scan execution."""

    scan_id: str
    target: str
    profile: str
    status: str  # "completed", "failed", "timeout"
    xml_output: str | None = None  # Raw XML content (on success)
    error_message: str | None = None  # Error description (on failure)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    nmap_version: str | None = None
    command_args: list[str] = field(default_factory=list)  # For reproducibility (no secrets)
    exit_code: int | None = None


def check_nmap(nmap_path: str = "nmap") -> str:
    """
    Verify that Nmap is installed and return its version.

    Args:
        nmap_path: Path to the nmap binary.

    Returns:
        Nmap version string.

    Raises:
        NmapNotFoundError: If Nmap is not found or not executable.
    """
    resolved = shutil.which(nmap_path)
    if resolved is None:
        raise NmapNotFoundError(
            f"Nmap not found at '{nmap_path}'.",
            detail="Install Nmap: https://nmap.org/download.html",
        )

    try:
        result = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,  # NEVER use shell=True
        )
        version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
        logger.info("nmap_found", path=resolved, version=version_line)
        return version_line
    except subprocess.TimeoutExpired:
        raise NmapNotFoundError("Nmap --version timed out.")
    except OSError as e:
        raise NmapNotFoundError(f"Cannot execute Nmap: {e}")


def run_scan(
    target: str,
    profile_name: str,
    *,
    nmap_path: str = "nmap",
    timeout: int = 300,
    ports: str | None = None,
    output_dir: Path | None = None,
) -> ScanResult:
    """
    Execute an Nmap scan against a validated target.

    IMPORTANT: This function assumes `target` and `profile_name` have already
    been validated by the validation module. Do NOT call this with raw user input.

    Args:
        target: Validated target (IP, CIDR, or hostname).
        profile_name: Name of a validated scan profile.
        nmap_path: Path to the nmap binary.
        timeout: Maximum scan duration in seconds.
        ports: Optional validated port specification (overrides profile).
        output_dir: Optional directory for XML output (uses tempdir if None).

    Returns:
        ScanResult with XML output or error information.

    Raises:
        ScannerError: If the scan cannot be started.
        NmapNotFoundError: If Nmap is not available.
    """
    scan_id = str(uuid.uuid4())
    start_time = datetime.now(timezone.utc)

    # Resolve nmap binary
    resolved_nmap = shutil.which(nmap_path)
    if resolved_nmap is None:
        raise NmapNotFoundError(f"Nmap not found at '{nmap_path}'.")

    # Get the profile
    profile = get_profile(profile_name)
    if profile is None:
        raise ScannerError(f"Unknown scan profile: {profile_name}")

    # Build the output path
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="aegis_scan_"))
    xml_path = output_dir / f"scan_{scan_id}.xml"

    # Build the argument list — ONLY from validated components
    cmd: list[str] = [resolved_nmap]
    cmd.extend(profile.arguments)

    # Add port override if specified
    if ports:
        cmd.extend(["-p", ports])

    # Add XML output
    cmd.extend(["-oX", str(xml_path)])

    # Target is ALWAYS the last argument
    cmd.append(target)

    # Log the command (safe — all args are from validated sources)
    logger.info(
        "scan_starting",
        scan_id=scan_id,
        target=target,
        profile=profile_name,
        timeout=timeout,
        command=cmd,
    )

    # Execute
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # CRITICAL: Never use shell=True
        )

        end_time = datetime.now(timezone.utc)

        # Read XML output
        xml_content: str | None = None
        if xml_path.exists():
            xml_content = xml_path.read_text(encoding="utf-8")

        # Nmap uses exit codes: 0 = success, 1 = host seems down, others = error
        if proc.returncode == 0:
            logger.info(
                "scan_completed",
                scan_id=scan_id,
                target=target,
                duration_s=(end_time - start_time).total_seconds(),
            )
            return ScanResult(
                scan_id=scan_id,
                target=target,
                profile=profile_name,
                status="completed",
                xml_output=xml_content,
                start_time=start_time,
                end_time=end_time,
                nmap_version=_extract_nmap_version(xml_content),
                command_args=cmd[1:],  # Exclude nmap path for portability
                exit_code=0,
            )
        else:
            error_msg = proc.stderr.strip() if proc.stderr else f"Nmap exited with code {proc.returncode}"
            logger.warning(
                "scan_non_zero_exit",
                scan_id=scan_id,
                exit_code=proc.returncode,
                stderr=error_msg[:500],  # Truncate to prevent log flooding
            )
            return ScanResult(
                scan_id=scan_id,
                target=target,
                profile=profile_name,
                status="completed" if xml_content else "failed",
                xml_output=xml_content,
                error_message=error_msg,
                start_time=start_time,
                end_time=end_time,
                nmap_version=_extract_nmap_version(xml_content),
                command_args=cmd[1:],
                exit_code=proc.returncode,
            )

    except subprocess.TimeoutExpired:
        end_time = datetime.now(timezone.utc)
        logger.error(
            "scan_timeout",
            scan_id=scan_id,
            target=target,
            timeout=timeout,
        )
        # Try to read partial XML if it exists
        xml_content = None
        if xml_path.exists():
            try:
                xml_content = xml_path.read_text(encoding="utf-8")
            except Exception:
                pass

        return ScanResult(
            scan_id=scan_id,
            target=target,
            profile=profile_name,
            status="timeout",
            xml_output=xml_content,
            error_message=f"Scan timed out after {timeout} seconds.",
            start_time=start_time,
            end_time=end_time,
            command_args=cmd[1:],
        )

    except OSError as e:
        raise ScannerError(
            f"Failed to execute Nmap: {e}",
            detail="Check that Nmap is installed and the path is correct.",
        ) from e

    finally:
        # Clean up temp XML file (data is already in ScanResult)
        try:
            if xml_path.exists():
                xml_path.unlink()
            if output_dir and output_dir.exists() and not any(output_dir.iterdir()):
                output_dir.rmdir()
        except OSError:
            pass  # Best-effort cleanup


def _extract_nmap_version(xml_content: str | None) -> str | None:
    """Extract Nmap version from XML output for reproducibility metadata."""
    if not xml_content:
        return None
    # Quick extraction without full XML parsing
    import re
    match = re.search(r'scanner="nmap"[^>]*version="([^"]+)"', xml_content)
    return match.group(1) if match else None
