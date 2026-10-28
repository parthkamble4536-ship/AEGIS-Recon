"""
Unit tests for the Nmap scanner runner.

Tests use mocks — no actual Nmap execution needed.
Covers: successful scan, timeout, nmap missing, non-zero exit, version check.
"""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.core.errors import NmapNotFoundError, ScannerError
from app.scanner.runner import ScanResult, check_nmap, run_scan


class TestCheckNmap:
    """Test Nmap binary detection."""

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_nmap_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Nmap version 7.94 ( https://nmap.org )\n"
        )
        version = check_nmap("nmap")
        assert "7.94" in version

    @patch("app.scanner.runner.shutil.which", return_value=None)
    def test_nmap_not_found(self, mock_which: MagicMock) -> None:
        with pytest.raises(NmapNotFoundError, match="not found"):
            check_nmap("nmap")

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch(
        "app.scanner.runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=10),
    )
    def test_nmap_version_timeout(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with pytest.raises(NmapNotFoundError, match="timed out"):
            check_nmap("nmap")

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run", side_effect=OSError("Permission denied"))
    def test_nmap_not_executable(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with pytest.raises(NmapNotFoundError, match="Cannot execute"):
            check_nmap("nmap")


class TestRunScan:
    """Test scan execution with mocked subprocess."""

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_successful_scan(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any
    ) -> None:
        # Write a fake XML file that the runner will "find"
        xml_content = '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>'

        def side_effect(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess:
            # Simulate nmap writing an XML file
            # Find the -oX argument to get the output path
            for i, arg in enumerate(cmd):
                if arg == "-oX" and i + 1 < len(cmd):
                    from pathlib import Path

                    Path(cmd[i + 1]).write_text(xml_content)
                    break
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        result = run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            output_dir=tmp_path,
        )

        assert isinstance(result, ScanResult)
        assert result.status == "completed"
        assert result.target == "192.168.56.101"
        assert result.profile == "quick"
        assert result.xml_output is not None
        assert result.exit_code == 0

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_scan_timeout(self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=60)

        result = run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            output_dir=tmp_path,
        )

        assert result.status == "timeout"
        assert result.error_message is not None
        assert "timed out" in result.error_message

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_scan_non_zero_exit(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Host seems down"
        )

        result = run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            output_dir=tmp_path,
        )

        assert result.status == "failed"
        assert result.exit_code == 1
        assert result.error_message is not None
        assert "Host seems down" in result.error_message

    @patch("app.scanner.runner.shutil.which", return_value=None)
    def test_scan_nmap_missing(self, mock_which: MagicMock) -> None:
        with pytest.raises(NmapNotFoundError):
            run_scan("192.168.56.101", "quick")

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run", side_effect=OSError("Cannot run"))
    def test_scan_os_error(self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any) -> None:
        with pytest.raises(ScannerError, match="Failed to execute"):
            run_scan(
                "192.168.56.101",
                "quick",
                nmap_path="nmap",
                output_dir=tmp_path,
            )

    def test_unknown_profile_rejected(self) -> None:
        with pytest.raises(ScannerError, match="Unknown scan profile"):
            # Mock shutil.which so we get past the nmap check
            with patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap"):
                run_scan("192.168.56.101", "nonexistent_profile")

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_shell_false_enforced(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any
    ) -> None:
        """Verify subprocess.run is called with shell=False."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            output_dir=tmp_path,
        )

        # Check that shell=False was passed
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("shell") is False

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_target_is_last_argument(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any
    ) -> None:
        """Target must always be the last argument to nmap."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            output_dir=tmp_path,
        )

        cmd = mock_run.call_args[0][0]
        assert cmd[-1] == "192.168.56.101"

    @patch("app.scanner.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.scanner.runner.subprocess.run")
    def test_port_override_in_command(
        self, mock_run: MagicMock, mock_which: MagicMock, tmp_path: Any
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        run_scan(
            "192.168.56.101",
            "quick",
            nmap_path="nmap",
            timeout=60,
            ports="22,80,443",
            output_dir=tmp_path,
        )

        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == "22,80,443"
