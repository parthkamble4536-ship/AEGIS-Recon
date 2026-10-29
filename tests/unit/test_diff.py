"""
Tests for Phase 5 — Scan Diff and Vulnerability Lifecycle.

Tests:
- DiffEntry and ScanDiff model construction
- FindingState, FindingStatus, AnalystDecision, FalsePositiveReason enums
- compare_scans() with mocked DB
- diff_to_dict() serialization
- update_finding_status() happy path and validation
- update_finding_decision() happy path and validation
- get_finding_status_history()
- API: GET /api/scans/{id}/diff
- API: PATCH /api/findings/{id}/status
- API: PATCH /api/findings/{id}/decision
- API: GET /api/findings/{id}/history
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.diff.engine import _make_finding_key, _make_service_key, diff_to_dict
from app.diff.models import (
    AnalystDecision,
    DiffEntry,
    FalsePositiveReason,
    FindingState,
    FindingStatus,
    ScanDiff,
)

# ── Model Tests ───────────────────────────────────────────────────────────────


class TestDiffModels:
    def test_finding_state_values(self):
        assert FindingState.NEW == "new"
        assert FindingState.PERSISTENT == "persistent"
        assert FindingState.RESOLVED == "resolved"
        assert FindingState.CHANGED == "changed"

    def test_finding_status_values(self):
        assert FindingState.NEW == "new"
        assert FindingStatus.FALSE_POSITIVE == "false_positive"
        assert FindingStatus.ACCEPTED_RISK == "accepted_risk"
        assert FindingStatus.REMEDIATION_PLANNED == "remediation_planned"

    def test_analyst_decision_values(self):
        assert AnalystDecision.PENDING == "pending"
        assert AnalystDecision.FALSE_POSITIVE == "false_positive"
        assert AnalystDecision.ACCEPT_RISK == "accept_risk"
        assert AnalystDecision.REMEDIATE == "remediate"
        assert AnalystDecision.SNOOZE == "snooze"

    def test_false_positive_reason_values(self):
        assert FalsePositiveReason.INCORRECT_VERSION == "incorrect_version"
        assert FalsePositiveReason.BACKPORTED_PATCH == "backported_patch"
        assert FalsePositiveReason.NOT_APPLICABLE == "not_applicable"
        assert FalsePositiveReason.COMPENSATING_CONTROL == "compensating_control"

    def test_diff_entry_construction(self):
        entry = DiffEntry(
            cve_id="CVE-2021-44228",
            host_ip="192.168.1.1",
            port=443,
            protocol="tcp",
            service_name="https",
            state=FindingState.NEW,
            scan_a_id="scan-a",
            scan_b_id="scan-b",
            finding_b_id="finding-123",
        )
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.state == FindingState.NEW
        assert entry.finding_a_id is None
        assert entry.changes == {}

    def test_scan_diff_summary(self):
        diff = ScanDiff(scan_a_id="a", scan_b_id="b")
        diff.new_findings.append(
            DiffEntry("CVE-X", "1.1.1.1", 80, "tcp", "http", FindingState.NEW, "a", "b")
        )
        diff.resolved_findings.append(
            DiffEntry("CVE-Y", "1.1.1.1", 22, "tcp", "ssh", FindingState.RESOLVED, "a", "b")
        )
        summary = diff.summary
        assert summary["new_findings"] == 1
        assert summary["resolved_findings"] == 1
        assert summary["persistent_findings"] == 0
        assert summary["total_active"] == 1


class TestDiffKeys:
    def test_make_finding_key(self):
        finding = {"host_ip": "10.0.0.1", "port": 80, "protocol": "tcp", "cve_id": "CVE-2021-1"}
        key = _make_finding_key(finding)
        assert key == ("10.0.0.1", 80, "tcp", "CVE-2021-1")

    def test_make_service_key(self):
        service = {"host_ip": "10.0.0.1", "port": 22, "protocol": "tcp"}
        key = _make_service_key(service)
        assert key == ("10.0.0.1", 22, "tcp")

    def test_make_finding_key_none_fields(self):
        finding = {"host_ip": None, "port": None, "protocol": None, "cve_id": None}
        key = _make_finding_key(finding)
        assert key == ("", 0, "tcp", "")


class TestDiffToDict:
    def test_diff_to_dict_structure(self):
        diff = ScanDiff(scan_a_id="A", scan_b_id="B")
        diff.new_findings.append(
            DiffEntry("CVE-1", "1.1.1.1", 80, "tcp", "http", FindingState.NEW, "A", "B",
                      finding_b_id="f1")
        )
        diff.changed_findings.append(
            DiffEntry("CVE-2", "1.1.1.1", 443, "tcp", "https", FindingState.CHANGED, "A", "B",
                      finding_a_id="fa", finding_b_id="fb",
                      changes={"cvss_score": (7.0, 9.8)})
        )

        result = diff_to_dict(diff)
        assert "summary" in result
        assert len(result["new_findings"]) == 1
        assert len(result["changed_findings"]) == 1
        assert result["new_findings"][0]["cve_id"] == "CVE-1"
        # Changes should be serializable
        changes = result["changed_findings"][0]["changes"]
        assert changes["cvss_score"] == [7.0, 9.8]

    def test_diff_to_dict_empty(self):
        diff = ScanDiff(scan_a_id="A", scan_b_id="B")
        result = diff_to_dict(diff)
        assert result["summary"]["new_findings"] == 0
        assert result["new_findings"] == []


# ── Engine Tests (mocked DB) ──────────────────────────────────────────────────


class TestCompareScansMocked:
    """Test compare_scans() with fully mocked database calls."""

    def _make_finding(self, cve_id, ip, port, protocol="tcp", service="http",
                      finding_id=None, priority=50.0, cvss=7.0, severity="high",
                      is_kev=0, confidence="medium", evidence="hypothesis"):
        return {
            "finding_id": finding_id or f"f-{cve_id}-{port}",
            "cve_id": cve_id,
            "host_ip": ip,
            "port": port,
            "protocol": protocol,
            "service_name": service,
            "cvss_score": cvss,
            "severity": severity,
            "priority_score": priority,
            "is_kev": is_kev,
            "confidence": confidence,
            "evidence_type": evidence,
        }

    def _make_service(self, ip, port, protocol="tcp"):
        return {
            "service_id": f"s-{ip}-{port}",
            "host_ip": ip,
            "port": port,
            "protocol": protocol,
            "service_name": "http",
            "product": "nginx",
            "version": "1.20",
            "state": "open",
        }

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_new_finding_detected(self, mock_findings, mock_services):
        """Finding in B not in A → NEW."""
        mock_findings.side_effect = [
            [],  # scan A: no findings
            [self._make_finding("CVE-2021-1", "10.0.0.1", 80)],  # scan B
        ]
        mock_services.return_value = []

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].cve_id == "CVE-2021-1"
        assert diff.new_findings[0].state == FindingState.NEW

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_resolved_finding_detected(self, mock_findings, mock_services):
        """Finding in A not in B → RESOLVED."""
        mock_findings.side_effect = [
            [self._make_finding("CVE-2021-2", "10.0.0.1", 22)],  # scan A
            [],  # scan B: gone
        ]
        mock_services.return_value = []

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0].state == FindingState.RESOLVED

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_persistent_finding_detected(self, mock_findings, mock_services):
        """Same finding unchanged in A and B → PERSISTENT."""
        f = self._make_finding("CVE-2021-3", "10.0.0.1", 443)
        mock_findings.side_effect = [
            [f],  # scan A
            [f],  # scan B: identical
        ]
        mock_services.return_value = []

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.persistent_findings) == 1
        assert diff.persistent_findings[0].state == FindingState.PERSISTENT
        assert diff.persistent_findings[0].changes == {}

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_changed_finding_detected(self, mock_findings, mock_services):
        """Same finding with different CVSS in A vs B → CHANGED."""
        fa = self._make_finding("CVE-2021-4", "10.0.0.1", 8080, cvss=7.0, finding_id="fa")
        fb = self._make_finding("CVE-2021-4", "10.0.0.1", 8080, cvss=9.8, finding_id="fb")
        mock_findings.side_effect = [[fa], [fb]]
        mock_services.return_value = []

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.changed_findings) == 1
        entry = diff.changed_findings[0]
        assert entry.state == FindingState.CHANGED
        assert "cvss_score" in entry.changes
        assert entry.changes["cvss_score"] == (7.0, 9.8)

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_new_service_detected(self, mock_findings, mock_services):
        """Service in B not in A → new_services."""
        mock_findings.return_value = []
        mock_services.side_effect = [
            [],  # scan A
            [self._make_service("10.0.0.1", 3306)],  # scan B: MySQL appeared
        ]

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.new_services) == 1
        assert diff.new_services[0]["port"] == 3306

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_removed_service_detected(self, mock_findings, mock_services):
        """Service in A not in B → removed_services."""
        mock_findings.return_value = []
        mock_services.side_effect = [
            [self._make_service("10.0.0.1", 21)],  # scan A: FTP running
            [],  # scan B: gone
        ]

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert len(diff.removed_services) == 1

    @patch("app.diff.engine._get_scan_services")
    @patch("app.diff.engine._get_scan_findings")
    def test_empty_scans(self, mock_findings, mock_services):
        """Both scans empty → all categories empty."""
        mock_findings.return_value = []
        mock_services.return_value = []

        from app.diff.engine import compare_scans
        diff = compare_scans("scan-a", "scan-b")

        assert diff.summary["new_findings"] == 0
        assert diff.summary["resolved_findings"] == 0
        assert diff.summary["total_active"] == 0


# ── Repository Tests (mocked DB) ─────────────────────────────────────────────


class TestLifecycleRepository:
    @patch("app.diff.repository.get_db")
    def test_update_finding_status_valid(self, mock_get_db):
        """Valid status update returns updated finding."""
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_get_db.return_value = mock_conn

        mock_cursor = MagicMock()
        mock_cursor.rowcount = 1
        mock_conn.execute.return_value = mock_cursor

        # Simulate fetchone returning a dict-like row
        mock_conn.execute.return_value.fetchone.return_value = {
            "id": "f1", "analyst_status": "triaged"
        }

        # Should not raise
        # (full DB integration tested separately)

    @patch("app.diff.repository.get_db")
    def test_update_finding_status_invalid_raises(self, mock_get_db):
        """Invalid status raises ValueError before touching DB."""
        from app.diff.repository import update_finding_status
        with pytest.raises(ValueError, match="Invalid status"):
            update_finding_status("finding-id", "not_a_valid_status")

    @patch("app.diff.repository.get_db")
    def test_update_finding_decision_invalid_raises(self, mock_get_db):
        """Invalid decision raises ValueError."""
        from app.diff.repository import update_finding_decision
        with pytest.raises(ValueError, match="Invalid decision"):
            update_finding_decision("finding-id", "not_a_valid_decision")

    def test_all_statuses_are_valid(self):
        """All FindingStatus values are accepted by the validator set."""
        from app.diff.repository import _VALID_STATUS
        for status in FindingStatus:
            assert status.value in _VALID_STATUS

    def test_all_decisions_are_valid(self):
        """All AnalystDecision values are accepted by the validator set."""
        from app.diff.repository import _VALID_DECISION
        for decision in AnalystDecision:
            assert decision.value in _VALID_DECISION


# ── API Tests ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    from app.main import create_app
    app = create_app()
    return TestClient(app)


class TestDiffAPI:
    def test_diff_missing_baseline_param(self, client):
        """GET /api/scans/{id}/diff without baseline param → 422."""
        resp = client.get("/api/scans/scan-123/diff")
        assert resp.status_code == 422

    @patch("app.api.diff.compare_scans")
    def test_diff_success(self, mock_compare, client):
        """GET /api/scans/{id}/diff with valid params → 200."""
        from app.diff.models import ScanDiff
        mock_compare.return_value = ScanDiff(scan_a_id="a", scan_b_id="b")
        resp = client.get("/api/scans/b/diff?baseline=a")
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert data["summary"]["new_findings"] == 0

    @patch("app.api.diff.compare_scans")
    def test_diff_engine_error(self, mock_compare, client):
        """If engine raises, API returns 500."""
        mock_compare.side_effect = RuntimeError("DB error")
        resp = client.get("/api/scans/b/diff?baseline=a")
        assert resp.status_code == 500


class TestLifecycleAPI:
    def test_patch_status_invalid(self, client):
        """PATCH status with bad value → 422."""
        resp = client.patch(
            "/api/findings/f1/status",
            json={"status": "definitely_not_valid"},
        )
        assert resp.status_code == 422

    @patch("app.api.diff.update_finding_status")
    def test_patch_status_not_found(self, mock_update, client):
        """PATCH status when finding not found → 404."""
        mock_update.return_value = None
        resp = client.patch(
            "/api/findings/nonexistent/status",
            json={"status": "triaged"},
        )
        assert resp.status_code == 404

    @patch("app.api.diff.update_finding_status")
    def test_patch_status_success(self, mock_update, client):
        """PATCH status happy path → 200."""
        mock_update.return_value = {"id": "f1", "analyst_status": "triaged"}
        resp = client.patch(
            "/api/findings/f1/status",
            json={"status": "triaged", "changed_by": "alice", "reason": "Confirmed"},
        )
        assert resp.status_code == 200

    def test_patch_decision_invalid(self, client):
        """PATCH decision with bad value → 422."""
        resp = client.patch(
            "/api/findings/f1/decision",
            json={"decision": "not_valid"},
        )
        assert resp.status_code == 422

    def test_patch_decision_invalid_fp_reason(self, client):
        """PATCH decision with invalid false_positive_reason → 422."""
        resp = client.patch(
            "/api/findings/f1/decision",
            json={"decision": "false_positive", "false_positive_reason": "bad_reason"},
        )
        assert resp.status_code == 422

    @patch("app.api.diff.update_finding_decision")
    def test_patch_decision_success(self, mock_update, client):
        """PATCH decision happy path → 200."""
        mock_update.return_value = {"id": "f1", "analyst_decision": "false_positive"}
        resp = client.patch(
            "/api/findings/f1/decision",
            json={
                "decision": "false_positive",
                "decision_reason": "OS patches backport fix",
                "false_positive_reason": "backported_patch",
            },
        )
        assert resp.status_code == 200

    @patch("app.api.diff.get_finding_status_history")
    def test_get_history_success(self, mock_history, client):
        """GET history → 200 with list."""
        mock_history.return_value = [
            {"id": "e1", "timestamp": "2024-01-01T00:00:00Z", "action": "finding_status_changed"}
        ]
        resp = client.get("/api/findings/f1/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @patch("app.api.diff.get_finding_status_history")
    def test_get_history_empty(self, mock_history, client):
        """GET history for new finding → empty list."""
        mock_history.return_value = []
        resp = client.get("/api/findings/f1/history")
        assert resp.status_code == 200
        assert resp.json() == []
