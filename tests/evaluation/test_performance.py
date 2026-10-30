"""
Performance benchmark tests for AEGIS-Recon.

Uses time.perf_counter() to measure real elapsed time.
DO NOT fabricate results — assertions are conservative (5s for 100 findings).

Tests are marked @pytest.mark.evaluation and excluded from the standard suite.
Run with: pytest tests/evaluation/test_performance.py -v
"""

from __future__ import annotations

import time
from typing import Any

import pytest


def _make_findings(n: int) -> list[dict[str, Any]]:
    """Generate n synthetic finding dicts for benchmarking."""
    findings = []
    for i in range(n):
        findings.append(
            {
                "finding_id": f"f-{i:05d}",
                "cve_id": f"CVE-2021-{1000 + i}",
                "host_ip": f"10.0.{i // 256}.{i % 256}",
                "port": 80 + (i % 1000),
                "protocol": "tcp",
                "service_name": "http",
                "cvss_score": 5.0 + (i % 50) / 10,
                "severity": "medium",
                "priority_score": 40.0 + (i % 60),
                "is_kev": i % 20 == 0,
                "confidence": "medium",
                "evidence_type": "hypothesis",
            }
        )
    return findings


def _make_risk_input(n: int) -> list[dict[str, Any]]:
    """Generate n risk scoring inputs (kwargs matching calculate_risk_v2 signature)."""
    envs = ["LAB", "DEV", "STAGING", "PRODUCTION"]
    crits = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return [
        {
            "cvss_score": 4.0 + (i % 60) / 10,
            "is_kev": i % 15 == 0,
            "epss_probability": (i % 100) / 100 if i % 5 != 0 else None,
            "confidence": ["low", "medium", "high"][i % 3],
            "evidence_type": ["hypothesis", "external_intelligence"][i % 2],
            "has_exploit_ref": i % 7 == 0,
            "asset_criticality": crits[i % 4],
            "asset_environment": envs[i % 4],
        }
        for i in range(n)
    ]


@pytest.mark.evaluation
class TestPerformance:
    def test_diff_engine_10_findings(self):
        """Diff of 10 findings completes in under 1 second."""
        from app.diff.engine import _make_finding_key
        from app.diff.models import DiffEntry, FindingState, ScanDiff

        findings = _make_findings(10)
        start = time.perf_counter()

        index_a = {_make_finding_key(f): f for f in findings[:5]}
        index_b = {_make_finding_key(f): f for f in findings[5:]}

        diff = ScanDiff(scan_a_id="a", scan_b_id="b")
        keys_a = set(index_a)
        keys_b = set(index_b)

        for key in keys_b - keys_a:
            fb = index_b[key]
            diff.new_findings.append(
                DiffEntry(
                    fb["cve_id"],
                    fb["host_ip"],
                    fb["port"],
                    fb["protocol"],
                    fb["service_name"],
                    FindingState.NEW,
                    "a",
                    "b",
                    finding_b_id=fb["finding_id"],
                )
            )

        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"10-finding diff took {elapsed:.3f}s (expected < 1.0s)"
        assert len(diff.new_findings) <= 10

    def test_diff_engine_100_findings(self):
        """Diff of 100 findings completes in under 2 seconds."""
        from app.diff.engine import _make_finding_key
        from app.diff.models import DiffEntry, FindingState, ScanDiff

        findings_a = _make_findings(100)
        # B has 80 from A (persistent) + 20 new
        findings_b = findings_a[:80] + _make_findings(20)
        # Adjust IDs to avoid collision
        for i, f in enumerate(findings_b[80:]):
            f["cve_id"] = f"CVE-9999-{i:04d}"
            f["finding_id"] = f"fn-new-{i}"

        start = time.perf_counter()

        index_a = {_make_finding_key(f): f for f in findings_a}
        index_b = {_make_finding_key(f): f for f in findings_b}
        keys_a = set(index_a)
        keys_b = set(index_b)

        diff = ScanDiff(scan_a_id="a", scan_b_id="b")
        for key in keys_b - keys_a:
            fb = index_b[key]
            diff.new_findings.append(
                DiffEntry(
                    fb["cve_id"],
                    fb["host_ip"],
                    fb["port"],
                    fb["protocol"],
                    fb["service_name"],
                    FindingState.NEW,
                    "a",
                    "b",
                    finding_b_id=fb["finding_id"],
                )
            )
        for key in keys_a - keys_b:
            fa = index_a[key]
            diff.resolved_findings.append(
                DiffEntry(
                    fa["cve_id"],
                    fa["host_ip"],
                    fa["port"],
                    fa["protocol"],
                    fa["service_name"],
                    FindingState.RESOLVED,
                    "a",
                    "b",
                    finding_a_id=fa["finding_id"],
                )
            )

        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"100-finding diff took {elapsed:.3f}s (expected < 2.0s)"

    def test_risk_scoring_50_findings(self):
        """Risk scoring 50 findings completes in under 2 seconds."""
        from app.risk.engine import calculate_risk_v2
        from app.risk.models import RiskPolicyWeights

        inputs = _make_risk_input(50)
        policy = RiskPolicyWeights()

        start = time.perf_counter()
        results = [calculate_risk_v2(**inp, policy=policy) for inp in inputs]
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"50-finding risk scoring took {elapsed:.3f}s (expected < 2.0s)"
        assert len(results) == 50
        # All scores must be in valid range
        for r in results:
            assert 0 <= r.priority_score <= 100, f"Score out of range: {r.priority_score}"

    def test_risk_scoring_100_findings(self):
        """Risk scoring 100 findings completes in under 5 seconds."""
        from app.risk.engine import calculate_risk_v2
        from app.risk.models import RiskPolicyWeights

        inputs = _make_risk_input(100)
        policy = RiskPolicyWeights()

        start = time.perf_counter()
        results = [calculate_risk_v2(**inp, policy=policy) for inp in inputs]
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"100-finding risk scoring took {elapsed:.3f}s (expected < 5.0s)"
        assert len(results) == 100

    def test_evidence_chain_construction_performance(self):
        """Building 20 evidence chains completes quickly."""
        from app.evidence.models import Evidence, EvidenceChain, EvidenceSource, EvidenceType

        start = time.perf_counter()

        chains = []
        for i in range(20):
            items = [
                Evidence(
                    f"e{i}-{j}",
                    f"f{i}",
                    EvidenceType.HYPOTHESIS,
                    EvidenceSource.AEGIS_RULE,
                    "rule:match",
                    "2024-01-01T00:00:00Z",
                    f"hash{i}{j}",
                    f"Description {j}",
                )
                for j in range(5)
            ]
            chain = EvidenceChain(finding_id=f"f{i}", items=items)
            chains.append(chain.summary())

        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"20 evidence chains took {elapsed:.3f}s (expected < 1.0s)"
        assert len(chains) == 20
