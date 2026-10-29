"""
Tests for Asset Inventory (Phase 3).

Uses an in-memory SQLite database — no real DB file created.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.assets.models import Asset, AssetCriticality, AssetEnvironment, AssetExposure
from app.assets.service import explain_asset_priority_difference, get_asset_context_for_ip
from app.db.database import init_db, reset_db

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def test_db(tmp_path: Path):
    """Provide a temporary database for each test."""
    db_file = str(tmp_path / "test_assets.db")
    init_db(db_file)
    yield db_file
    reset_db()


# ─────────────────────────────────────────────────────────────────────────────
# Model tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAssetModel:
    def test_asset_dataclass_fields(self) -> None:
        """Asset has all required fields from the spec."""
        asset = Asset(
            asset_id="a1b2c3",
            hostname="metasploitable2.lab",
            ip="192.168.56.101",
            environment=AssetEnvironment.LAB,
            criticality=AssetCriticality.LOW,
            owner="security-team",
            business_service="lab-testing",
            internet_exposed=False,
            notes="Metasploitable 2 training VM",
        )
        assert asset.asset_id == "a1b2c3"
        assert asset.hostname == "metasploitable2.lab"
        assert asset.ip == "192.168.56.101"
        assert asset.environment == AssetEnvironment.LAB
        assert asset.criticality == AssetCriticality.LOW
        assert not asset.internet_exposed

    def test_exposure_property_internet_exposed(self) -> None:
        """internet_exposed=True → exposure=EXTERNALLY_EXPOSED."""
        asset = Asset(
            asset_id="x",
            ip="1.2.3.4",
            internet_exposed=True,
            environment=AssetEnvironment.PRODUCTION,
            criticality=AssetCriticality.CRITICAL,
        )
        assert asset.exposure == AssetExposure.EXTERNALLY_EXPOSED

    def test_exposure_property_lab_internal(self) -> None:
        """LAB environment + not internet exposed → INTERNAL."""
        asset = Asset(
            asset_id="x",
            ip="192.168.1.1",
            internet_exposed=False,
            environment=AssetEnvironment.LAB,
            criticality=AssetCriticality.LOW,
        )
        assert asset.exposure == AssetExposure.INTERNAL

    def test_exposure_property_unknown(self) -> None:
        """Non-LAB + not internet exposed → UNKNOWN."""
        asset = Asset(
            asset_id="x",
            ip="10.0.0.1",
            internet_exposed=False,
            environment=AssetEnvironment.PRODUCTION,
            criticality=AssetCriticality.HIGH,
        )
        assert asset.exposure == AssetExposure.UNKNOWN

    def test_all_criticality_values(self) -> None:
        """All criticality enum values are accessible."""
        assert AssetCriticality.LOW == "LOW"
        assert AssetCriticality.MEDIUM == "MEDIUM"
        assert AssetCriticality.HIGH == "HIGH"
        assert AssetCriticality.CRITICAL == "CRITICAL"

    def test_all_environment_values(self) -> None:
        """All environment enum values are accessible."""
        for env in ["LAB", "DEV", "TEST", "STAGING", "PRODUCTION"]:
            assert AssetEnvironment(env) == env

    def test_all_exposure_values(self) -> None:
        """All exposure enum values are accessible."""
        for exp in ["INTERNAL", "EXTERNALLY_EXPOSED", "UNKNOWN"]:
            assert AssetExposure(exp) == exp


# ─────────────────────────────────────────────────────────────────────────────
# Repository tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAssetRepository:
    def test_create_and_get_asset(self, test_db: str) -> None:
        """Create an asset and retrieve it by ID."""
        from app.assets.repository import create_asset, get_asset

        asset = Asset(
            asset_id="test-001",
            hostname="web-prod",
            ip="10.0.0.1",
            environment=AssetEnvironment.PRODUCTION,
            criticality=AssetCriticality.CRITICAL,
            owner="ops-team",
            business_service="e-commerce",
            internet_exposed=True,
            notes="Main web server",
        )
        created = create_asset(asset)
        assert created.asset_id == "test-001"

        retrieved = get_asset("test-001")
        assert retrieved is not None
        assert retrieved.hostname == "web-prod"
        assert retrieved.ip == "10.0.0.1"
        assert retrieved.environment == AssetEnvironment.PRODUCTION
        assert retrieved.criticality == AssetCriticality.CRITICAL
        assert retrieved.internet_exposed is True

    def test_get_nonexistent_asset_returns_none(self, test_db: str) -> None:
        """get_asset with unknown ID returns None."""
        from app.assets.repository import get_asset

        result = get_asset("does-not-exist")
        assert result is None

    def test_get_asset_by_ip(self, test_db: str) -> None:
        """Look up an asset by IP address."""
        from app.assets.repository import create_asset, get_asset_by_ip

        asset = Asset(
            asset_id="ip-test-001",
            ip="192.168.56.101",
            environment=AssetEnvironment.LAB,
            criticality=AssetCriticality.LOW,
        )
        create_asset(asset)

        result = get_asset_by_ip("192.168.56.101")
        assert result is not None
        assert result.asset_id == "ip-test-001"

    def test_get_asset_by_ip_unknown_returns_none(self, test_db: str) -> None:
        """get_asset_by_ip with unknown IP returns None."""
        from app.assets.repository import get_asset_by_ip

        result = get_asset_by_ip("99.99.99.99")
        assert result is None

    def test_list_assets_ordered_by_criticality(self, test_db: str) -> None:
        """list_assets returns assets with CRITICAL first."""
        from app.assets.repository import create_asset, list_assets

        for asset_id, crit, ip in [
            ("low-1", AssetCriticality.LOW, "10.0.0.4"),
            ("crit-1", AssetCriticality.CRITICAL, "10.0.0.1"),
            ("high-1", AssetCriticality.HIGH, "10.0.0.2"),
            ("med-1", AssetCriticality.MEDIUM, "10.0.0.3"),
        ]:
            create_asset(Asset(asset_id=asset_id, criticality=crit, ip=ip, environment=AssetEnvironment.LAB))

        assets = list_assets()
        crits = [a.criticality for a in assets]
        # CRITICAL must come before HIGH, HIGH before MEDIUM, MEDIUM before LOW
        crit_idx = crits.index(AssetCriticality.CRITICAL)
        high_idx = crits.index(AssetCriticality.HIGH)
        med_idx = crits.index(AssetCriticality.MEDIUM)
        low_idx = crits.index(AssetCriticality.LOW)
        assert crit_idx < high_idx < med_idx < low_idx

    def test_update_asset(self, test_db: str) -> None:
        """Update an asset field."""
        from app.assets.repository import create_asset, update_asset

        asset = Asset(
            asset_id="upd-001",
            ip="10.0.0.5",
            environment=AssetEnvironment.DEV,
            criticality=AssetCriticality.LOW,
        )
        create_asset(asset)

        updated = update_asset("upd-001", {"criticality": "HIGH", "internet_exposed": True})
        assert updated is not None
        assert updated.criticality == AssetCriticality.HIGH
        assert updated.internet_exposed is True

    def test_update_nonexistent_asset_returns_none(self, test_db: str) -> None:
        """update_asset with unknown ID returns None."""
        from app.assets.repository import update_asset

        result = update_asset("no-such-id", {"criticality": "HIGH"})
        assert result is None

    def test_delete_asset(self, test_db: str) -> None:
        """Delete an asset."""
        from app.assets.repository import create_asset, delete_asset, get_asset

        asset = Asset(asset_id="del-001", ip="10.0.0.6", environment=AssetEnvironment.LAB, criticality=AssetCriticality.LOW)
        create_asset(asset)
        assert delete_asset("del-001") is True
        assert get_asset("del-001") is None

    def test_delete_nonexistent_returns_false(self, test_db: str) -> None:
        """delete_asset with unknown ID returns False."""
        from app.assets.repository import delete_asset

        assert delete_asset("ghost-id") is False

    def test_create_asset_auto_timestamps(self, test_db: str) -> None:
        """Created asset has non-empty timestamps."""
        from app.assets.repository import create_asset

        asset = Asset(asset_id="ts-001", ip="10.0.0.7", environment=AssetEnvironment.LAB, criticality=AssetCriticality.LOW)
        created = create_asset(asset)
        assert created.created_at != ""
        assert created.updated_at != ""


# ─────────────────────────────────────────────────────────────────────────────
# Service layer tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAssetService:
    def test_get_asset_context_found(self, test_db: str) -> None:
        """Asset found → context dict with real values."""
        from app.assets.repository import create_asset

        asset = Asset(
            asset_id="ctx-001",
            ip="10.10.10.10",
            environment=AssetEnvironment.PRODUCTION,
            criticality=AssetCriticality.CRITICAL,
            internet_exposed=True,
            owner="ops",
            business_service="payments",
        )
        create_asset(asset)

        ctx = get_asset_context_for_ip("10.10.10.10")
        assert ctx["asset_id"] == "ctx-001"
        assert ctx["criticality"] == "CRITICAL"
        assert ctx["environment"] == "PRODUCTION"
        assert ctx["internet_exposed"] is True
        assert ctx["owner"] == "ops"

    def test_get_asset_context_not_found_safe_defaults(self, test_db: str) -> None:
        """Asset not found → safe defaults (LOW criticality, LAB environment)."""
        ctx = get_asset_context_for_ip("1.2.3.4")
        assert ctx["asset_id"] is None
        assert ctx["criticality"] == "LOW"
        assert ctx["environment"] == "LAB"
        assert ctx["internet_exposed"] is False

    def test_explain_asset_priority_difference_criticality(self) -> None:
        """Explanation mentions criticality difference."""
        a = Asset(asset_id="a", ip="1.1.1.1", environment=AssetEnvironment.PRODUCTION,
                  criticality=AssetCriticality.CRITICAL, internet_exposed=True)
        b = Asset(asset_id="b", ip="2.2.2.2", environment=AssetEnvironment.LAB,
                  criticality=AssetCriticality.LOW, internet_exposed=False)
        explanation = explain_asset_priority_difference(a, b)
        assert "CRITICAL" in explanation or "criticality" in explanation.lower()

    def test_explain_identical_assets(self) -> None:
        """Identical assets → 'equivalent context' explanation."""
        a = Asset(asset_id="a", ip="1.1.1.1", environment=AssetEnvironment.LAB,
                  criticality=AssetCriticality.LOW, internet_exposed=False)
        b = Asset(asset_id="b", ip="2.2.2.2", environment=AssetEnvironment.LAB,
                  criticality=AssetCriticality.LOW, internet_exposed=False)
        explanation = explain_asset_priority_difference(a, b)
        assert "equivalent" in explanation.lower()
