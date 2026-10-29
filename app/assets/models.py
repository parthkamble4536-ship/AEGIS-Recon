"""
Asset inventory models for AEGIS-Recon.

Assets provide context for findings — the same vulnerability can carry a
different priority depending on whether the affected asset is a production
internet-facing system or a dev lab machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AssetCriticality(StrEnum):
    """Business criticality of the asset."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetEnvironment(StrEnum):
    """Deployment environment of the asset."""

    LAB = "LAB"
    DEV = "DEV"
    TEST = "TEST"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class AssetExposure(StrEnum):
    """Network exposure classification of the asset."""

    INTERNAL = "INTERNAL"
    EXTERNALLY_EXPOSED = "EXTERNALLY_EXPOSED"
    UNKNOWN = "UNKNOWN"


@dataclass
class Asset:
    """
    An asset in the AEGIS-Recon inventory.

    Provides context for vulnerability prioritization. A critical
    production-exposed asset will elevate findings compared to the
    same vulnerability on a lab machine.
    """

    asset_id: str
    hostname: str = ""
    ip: str = ""
    environment: AssetEnvironment = AssetEnvironment.LAB
    criticality: AssetCriticality = AssetCriticality.LOW
    owner: str = ""
    business_service: str = ""
    internet_exposed: bool = False
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    @property
    def exposure(self) -> AssetExposure:
        """Derive exposure from internet_exposed flag."""
        if self.internet_exposed:
            return AssetExposure.EXTERNALLY_EXPOSED
        if self.environment == AssetEnvironment.LAB:
            return AssetExposure.INTERNAL
        return AssetExposure.UNKNOWN
