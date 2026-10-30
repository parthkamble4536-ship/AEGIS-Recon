"""
Asset service layer for AEGIS-Recon.

Business logic for asset lookups and context enrichment.
"""

from __future__ import annotations

from app.assets.models import Asset, AssetCriticality, AssetEnvironment, AssetExposure
from app.assets.repository import get_asset_by_ip
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_asset_context_for_ip(ip: str) -> dict:
    """
    Return asset context dict for a given IP address.

    Used to enrich findings with asset context at priority scoring time.
    Returns safe defaults when no asset record exists.

    Returns:
        Dict with: asset_id, criticality, environment, exposure, owner,
                   business_service, internet_exposed.
    """
    asset = get_asset_by_ip(ip)

    if asset is None:
        logger.debug("asset_context_not_found", ip=ip)
        return {
            "asset_id": None,
            "criticality": str(AssetCriticality.LOW),
            "environment": str(AssetEnvironment.LAB),
            "exposure": str(AssetExposure.UNKNOWN),
            "owner": "",
            "business_service": "",
            "internet_exposed": False,
        }

    return {
        "asset_id": asset.asset_id,
        "criticality": str(asset.criticality),
        "environment": str(asset.environment),
        "exposure": str(asset.exposure),
        "owner": asset.owner,
        "business_service": asset.business_service,
        "internet_exposed": asset.internet_exposed,
    }


def explain_asset_priority_difference(asset_a: Asset, asset_b: Asset) -> str:
    """
    Generate a human-readable explanation of why a finding may have
    a different priority on Asset A vs Asset B.

    Used in analyst workflow to explain context-driven priority differences.
    """
    reasons = []

    if asset_a.criticality != asset_b.criticality:
        reasons.append(
            f"Asset A has {asset_a.criticality} criticality vs {asset_b.criticality} on Asset B."
        )

    if asset_a.environment != asset_b.environment:
        reasons.append(
            f"Asset A is in {asset_a.environment} environment vs {asset_b.environment} on Asset B."
        )

    if asset_a.internet_exposed != asset_b.internet_exposed:
        a_exp = "externally exposed" if asset_a.internet_exposed else "internal"
        b_exp = "externally exposed" if asset_b.internet_exposed else "internal"
        reasons.append(f"Asset A is {a_exp} vs {b_exp} on Asset B.")

    if not reasons:
        return "Assets have equivalent context — priority difference driven by other factors."

    return "This finding has a higher priority on Asset A than Asset B because: " + " ".join(
        reasons
    )
