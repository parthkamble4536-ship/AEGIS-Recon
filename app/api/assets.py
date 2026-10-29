"""
Asset inventory API endpoints for AEGIS-Recon.

Provides CRUD operations for the asset registry, which gives context
to vulnerability findings (criticality, environment, exposure, owner).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.assets.models import Asset
from app.assets.repository import (
    create_asset,
    delete_asset,
    get_asset,
    list_assets,
    update_asset,
)
from app.assets.schemas import AssetCreate, AssetResponse, AssetUpdate

router = APIRouter()


def _asset_to_response(asset: Asset) -> AssetResponse:
    """Convert Asset dataclass to API response schema."""
    return AssetResponse(
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        ip=asset.ip,
        environment=asset.environment,
        criticality=asset.criticality,
        exposure=asset.exposure,
        owner=asset.owner,
        business_service=asset.business_service,
        internet_exposed=asset.internet_exposed,
        notes=asset.notes,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.get("/assets", response_model=list[AssetResponse])
def list_all_assets() -> list[AssetResponse]:
    """
    List all assets in the inventory.

    Returns assets ordered by criticality (CRITICAL first) then by IP.
    """
    assets = list_assets()
    return [_asset_to_response(a) for a in assets]


@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_new_asset(body: AssetCreate) -> AssetResponse:
    """
    Register a new asset in the inventory.

    Asset context (criticality, environment, exposure) will be used
    to adjust vulnerability priority scores for this host.
    """
    asset = Asset(
        asset_id=str(uuid.uuid4()),
        hostname=body.hostname,
        ip=body.ip,
        environment=body.environment,
        criticality=body.criticality,
        owner=body.owner,
        business_service=body.business_service,
        internet_exposed=body.internet_exposed,
        notes=body.notes,
    )
    created = create_asset(asset)
    return _asset_to_response(created)


@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_single_asset(asset_id: str) -> AssetResponse:
    """Retrieve a single asset by ID."""
    asset = get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return _asset_to_response(asset)


@router.put("/assets/{asset_id}", response_model=AssetResponse)
def update_existing_asset(asset_id: str, body: AssetUpdate) -> AssetResponse:
    """
    Update an existing asset's fields.

    Only provided (non-null) fields are updated.
    """
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = update_asset(asset_id, updates)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return _asset_to_response(updated)


@router.delete("/assets/{asset_id}", status_code=204)
def remove_asset(asset_id: str) -> None:
    """Remove an asset from the inventory."""
    removed = delete_asset(asset_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

