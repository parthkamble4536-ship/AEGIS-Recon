"""
Pydantic schemas for the Asset API.

Used for request validation and response serialization.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.assets.models import AssetCriticality, AssetEnvironment, AssetExposure


class AssetCreate(BaseModel):
    """Schema for creating a new asset."""

    hostname: str = ""
    ip: str = ""
    environment: AssetEnvironment = AssetEnvironment.LAB
    criticality: AssetCriticality = AssetCriticality.LOW
    owner: str = ""
    business_service: str = ""
    internet_exposed: bool = False
    notes: str = ""


class AssetUpdate(BaseModel):
    """Schema for updating an existing asset (all fields optional)."""

    hostname: str | None = None
    ip: str | None = None
    environment: AssetEnvironment | None = None
    criticality: AssetCriticality | None = None
    owner: str | None = None
    business_service: str | None = None
    internet_exposed: bool | None = None
    notes: str | None = None


class AssetResponse(BaseModel):
    """Schema for an asset in API responses."""

    asset_id: str
    hostname: str
    ip: str
    environment: AssetEnvironment
    criticality: AssetCriticality
    exposure: AssetExposure
    owner: str
    business_service: str
    internet_exposed: bool
    notes: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}
