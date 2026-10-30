"""
Asset repository for AEGIS-Recon.

Provides CRUD operations against the assets SQLite table.
Uses the existing get_db() context manager pattern.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.assets.models import Asset, AssetCriticality, AssetEnvironment
from app.core.logging import get_logger
from app.db.database import get_db

logger = get_logger(__name__)


def create_asset(asset: Asset) -> Asset:
    """
    Insert a new asset into the database.

    Args:
        asset: Asset to create. asset_id will be generated if empty.

    Returns:
        The created asset with asset_id and timestamps set.
    """
    if not asset.asset_id:
        asset.asset_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    asset.created_at = now
    asset.updated_at = now

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO assets (
                asset_id, hostname, ip, environment, criticality,
                owner, business_service, internet_exposed, notes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset.asset_id,
                asset.hostname,
                asset.ip,
                str(asset.environment),
                str(asset.criticality),
                asset.owner,
                asset.business_service,
                1 if asset.internet_exposed else 0,
                asset.notes,
                asset.created_at,
                asset.updated_at,
            ),
        )

    logger.info("asset_created", asset_id=asset.asset_id, ip=asset.ip)
    return asset


def get_asset(asset_id: str) -> Asset | None:
    """Retrieve an asset by ID. Returns None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()

    return _row_to_asset(row) if row else None


def get_asset_by_ip(ip: str) -> Asset | None:
    """Retrieve an asset by IP address. Returns the first match."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM assets WHERE ip = ? LIMIT 1",
            (ip,),
        ).fetchone()

    return _row_to_asset(row) if row else None


def list_assets() -> list[Asset]:
    """Return all assets ordered by criticality (highest first), then by IP."""
    # Use a static CASE expression — no user input, no injection risk
    order_sql = (
        "SELECT * FROM assets ORDER BY "
        "CASE criticality WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, "
        "ip"
    )
    with get_db() as conn:
        rows = conn.execute(order_sql).fetchall()  # nosec B608

    return [_row_to_asset(r) for r in rows]


def update_asset(asset_id: str, updates: dict) -> Asset | None:
    """
    Update an existing asset. Only provided fields are changed.

    Uses explicit per-column UPDATE statements to avoid dynamic SQL
    and satisfy security linting (no f-string SQL injection risk).

    Args:
        asset_id: Asset to update.
        updates: Dict of field name → new value (only non-None values).

    Returns:
        Updated Asset or None if not found.
    """
    existing = get_asset(asset_id)
    if existing is None:
        return None

    # Map allowed field names to their SQL column update statements (no user input in SQL)
    now = datetime.now(UTC).isoformat()

    allowed_columns = {
        "hostname",
        "ip",
        "environment",
        "criticality",
        "owner",
        "business_service",
        "internet_exposed",
        "notes",
    }

    # Build (column, value) pairs for allowed updates only
    col_values: list[tuple[str, object]] = [("updated_at", now)]
    for col, value in updates.items():
        if col not in allowed_columns or value is None:
            continue
        if col == "internet_exposed":
            col_values.append((col, 1 if value else 0))
        else:
            col_values.append((col, str(value) if hasattr(value, "value") else value))

    # Build a safe SQL using only pre-validated column names from the allowlist
    # (no user-supplied strings reach the SQL template)
    set_parts = ", ".join(f"{col} = ?" for col, _ in col_values)
    param_values = [v for _, v in col_values]
    param_values.append(asset_id)

    sql = f"UPDATE assets SET {set_parts} WHERE asset_id = ?"  # nosec B608  # noqa: S608
    with get_db() as conn:
        conn.execute(sql, param_values)

    logger.info("asset_updated", asset_id=asset_id)
    return get_asset(asset_id)


def delete_asset(asset_id: str) -> bool:
    """Delete an asset. Returns True if deleted, False if not found."""
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM assets WHERE asset_id = ?",
            (asset_id,),
        )
    return cursor.rowcount > 0


def _row_to_asset(row: object) -> Asset:
    """Convert a sqlite3.Row to an Asset dataclass."""
    return Asset(
        asset_id=row["asset_id"],  # type: ignore[index]
        hostname=row["hostname"] or "",  # type: ignore[index]
        ip=row["ip"] or "",  # type: ignore[index]
        environment=AssetEnvironment(row["environment"]),  # type: ignore[index]
        criticality=AssetCriticality(row["criticality"]),  # type: ignore[index]
        owner=row["owner"] or "",  # type: ignore[index]
        business_service=row["business_service"] or "",  # type: ignore[index]
        internet_exposed=bool(row["internet_exposed"]),  # type: ignore[index]
        notes=row["notes"] or "",  # type: ignore[index]
        created_at=row["created_at"] or "",  # type: ignore[index]
        updated_at=row["updated_at"] or "",  # type: ignore[index]
    )
