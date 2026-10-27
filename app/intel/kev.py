"""
CISA Known Exploited Vulnerabilities (KEV) client for AEGIS-Recon.

Downloads and caches the KEV catalog to flag CVEs that are
actively exploited in the wild. This is a critical enrichment
signal — KEV entries always increase priority.

Design:
- Single JSON download (no pagination needed).
- Cached in DB with TTL.
- Each KEV entry has a due date for remediation (federal agencies).
- Retrieval timestamp stored for reproducibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.errors import IntelParseError, IntelUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
)


@dataclass
class KEVEntry:
    """A single entry from the CISA KEV catalog."""

    cve_id: str
    vendor: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    due_date: str = ""  # Federal remediation deadline
    short_description: str = ""
    required_action: str = ""
    known_ransomware_use: str = "Unknown"


@dataclass
class KEVCatalog:
    """The complete KEV catalog with retrieval metadata."""

    title: str = ""
    catalog_version: str = ""
    date_released: str = ""
    count: int = 0
    entries: dict[str, KEVEntry] = field(default_factory=dict)  # Keyed by CVE ID
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def fetch_kev_catalog(
    *,
    kev_url: str = DEFAULT_KEV_URL,
    timeout: int = 30,
) -> KEVCatalog:
    """
    Download the CISA KEV catalog.

    Args:
        kev_url: URL to the KEV JSON feed.
        timeout: HTTP request timeout in seconds.

    Returns:
        KEVCatalog with all entries indexed by CVE ID.

    Raises:
        IntelUnavailableError: If the download fails.
    """
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(kev_url)

        if response.status_code != 200:
            raise IntelUnavailableError(
                f"KEV catalog download failed: HTTP {response.status_code}",
            )

        data = response.json()
        return _parse_kev_catalog(data)

    except httpx.TimeoutException:
        raise IntelUnavailableError("KEV catalog download timed out.")
    except httpx.HTTPError as e:
        raise IntelUnavailableError(f"KEV catalog download error: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        raise IntelParseError(f"KEV catalog parse error: {e}")


def parse_kev_from_cache(cached_json: str) -> KEVCatalog:
    """
    Parse a cached KEV catalog JSON string.

    Args:
        cached_json: JSON string of the KEV catalog.

    Returns:
        KEVCatalog instance.
    """
    try:
        data = json.loads(cached_json)
        return _parse_kev_catalog(data)
    except (json.JSONDecodeError, KeyError) as e:
        raise IntelParseError(f"Cached KEV parse error: {e}")


def _parse_kev_catalog(data: dict[str, Any]) -> KEVCatalog:
    """Parse raw KEV JSON into a KEVCatalog."""
    entries: dict[str, KEVEntry] = {}

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        entries[cve_id] = KEVEntry(
            cve_id=cve_id,
            vendor=vuln.get("vendorProject", "")[:200],
            product=vuln.get("product", "")[:200],
            vulnerability_name=vuln.get("vulnerabilityName", "")[:500],
            date_added=vuln.get("dateAdded", ""),
            due_date=vuln.get("dueDate", ""),
            short_description=vuln.get("shortDescription", "")[:1000],
            required_action=vuln.get("requiredAction", "")[:500],
            known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown"),
        )

    catalog = KEVCatalog(
        title=data.get("title", ""),
        catalog_version=data.get("catalogVersion", ""),
        date_released=data.get("dateReleased", ""),
        count=data.get("count", len(entries)),
        entries=entries,
        retrieved_at=datetime.now(UTC),
    )

    logger.info(
        "kev_catalog_parsed",
        total_entries=len(entries),
        catalog_version=catalog.catalog_version,
    )

    return catalog


def is_in_kev(cve_id: str, catalog: KEVCatalog) -> KEVEntry | None:
    """
    Check if a CVE is in the KEV catalog.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228").
        catalog: Loaded KEV catalog.

    Returns:
        KEVEntry if found, None otherwise.
    """
    return catalog.entries.get(cve_id)
