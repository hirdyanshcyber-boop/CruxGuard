"""AbuseIPDB threat-intelligence client — free API tier."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.config import SETTINGS

logger = logging.getLogger(__name__)

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """Query AbuseIPDB for an IP's reputation.

    Returns the `data` block on success. On failure (no key, HTTP error,
    timeout) returns a neutral record so the graph can still progress.
    """
    if not SETTINGS.abuseipdb_api_key:
        logger.info("AbuseIPDB key not set — returning neutral reputation.")
        return {"abuseConfidenceScore": 0, "totalReports": 0, "source": "offline-stub"}

    headers = {
        "Key": SETTINGS.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}

    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(_ENDPOINT, headers=headers, params=params)
            r.raise_for_status()
            return r.json().get("data", {})
    except Exception as exc:  # noqa: BLE001
        logger.warning("AbuseIPDB lookup failed: %s", exc)
        return {"abuseConfidenceScore": 0, "totalReports": 0, "source": f"error: {exc}"}
