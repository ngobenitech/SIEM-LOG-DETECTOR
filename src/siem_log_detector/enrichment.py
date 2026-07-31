"""Threat intelligence enrichment for external IP addresses."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from siem_log_detector.models import Alert

_CACHE_PATH = Path(".siem_detector_enrichment_cache.json")
_CACHE_TTL_SECONDS = 3600


def _load_cache() -> dict[str, dict[str, Any]]:
    if not _CACHE_PATH.exists():
        return {}
    try:
        with _CACHE_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict[str, dict[str, Any]]) -> None:
    try:
        with _CACHE_PATH.open("w", encoding="utf-8") as handle:
            json.dump(cache, handle, indent=2, sort_keys=False)
            handle.write("\n")
    except OSError:
        pass


def _query_abuseipdb(ip_address: str, api_key: str) -> dict[str, Any] | None:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    request = Request(url, headers={"Key": api_key, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("data", {})
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


def enrich_alerts(
    alerts: tuple[Alert, ...],
    api_key: str,
) -> tuple[Alert, ...]:
    """Enrich alerts with AbuseIPDB threat intelligence.

    Queries the AbuseIPDB API for each unique external source IP and adds
    ``abuse_score``, ``country``, and ``usage_type`` to the alert metadata.

    Results are cached for one hour to respect rate limits.

    Args:
        alerts: Tuple of Alert objects to enrich.
        api_key: AbuseIPDB API key.

    Returns:
        Tuple of enriched Alert objects with additional fields in the
        ``to_dict()`` representation.
    """
    if not api_key:
        return alerts

    cache = _load_cache()
    now = time.time()
    unique_ips = sorted({alert.source_ip for alert in alerts if alert.source_ip})
    ip_data: dict[str, dict[str, Any]] = {}

    for ip_address in unique_ips:
        cached = cache.get(ip_address)
        if cached and (now - cached.get("timestamp", 0)) < _CACHE_TTL_SECONDS:
            ip_data[ip_address] = cached.get("data", {})
            continue

        data = _query_abuseipdb(ip_address, api_key)
        if data is None:
            ip_data[ip_address] = {}
        else:
            ip_data[ip_address] = {
                "abuse_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
            }

        cache[ip_address] = {"timestamp": now, "data": ip_data[ip_address]}

    _save_cache(cache)

    enriched: list[Alert] = []
    for alert in alerts:
        enrichment = ip_data.get(alert.source_ip, {})
        if enrichment:
            new_alert = _AlertWithEnrichment(
                original=alert,
                enrichment=enrichment,
            )
            enriched.append(new_alert)
        else:
            enriched.append(alert)

    return tuple(enriched)


class _AlertWithEnrichment:
    """Wrapper that adds enrichment metadata to an Alert without mutation."""

    __slots__ = ("original", "enrichment")

    def __init__(self, original: Alert, enrichment: dict[str, Any]) -> None:
        self.original = original
        self.enrichment = enrichment

    def __getattr__(self, item: str) -> Any:
        return getattr(self.original, item)

    def to_dict(self) -> dict[str, object]:
        data = self.original.to_dict()
        data.update(self.enrichment)
        return data
