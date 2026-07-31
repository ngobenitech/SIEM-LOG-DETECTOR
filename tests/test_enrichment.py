from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from siem_log_detector.detector import detect
from siem_log_detector.enrichment import enrich_alerts
from siem_log_detector.models import Alert
from siem_log_detector.parser import parse_log

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"


def _make_alert(source_ip: str = "203.0.113.10") -> Alert:
    return Alert(
        rule_id="SSH-BF-001",
        title="Test",
        severity="high",
        mitre_techniques=("T1110",),
        source_ip=source_ip,
        hostnames=("host",),
        username=None,
        first_seen=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        last_seen=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        event_count=1,
        unique_users=(),
        description="test",
        recommended_actions=(),
        evidence=(),
    )


class EnrichmentTests(unittest.TestCase):
    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._CACHE_PATH")
    def test_enrich_alerts_adds_fields(self, mock_cache_path, mock_query) -> None:
        mock_cache_path.exists.return_value = False
        mock_query.return_value = {
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "usageType": "Data Center",
        }
        alerts = (_make_alert("203.0.113.10"),)
        enriched = enrich_alerts(alerts, "fake-key")

        self.assertEqual(len(enriched), 1)
        data = enriched[0].to_dict()
        self.assertEqual(data["abuse_score"], 85)
        self.assertEqual(data["country"], "US")
        self.assertEqual(data["usage_type"], "Data Center")

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._CACHE_PATH")
    def test_enrich_alerts_caches_results(self, mock_cache_path, mock_query) -> None:
        mock_cache_path.exists.return_value = False
        mock_query.return_value = {
            "abuseConfidenceScore": 50,
            "countryCode": "DE",
            "usageType": "Government",
        }
        alerts = (_make_alert("203.0.113.10"), _make_alert("203.0.113.10"))
        enriched = enrich_alerts(alerts, "fake-key")

        self.assertEqual(mock_query.call_count, 1)
        self.assertEqual(len(enriched), 2)

    def test_enrich_without_api_key_returns_original(self) -> None:
        alerts = (_make_alert(),)
        enriched = enrich_alerts(alerts, "")

        self.assertEqual(enriched, alerts)


if __name__ == "__main__":
    unittest.main()
