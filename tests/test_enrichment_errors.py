from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from siem_log_detector.enrichment import enrich_alerts, _load_cache, _save_cache
from siem_log_detector.models import Alert


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


class EnrichmentErrorPathTests(unittest.TestCase):
    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_uses_cache_on_hit(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {
            "203.0.113.10": {
                "timestamp": 9999999999,
                "data": {"abuse_score": 10, "country": "US"},
            }
        }
        alerts = (_make_alert("203.0.113.10"),)
        enriched = enrich_alerts(alerts, "fake-key")

        mock_query.assert_not_called()
        self.assertEqual(len(enriched), 1)

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_handles_api_none_response(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {}
        mock_query.return_value = None
        alerts = (_make_alert("203.0.113.10"),)
        enriched = enrich_alerts(alerts, "fake-key")

        mock_query.assert_called_once()
        self.assertEqual(len(enriched), 1)
        self.assertIs(enriched[0], alerts[0])

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_handles_empty_api_response(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {}
        mock_query.return_value = {}
        alerts = (_make_alert("203.0.113.10"),)
        enriched = enrich_alerts(alerts, "fake-key")

        mock_query.assert_called_once()
        self.assertEqual(len(enriched), 1)
        self.assertIsInstance(enriched[0], type(enriched[0]))

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_saves_cache(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {}
        mock_query.return_value = {"abuseConfidenceScore": 0, "countryCode": "US", "usageType": "Fixed Line"}
        alerts = (_make_alert("203.0.113.10"),)
        enrich_alerts(alerts, "fake-key")

        mock_save.assert_called_once()

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_alerts_wrapper_exposes_original_fields(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {}
        mock_query.return_value = {"abuseConfidenceScore": 50, "countryCode": "DE", "usageType": "Gov"}
        alert = _make_alert("203.0.113.10")
        enriched = enrich_alerts((alert,), "fake-key")

        self.assertEqual(enriched[0].rule_id, "SSH-BF-001")
        self.assertEqual(enriched[0].source_ip, "203.0.113.10")
        self.assertEqual(enriched[0].severity, "high")

    @patch("siem_log_detector.enrichment._query_abuseipdb")
    @patch("siem_log_detector.enrichment._load_cache")
    @patch("siem_log_detector.enrichment._save_cache")
    def test_enrich_handles_query_none(self, mock_save, mock_load, mock_query) -> None:
        mock_load.return_value = {}
        mock_query.return_value = None
        alerts = (_make_alert("203.0.113.10"),)
        enriched = enrich_alerts(alerts, "fake-key")

        self.assertEqual(len(enriched), 1)
        self.assertIs(enriched[0], alerts[0])


if __name__ == "__main__":
    unittest.main()
