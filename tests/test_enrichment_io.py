from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from siem_log_detector.enrichment import _load_cache, _save_cache


class EnrichmentIOErrorPathTests(unittest.TestCase):
    def test_load_cache_corrupt_json_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            handle.write("not valid json\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with patch("siem_log_detector.enrichment._CACHE_PATH", path):
                result = _load_cache()
                self.assertEqual(result, {})
        finally:
            path.unlink()

    def test_load_cache_missing_file_returns_empty(self) -> None:
        with patch("siem_log_detector.enrichment._CACHE_PATH", Path("nonexistent.json")):
            result = _load_cache()
            self.assertEqual(result, {})

    def test_save_cache_handles_write_error(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            handle.write("{}")
            handle.flush()
            path = Path(handle.name)

        try:
            path.chmod(0o444)
            with patch("siem_log_detector.enrichment._CACHE_PATH", path):
                _save_cache({"test": "data"})
        finally:
            path.chmod(0o666)
            path.unlink()

    @patch("siem_log_detector.enrichment.urlopen")
    def test_query_abuseipdb_handles_http_error(self, mock_urlopen) -> None:
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            "https://api.abuseipdb.com/api/v2/check", 403, "Forbidden", {}, None
        )
        from siem_log_detector.enrichment import _query_abuseipdb
        result = _query_abuseipdb("203.0.113.10", "fake-key")
        self.assertIsNone(result)

    @patch("siem_log_detector.enrichment.urlopen")
    def test_query_abuseipdb_handles_url_error(self, mock_urlopen) -> None:
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("network unreachable")
        from siem_log_detector.enrichment import _query_abuseipdb
        result = _query_abuseipdb("203.0.113.10", "fake-key")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
