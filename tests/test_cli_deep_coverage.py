from __future__ import annotations

import json
import logging
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from siem_log_detector.cli import (
    JsonFormatter,
    DynamicStreamHandler,
    _load_abuseipdb_key,
    _run_attack_coverage,
    _run_detect,
    _run_export,
    _run_sigma_export,
    load_config_from_yaml,
    main,
    setup_logging,
)
from siem_log_detector.detector import DetectionConfig

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"


class CliFormatterTests(unittest.TestCase):
    def test_json_formatter_with_exception(self) -> None:
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error", args=(), exc_info=(ValueError, ValueError("bad"), None),
        )
        output = formatter.format(record)
        self.assertIn('"exception"', output)

    def test_dynamic_stream_handler_error_path(self) -> None:
        handler = DynamicStreamHandler()
        with patch("sys.stdout.write", side_effect=OSError("disk full")):
            handler.emit(logging.LogRecord("x", logging.INFO, "", 0, "msg", (), None))

    def test_setup_logging_debug_sets_json_formatter(self) -> None:
        logger = setup_logging("DEBUG")
        handler = logger.handlers[0]
        self.assertIsInstance(handler.formatter, type(handler.formatter))


class ConfigParsingTests(unittest.TestCase):
    def test_load_config_yaml_import_error(self) -> None:
        with patch("builtins.__import__", side_effect=ImportError("no yaml")):
            with self.assertRaises(ImportError):
                load_config_from_yaml(SAMPLE_LOG)

    def test_load_config_non_dict_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("- item1\n- item2\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with self.assertRaises(ValueError):
                load_config_from_yaml(path)
        finally:
            path.unlink()


class DetectErrorPathTests(unittest.TestCase):
    def test_detect_invalid_threshold_returns_one(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--brute-force-threshold", "0"])
        self.assertEqual(exit_code, 1)

    def test_detect_missing_config_file_returns_one(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--config", "nonexistent.yml"])
        self.assertEqual(exit_code, 1)

    def test_detect_detection_exception_returns_two(self) -> None:
        with patch("siem_log_detector.cli.detect", side_effect=RuntimeError("boom")):
            with patch("sys.stdout", new_callable=lambda: StringIO()):
                exit_code = main([str(SAMPLE_LOG)])
        self.assertEqual(exit_code, 2)

    def test_detect_enrichment_key_from_env(self) -> None:
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "env-key"}):
            with patch("siem_log_detector.cli.enrich_alerts", return_value=()) as mock_enrich:
                with patch("sys.stdout", new_callable=lambda: StringIO()):
                    exit_code = main([str(SAMPLE_LOG), "--enrich"])
                self.assertEqual(exit_code, 0)
                mock_enrich.assert_called_once()

    def test_detect_enrichment_key_exception_returns_zero(self) -> None:
        with patch("siem_log_detector.cli._load_abuseipdb_key", side_effect=Exception("boom")):
            with patch("sys.stdout", new_callable=lambda: StringIO()):
                exit_code = main([str(SAMPLE_LOG), "--enrich"])
        self.assertEqual(exit_code, 0)

    def test_detect_enrichment_key_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / ".abuseipdb_key"
            key_file.write_text("file-key", encoding="utf-8")
            with patch("siem_log_detector.cli.Path", side_effect=lambda p: key_file if str(p) == ".abuseipdb_key" else Path(p)):
                with patch("siem_log_detector.cli.enrich_alerts", return_value=()) as mock_enrich:
                    with patch("sys.stdout", new_callable=lambda: StringIO()):
                        exit_code = main([str(SAMPLE_LOG), "--enrich"])
                    self.assertEqual(exit_code, 0)
                    mock_enrich.assert_called_once()

    def test_detect_csv_output_format(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--output-format", "csv"])
        self.assertEqual(exit_code, 0)

    def test_detect_write_output_error_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "readonly" / "report.txt"
            with patch("siem_log_detector.cli.write_output", side_effect=OSError("disk full")):
                with patch("sys.stdout", new_callable=lambda: StringIO()):
                    exit_code = main([str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 2)


class ExportErrorPathTests(unittest.TestCase):
    def test_export_write_output_error_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "readonly" / "events.json"
            with patch("siem_log_detector.cli.write_output", side_effect=OSError("disk full")):
                with patch("sys.stdout", new_callable=lambda: StringIO()):
                    exit_code = main(["export", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 2)


class SigmaExportErrorPathTests(unittest.TestCase):
    def test_sigma_export_yaml_import_error_returns_one(self) -> None:
        with patch.dict("sys.modules", {"yaml": None}):
            with patch("sys.stdout", new_callable=lambda: StringIO()):
                exit_code = main(["sigma", "export", "SSH-BF-001"])
        self.assertEqual(exit_code, 1)

    def test_sigma_export_write_output_error_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "readonly" / "rule.yml"
            with patch("siem_log_detector.cli.write_output", side_effect=OSError("disk full")):
                with patch("sys.stdout", new_callable=lambda: StringIO()):
                    exit_code = main(["sigma", "export", "SSH-BF-001", "--output", str(output)])
            self.assertEqual(exit_code, 2)


class AttackCoverageErrorPathTests(unittest.TestCase):
    def test_attack_coverage_write_output_error_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "readonly" / "layer.json"
            with patch("siem_log_detector.cli.write_navigator_layer", side_effect=OSError("disk full")):
                with patch("sys.stdout", new_callable=lambda: StringIO()):
                    exit_code = main(["attack", "coverage", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 2)


class ExportStdoutTests(unittest.TestCase):
    def test_export_json_to_stdout(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main(["export", str(SAMPLE_LOG)])
        self.assertEqual(exit_code, 0)

    def test_export_csv_to_stdout(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main(["export", str(SAMPLE_LOG), "--output-format", "csv"])
        self.assertEqual(exit_code, 0)


class AttackCoverageStdoutTests(unittest.TestCase):
    def test_attack_coverage_to_stdout(self) -> None:
        with patch("sys.stdout", new_callable=lambda: StringIO()):
            exit_code = main(["attack", "coverage", str(SAMPLE_LOG)])
        self.assertEqual(exit_code, 0)


class MainEdgePathTests(unittest.TestCase):
    def test_main_with_none_argv(self) -> None:
        with patch("sys.argv", ["siem-detect", str(SAMPLE_LOG)]):
            exit_code = main(None)
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
