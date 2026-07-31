from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from siem_log_detector.cli import main
from siem_log_detector.detector import detect
from siem_log_detector.models import Alert
from siem_log_detector.parser import parse_log
from siem_log_detector.reporting import (
    build_report,
    format_csv,
    format_events_csv,
    format_events_json,
    format_json,
    format_splunk,
    format_table,
    write_output,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth.log"
BENIGN_LOG = PROJECT_ROOT / "sample_logs" / "benign.log"
SIGMA_RULE = PROJECT_ROOT / "examples" / "sigma" / "ssh-brute-force.yml"


class ReportingFormatterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parse_result = parse_log(SAMPLE_LOG)
        self.config = __import__("siem_log_detector.detector", fromlist=["DetectionConfig"]).DetectionConfig()
        self.alerts = detect(self.parse_result.events, self.config)

    def test_format_json_contains_schema(self) -> None:
        report = build_report(SAMPLE_LOG, self.parse_result, self.alerts, self.config)
        text = format_json(report)

        self.assertIn('"schema_version": "1.0"', text)
        data = json.loads(text)
        self.assertEqual(data["summary"]["alerts"], 3)

    def test_format_splunk_renames_fields(self) -> None:
        text = format_splunk(self.alerts)
        lines = text.strip().splitlines()

        self.assertEqual(len(lines), 3)
        first = json.loads(lines[0])
        self.assertIn("_siem_rule", first)
        self.assertIn("_siem_severity", first)
        self.assertEqual(first["_siem_rule"], "SSH-SAF-003")

    def test_format_events_json_lists_parsed_events(self) -> None:
        text = format_events_json(self.parse_result.events)
        data = json.loads(text)

        self.assertEqual(len(data), 15)
        self.assertEqual(data[0]["source_ip"], "192.0.2.80")

    def test_format_events_csv_has_header_and_rows(self) -> None:
        text = format_events_csv(self.parse_result.events)
        lines = text.strip().splitlines()

        self.assertEqual(lines[0], "line_number,timestamp,hostname,username,source_ip,source_port,status,auth_method")
        self.assertEqual(len(lines), 16)

    def test_write_output_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "report.json"
            write_output(path, "hello")

            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(encoding="utf-8"), "hello")


class CliSigmaAndAttackTests(unittest.TestCase):
    def test_sigma_import_success(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["sigma", "import", str(SIGMA_RULE)])
        self.assertEqual(exit_code, 0)

    def test_sigma_import_missing_file(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["sigma", "import", "nonexistent.yml"])
        self.assertEqual(exit_code, 1)

    def test_sigma_export_known_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "rule.yml"
            with redirect_stdout(StringIO()):
                exit_code = main(["sigma", "export", "SSH-BF-001", "--output", str(output)])
            self.assertEqual(exit_code, 0)
            self.assertIn("SSH-BF-001", output.read_text(encoding="utf-8"))

    def test_sigma_export_unknown_rule(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["sigma", "export", "UNKNOWN"])
        self.assertEqual(exit_code, 1)

    def test_attack_coverage_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "layer.json"
            with redirect_stdout(StringIO()):
                exit_code = main(["attack", "coverage", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["domain"], "enterprise-attack")

    def test_attack_coverage_missing_log(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["attack", "coverage", "missing.log"])
        self.assertEqual(exit_code, 2)

    def test_detect_with_enrich_no_key(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--enrich"])
        self.assertEqual(exit_code, 0)

    def test_detect_with_enrich_missing_log(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["missing.log", "--enrich"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
