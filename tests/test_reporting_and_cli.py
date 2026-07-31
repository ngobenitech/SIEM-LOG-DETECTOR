from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from siem_log_detector.cli import main
from siem_log_detector.detector import DetectionConfig, detect
from siem_log_detector.parser import parse_log
from siem_log_detector.reporting import (
    build_report,
    format_csv,
    format_table,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth.log"
BENIGN_LOG = PROJECT_ROOT / "sample_logs" / "benign.log"


class ReportingAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parse_result = parse_log(SAMPLE_LOG)
        self.config = DetectionConfig()
        self.alerts = detect(self.parse_result.events, self.config)

    def test_sample_log_exercises_all_rules(self) -> None:
        self.assertEqual(
            {alert.rule_id for alert in self.alerts},
            {"SSH-BF-001", "SSH-PS-002", "SSH-SAF-003"},
        )

    def test_benign_fixture_produces_no_alerts(self) -> None:
        benign_result = parse_log(BENIGN_LOG)

        self.assertEqual(detect(benign_result.events), ())

    def test_report_has_stable_schema_and_summary(self) -> None:
        report = build_report(SAMPLE_LOG, self.parse_result, self.alerts, self.config)

        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["summary"]["parsed_events"], 15)
        self.assertEqual(report["summary"]["alerts"], 3)

    def test_csv_contains_one_row_per_alert(self) -> None:
        csv_text = format_csv(self.alerts)

        self.assertEqual(len(csv_text.strip().splitlines()), 4)
        self.assertIn("SSH-SAF-003", csv_text)

    def test_empty_table_has_explicit_message(self) -> None:
        self.assertEqual(
            format_table(()), "No alerts matched the configured thresholds."
        )

    def test_cli_writes_valid_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "alerts.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        str(SAMPLE_LOG),
                        "--output-format",
                        "json",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            report = json.loads(output_path.read_text())
            self.assertEqual(report["summary"]["alerts"], 3)
            self.assertIn("Wrote JSON report", stdout.getvalue())

    def test_fail_on_alert_returns_one(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--fail-on-alert"])

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
