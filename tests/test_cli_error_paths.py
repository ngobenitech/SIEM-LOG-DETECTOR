from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from siem_log_detector.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth.log"
BENIGN_LOG = PROJECT_ROOT / "sample_logs" / "benign.log"


class CliErrorPathTests(unittest.TestCase):
    def test_detect_missing_log_returns_two(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["missing.log"])
        self.assertEqual(exit_code, 2)

    def test_detect_invalid_config_returns_one(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("brute_force_threshold: not_an_int\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with redirect_stdout(StringIO()):
                exit_code = main([str(SAMPLE_LOG), "--config", str(path)])
            self.assertEqual(exit_code, 1)
        finally:
            path.unlink()

    def test_validate_missing_config_returns_one(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["validate", "nonexistent.yml"])
        self.assertEqual(exit_code, 1)

    def test_validate_valid_config_returns_zero(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("brute_force_threshold: 3\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with redirect_stdout(StringIO()):
                exit_code = main(["validate", str(path)])
            self.assertEqual(exit_code, 0)
        finally:
            path.unlink()

    def test_export_missing_log_returns_two(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["export", "missing.log"])
        self.assertEqual(exit_code, 2)

    def test_export_json_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "events.json"
            with redirect_stdout(StringIO()):
                exit_code = main(["export", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 0)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 15)

    def test_export_csv_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "events.csv"
            with redirect_stdout(StringIO()):
                exit_code = main(["export", str(SAMPLE_LOG), "--output-format", "csv", "--output", str(output)])
            self.assertEqual(exit_code, 0)
            content = output.read_text(encoding="utf-8")
            self.assertIn("line_number", content)

    def test_sigma_export_stdout(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["sigma", "export", "SSH-PS-002"])
        self.assertEqual(exit_code, 0)
        self.assertIn("SSH-PS-002", stdout.getvalue())

    def test_attack_coverage_missing_log_returns_two(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["attack", "coverage", "nonexistent.log"])
        self.assertEqual(exit_code, 2)

    def test_fail_on_alert_with_no_alerts_returns_zero(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(BENIGN_LOG), "--fail-on-alert"])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
