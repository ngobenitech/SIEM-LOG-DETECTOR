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


class CliEdgeCaseTests(unittest.TestCase):
    def test_no_arguments_defaults_to_detect(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(SAMPLE_LOG)])
        self.assertEqual(exit_code, 0)

    def test_unknown_command_returns_one(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["sigma"])
        self.assertEqual(exit_code, 1)

    def test_detect_with_output_format_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "table.txt"
            with redirect_stdout(StringIO()):
                exit_code = main([
                    str(SAMPLE_LOG),
                    "--output-format", "table",
                    "--output", str(output),
                ])
            self.assertEqual(exit_code, 0)
            self.assertIn("SSH-BF-001", output.read_text(encoding="utf-8"))

    def test_detect_with_output_format_splunk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "splunk.jsonl"
            with redirect_stdout(StringIO()):
                exit_code = main([
                    str(SAMPLE_LOG),
                    "--output-format", "splunk",
                    "--output", str(output),
                ])
            self.assertEqual(exit_code, 0)
            lines = output.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 3)

    def test_validate_invalid_yaml_returns_one(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("not: valid: [\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with redirect_stdout(StringIO()):
                exit_code = main(["validate", str(path)])
            self.assertEqual(exit_code, 1)
        finally:
            path.unlink()

    def test_sigma_import_invalid_yaml_returns_one(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("not: valid: [\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with redirect_stdout(StringIO()):
                exit_code = main(["sigma", "import", str(path)])
            self.assertEqual(exit_code, 1)
        finally:
            path.unlink()

    def test_export_stdout_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "events.json"
            with redirect_stdout(StringIO()):
                exit_code = main(["export", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 0)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 15)

    def test_export_stdout_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "events.csv"
            with redirect_stdout(StringIO()):
                exit_code = main(["export", str(SAMPLE_LOG), "--output-format", "csv", "--output", str(output)])
            self.assertEqual(exit_code, 0)
            content = output.read_text(encoding="utf-8")
            self.assertIn("line_number,timestamp,hostname,username,source_ip,source_port,status,auth_method", content)


if __name__ == "__main__":
    unittest.main()
