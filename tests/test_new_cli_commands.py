from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from siem_log_detector.cli import main

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"
SIGMA_RULE = Path(__file__).resolve().parents[1] / "examples" / "sigma" / "ssh-brute-force.yml"


class CliNewCommandsTests(unittest.TestCase):
    def test_sigma_import(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main(["sigma", "import", str(SIGMA_RULE)])
        self.assertEqual(exit_code, 0)

    def test_sigma_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "rule.yml"
            with redirect_stdout(StringIO()):
                exit_code = main(["sigma", "export", "SSH-BF-001", "--output", str(output)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            self.assertIn("SSH-BF-001", output.read_text(encoding="utf-8"))

    def test_attack_coverage_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "layer.json"
            with redirect_stdout(StringIO()):
                exit_code = main(["attack", "coverage", str(SAMPLE_LOG), "--output", str(output)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["domain"], "enterprise-attack")

    def test_enrich_flag_skips_without_key(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(SAMPLE_LOG), "--enrich"])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
