from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from siem_log_detector.detector import DetectionConfig
from siem_log_detector.sigma import export_sigma, import_sigma, write_sigma
from siem_log_detector.attack_navigator import build_navigator_layer, write_navigator_layer
from siem_log_detector.detector import detect
from siem_log_detector.models import Alert
from siem_log_detector.parser import parse_log

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"


class SigmaTests(unittest.TestCase):
    def test_import_sigma_rule_returns_config(self) -> None:
        rule_path = Path(__file__).resolve().parents[1] / "examples" / "sigma" / "ssh-brute-force.yml"
        rule = import_sigma(rule_path)

        self.assertEqual(rule.title, "SSH Brute Force Detection")
        self.assertEqual(rule.id, "ssh-brute-force-rule")
        self.assertIsInstance(rule.siem_config, DetectionConfig)
        self.assertEqual(rule.siem_config.brute_force_threshold, 5)

    def test_import_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            import_sigma(Path("does_not_exist.yml"))

    def test_import_invalid_yaml_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as handle:
            handle.write("not: valid: yaml: [\n")
            handle.flush()
            path = Path(handle.name)

        try:
            with self.assertRaises(ValueError):
                import_sigma(path)
        finally:
            path.unlink()

    def test_export_sigma_returns_known_rule(self) -> None:
        rule = export_sigma("SSH-BF-001")

        self.assertEqual(rule.id, "SSH-BF-001")
        self.assertIn("brute force", rule.description.lower())
        self.assertIsInstance(rule.siem_config, DetectionConfig)

    def test_export_unknown_rule_raises(self) -> None:
        with self.assertRaises(ValueError):
            export_sigma("UNKNOWN-RULE")

    def test_write_sigma_creates_file(self) -> None:
        rule = export_sigma("SSH-PS-002")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rule.yml"
            write_sigma(rule, path)

            self.assertTrue(path.exists())
            content = path.read_text(encoding="utf-8")
            self.assertIn("SSH-PS-002", content)
            self.assertIn("password spraying", content.lower())


class AttackNavigatorTests(unittest.TestCase):
    def test_build_layer_from_alerts(self) -> None:
        parse_result = parse_log(SAMPLE_LOG)
        alerts = detect(parse_result.events)
        layer = build_navigator_layer(alerts)

        self.assertEqual(layer["name"], "SIEM Log Detector Coverage")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("techniques", layer)
        technique_ids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertTrue(any(t.startswith("T1110") for t in technique_ids))

    def test_write_layer_creates_file(self) -> None:
        parse_result = parse_log(SAMPLE_LOG)
        alerts = detect(parse_result.events)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "layer.json"
            write_navigator_layer(alerts, path)

            self.assertTrue(path.exists())
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["domain"], "enterprise-attack")


if __name__ == "__main__":
    unittest.main()
