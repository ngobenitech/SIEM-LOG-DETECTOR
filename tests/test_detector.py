from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from siem_log_detector.detector import DetectionConfig, detect
from siem_log_detector.models import AuthEvent

BASE_TIME = datetime(2026, 7, 29, 9, 0, tzinfo=timezone.utc)


def make_event(
    minute: int,
    *,
    source_ip: str = "203.0.113.10",
    hostname: str = "host",
    username: str = "root",
    status: str = "failure",
) -> AuthEvent:
    timestamp = BASE_TIME + timedelta(minutes=minute)
    action = "Failed password" if status == "failure" else "Accepted password"
    raw = (
        f"{timestamp.isoformat()} {hostname} sshd[1]: {action} for {username} "
        f"from {source_ip} port 50000 ssh2"
    )
    return AuthEvent(
        line_number=minute + 1,
        timestamp=timestamp,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        source_port=50000,
        status=status,  # type: ignore[arg-type]
        auth_method="password",
        raw=raw,
    )


class DetectionTests(unittest.TestCase):
    def test_detects_brute_force_inside_window(self) -> None:
        alerts = detect(make_event(index) for index in range(5))

        self.assertEqual([alert.rule_id for alert in alerts], ["SSH-BF-001"])
        self.assertEqual(alerts[0].event_count, 5)

    def test_does_not_combine_failures_outside_window(self) -> None:
        events = [make_event(index * 10) for index in range(5)]

        self.assertEqual(detect(events), ())

    def test_detects_password_spray_across_accounts(self) -> None:
        events = [
            make_event(index, source_ip="198.51.100.25", username=username)
            for index, username in enumerate(("alice", "bob", "carol", "dave"))
        ]
        alerts = detect(events)

        self.assertEqual([alert.rule_id for alert in alerts], ["SSH-PS-002"])
        self.assertEqual(alerts[0].unique_users, ("alice", "bob", "carol", "dave"))

    def test_detects_success_after_failures(self) -> None:
        events = [make_event(index, username="analyst") for index in range(3)]
        events.append(make_event(3, username="analyst", status="success"))
        alerts = detect(events)

        self.assertEqual([alert.rule_id for alert in alerts], ["SSH-SAF-003"])
        self.assertEqual(alerts[0].severity, "critical")
        self.assertIn("not proof of compromise", alerts[0].description)

    def test_does_not_correlate_success_from_different_source(self) -> None:
        events = [make_event(index, username="analyst") for index in range(3)]
        events.append(
            make_event(
                3,
                source_ip="203.0.113.99",
                username="analyst",
                status="success",
            )
        )

        self.assertEqual(detect(events), ())

    def test_does_not_correlate_success_on_different_host(self) -> None:
        events = [make_event(index, username="analyst") for index in range(3)]
        events.append(
            make_event(
                3, hostname="different-host", username="analyst", status="success"
            )
        )

        self.assertEqual(detect(events), ())

    def test_custom_thresholds_are_applied(self) -> None:
        config = DetectionConfig(
            brute_force_threshold=2,
            spray_user_threshold=10,
            success_failure_threshold=10,
        )
        alerts = detect([make_event(0), make_event(1)], config)

        self.assertEqual([alert.rule_id for alert in alerts], ["SSH-BF-001"])

    def test_rejects_non_positive_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be at least 1"):
            DetectionConfig(brute_force_threshold=0)


if __name__ == "__main__":
    unittest.main()
