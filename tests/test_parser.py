from __future__ import annotations

import unittest
from datetime import datetime, timezone

from siem_log_detector.parser import parse_lines


class ParserTests(unittest.TestCase):
    def test_parses_iso_failure_and_success(self) -> None:
        result = parse_lines(
            [
                "2026-07-29T09:00:00Z host sshd[1]: Failed password for "
                "invalid user admin from 203.0.113.10 port 50001 ssh2\n",
                "2026-07-29T09:01:00+00:00 host sshd[2]: Accepted publickey "
                "for deploy from 2001:db8::10 port 50002 ssh2\n",
            ]
        )

        self.assertEqual(len(result.events), 2)
        self.assertEqual(result.events[0].status, "failure")
        self.assertEqual(result.events[0].username, "admin")
        self.assertEqual(result.events[1].status, "success")
        self.assertEqual(result.events[1].source_ip, "2001:db8::10")

    def test_parses_traditional_syslog_with_assumed_year(self) -> None:
        result = parse_lines(
            [
                "May  4 01:14:35 server sshd[12345]: Failed password for root "
                "from 192.0.2.10 port 54722 ssh2\n"
            ],
            assumed_year=2025,
        )

        self.assertEqual(
            result.events[0].timestamp,
            datetime(2025, 5, 4, 1, 14, 35, tzinfo=timezone.utc),
        )

    def test_counts_unsupported_and_invalid_records_as_skipped(self) -> None:
        result = parse_lines(
            [
                "# synthetic fixture\n",
                "2026-07-29T09:00:00Z host sudo: unrelated event\n",
                "2026-07-29T09:00:00Z host sshd[1]: Failed password for root "
                "from 999.0.0.1 port 22 ssh2\n",
                "2026-07-29T09:00:00Z host sshd[1]: Failed password for root "
                "from 192.0.2.10 port 70000 ssh2\n",
                "\n",
            ]
        )

        self.assertEqual(result.skipped_lines, 5)
        self.assertEqual(result.skipped_lines, 5)
        self.assertEqual(result.events, ())

    def test_normalizes_source_ip(self) -> None:
        result = parse_lines(
            [
                "2026-07-29T09:00:00Z host sshd[1]: Failed password for root "
                "from 2001:0db8:0:0:0:0:0:1 port 22 ssh2\n"
            ]
        )

        self.assertEqual(result.events[0].source_ip, "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
