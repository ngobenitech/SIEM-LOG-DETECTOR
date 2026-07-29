"""Command-line interface for the detector."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from siem_log_detector import __version__
from siem_log_detector.detector import DetectionConfig, detect
from siem_log_detector.parser import parse_log
from siem_log_detector.reporting import (
    build_report,
    format_csv,
    format_json,
    format_table,
    write_output,
)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI parser separately so tests can inspect it."""

    parser = argparse.ArgumentParser(
        prog="siem-detect",
        description=(
            "Parse OpenSSH authentication logs and correlate suspicious login patterns."
        ),
    )
    parser.add_argument("log_file", type=Path, help="path to a Linux auth log")
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument("--output", type=Path, help="also write output to this file")
    parser.add_argument(
        "--year",
        type=int,
        help="year to assign to traditional syslog timestamps without a year",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="failed logins from one IP required for SSH-BF-001 (default: 5)",
    )
    parser.add_argument(
        "--brute-force-window",
        type=int,
        default=5,
        metavar="MINUTES",
        help="SSH-BF-001 correlation window (default: 5)",
    )
    parser.add_argument(
        "--spray-user-threshold",
        type=int,
        default=4,
        help="distinct accounts required for SSH-PS-002 (default: 4)",
    )
    parser.add_argument(
        "--spray-window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="SSH-PS-002 correlation window (default: 10)",
    )
    parser.add_argument(
        "--success-failure-threshold",
        type=int,
        default=3,
        help="failures required before success for SSH-SAF-003 (default: 3)",
    )
    parser.add_argument(
        "--success-window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="SSH-SAF-003 lookback window (default: 10)",
    )
    parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="return exit code 1 when one or more alerts are detected",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = DetectionConfig(
            brute_force_threshold=args.brute_force_threshold,
            brute_force_window_minutes=args.brute_force_window,
            spray_user_threshold=args.spray_user_threshold,
            spray_window_minutes=args.spray_window,
            success_failure_threshold=args.success_failure_threshold,
            success_window_minutes=args.success_window,
        )
    except ValueError as exc:
        parser.error(str(exc))

    try:
        result = parse_log(args.log_file, assumed_year=args.year)
    except OSError as exc:
        print(f"error: unable to read {args.log_file}: {exc}", file=sys.stderr)
        return 2

    alerts = detect(result.events, config)
    report = build_report(args.log_file, result, alerts, config)

    if args.format == "json":
        content = format_json(report)
    elif args.format == "csv":
        content = format_csv(alerts)
    else:
        summary = report["summary"]
        content = (
            f"Input: {args.log_file}\n"
            f"Parsed: {summary['parsed_events']} events from "
            f"{summary['total_lines']} lines "
            f"({summary['skipped_lines']} skipped)\n"
            f"Alerts: {summary['alerts']}\n\n"
            f"{format_table(alerts)}\n"
        )

    if args.output:
        try:
            write_output(args.output, content)
        except OSError as exc:
            print(f"error: unable to write {args.output}: {exc}", file=sys.stderr)
            return 2
        if args.format != "table":
            print(f"Wrote {args.format.upper()} report to {args.output}")
        else:
            print(content, end="")
            print(f"\nWrote table report to {args.output}")
    else:
        print(content, end="")

    return 1 if args.fail_on_alert and alerts else 0
