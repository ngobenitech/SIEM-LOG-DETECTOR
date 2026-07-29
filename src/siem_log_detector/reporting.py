"""Human-readable and machine-readable alert reporting."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from siem_log_detector.detector import DetectionConfig
from siem_log_detector.models import Alert
from siem_log_detector.parser import ParseResult

_CSV_FIELDS = (
    "rule_id",
    "title",
    "severity",
    "mitre_techniques",
    "source_ip",
    "hostnames",
    "username",
    "first_seen",
    "last_seen",
    "event_count",
    "unique_users",
    "description",
)


def build_report(
    input_path: Path,
    parse_result: ParseResult,
    alerts: Iterable[Alert],
    config: DetectionConfig,
) -> dict[str, object]:
    """Build the stable report schema used by JSON output."""

    normalized_alerts = tuple(alerts)
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": str(input_path),
        "summary": {
            "total_lines": parse_result.total_lines,
            "parsed_events": len(parse_result.events),
            "skipped_lines": parse_result.skipped_lines,
            "alerts": len(normalized_alerts),
        },
        "configuration": config.to_dict(),
        "alerts": [alert.to_dict() for alert in normalized_alerts],
    }


def format_table(alerts: Iterable[Alert]) -> str:
    """Return a dependency-free console table."""

    normalized = tuple(alerts)
    if not normalized:
        return "No alerts matched the configured thresholds."

    headers = ("RULE", "SEVERITY", "HOST", "SOURCE IP", "USER", "EVENTS", "TITLE")
    rows = [
        (
            alert.rule_id,
            alert.severity.upper(),
            (
                alert.hostnames[0]
                if len(alert.hostnames) == 1
                else f"{len(alert.hostnames)} hosts"
            ),
            alert.source_ip,
            alert.username or "-",
            str(alert.event_count),
            alert.title,
        )
        for alert in normalized
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]

    def render(row: tuple[str, ...]) -> str:
        return "  ".join(
            value.ljust(widths[index]) for index, value in enumerate(row)
        ).rstrip()

    separator = "  ".join("-" * width for width in widths)
    return "\n".join((render(headers), separator, *(render(row) for row in rows)))


def format_csv(alerts: Iterable[Alert]) -> str:
    """Return alert summaries as CSV text."""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for alert in alerts:
        row = alert.to_dict()
        writer.writerow(
            {
                field: (
                    ";".join(str(item) for item in row[field])
                    if isinstance(row[field], list)
                    else row[field]
                )
                for field in _CSV_FIELDS
            }
        )
    return output.getvalue()


def format_json(report: dict[str, object]) -> str:
    """Return a pretty-printed JSON report."""

    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def write_output(path: Path, content: str) -> None:
    """Write a report, creating its parent directory when required."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
