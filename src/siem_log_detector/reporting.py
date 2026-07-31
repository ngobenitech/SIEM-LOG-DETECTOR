"""Human-readable and machine-readable alert reporting."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from siem_log_detector.detector import DetectionConfig
from siem_log_detector.models import Alert, AuthEvent
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

_EVENT_CSV_FIELDS = (
    "line_number",
    "timestamp",
    "hostname",
    "username",
    "source_ip",
    "source_port",
    "status",
    "auth_method",
)


def build_report(
    input_path: Path,
    parse_result: ParseResult,
    alerts: Iterable[Alert],
    config: DetectionConfig,
) -> dict[str, object]:
    """Build the stable report schema used by JSON output.

    Args:
        input_path: Path to the processed log file.
        parse_result: Parser output containing events and statistics.
        alerts: Iterable of detection alerts produced by the engine.
        config: Active detection configuration.

    Returns:
        Dictionary with schema version, generation timestamp, summary,
        configuration, and alert list.
    """
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
    """Return a dependency-free console table.

    Args:
        alerts: Iterable of alerts to format.

    Returns:
        Formatted table string or a no-alert message.
    """
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
    """Return alert summaries as CSV text.

    Args:
        alerts: Iterable of alerts to format.

    Returns:
        CSV string with header and one row per alert.
    """
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
    """Return a pretty-printed JSON report.

    Args:
        report: Report dictionary produced by build_report.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def format_splunk(alerts: Iterable[Alert]) -> str:
    """Return alerts as JSON Lines suitable for Splunk ingestion.

    Each line is a self-contained JSON object. Splunk can index this output
    directly using a JSON sourcetype.

    Args:
        alerts: Iterable of alerts to format.

    Returns:
        JSON Lines string with one object per alert.
    """
    lines = []
    for alert in alerts:
        data = alert.to_dict()
        data["_siem_rule"] = data.pop("rule_id")
        data["_siem_severity"] = data.pop("severity")
        lines.append(json.dumps(data, sort_keys=False))
    return "\n".join(lines) + "\n" if lines else ""


def format_events_json(events: Iterable[AuthEvent]) -> str:
    """Return parsed events as a JSON array.

    Args:
        events: Iterable of parsed authentication events.

    Returns:
        Pretty-printed JSON string containing the event list.
    """
    event_list = [event.to_dict() for event in events]
    return json.dumps(event_list, indent=2, sort_keys=False) + "\n"


def format_events_csv(events: Iterable[AuthEvent]) -> str:
    """Return parsed events as CSV text.

    Args:
        events: Iterable of parsed authentication events.

    Returns:
        CSV string with header and one row per event.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_EVENT_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for event in events:
        row = event.to_dict()
        writer.writerow(
            {
                field: (
                    ";".join(str(item) for item in row[field])
                    if isinstance(row[field], list)
                    else row[field]
                )
                for field in _EVENT_CSV_FIELDS
            }
        )
    return output.getvalue()


def write_output(path: Path, content: str) -> None:
    """Write a report, creating its parent directory when required.

    Args:
        path: Destination file path.
        content: String content to write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
