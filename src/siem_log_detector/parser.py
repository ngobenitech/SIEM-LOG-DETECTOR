"""Parse OpenSSH authentication records into normalized events."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from siem_log_detector.models import AuthEvent

_TIMESTAMP = (
    r"(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")"
)
_PREFIX_RE = re.compile(
    rf"^{_TIMESTAMP}\s+(?P<hostname>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)
_AUTH_RE = re.compile(
    r"^(?P<action>Failed password|Accepted password|Accepted publickey)"
    r" for (?:invalid user )?(?P<username>\S+)"
    r" from (?P<source_ip>\S+) port (?P<source_port>\d+)"
)


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Parsed events plus ingestion statistics."""

    events: tuple[AuthEvent, ...]
    total_lines: int
    skipped_lines: int


def _parse_timestamp(value: str, assumed_year: int) -> datetime:
    if value[0].isdigit():
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    parsed = datetime.strptime(f"{assumed_year} {value}", "%Y %b %d %H:%M:%S")
    return parsed.replace(tzinfo=timezone.utc)


def parse_lines(lines: Iterable[str], assumed_year: int | None = None) -> ParseResult:
    """Parse iterable log lines.

    Non-SSH and unsupported records are counted as skipped rather than raising,
    which mirrors normal ingestion of a mixed Linux ``auth.log`` file.
    """

    year = assumed_year or datetime.now(timezone.utc).year
    events: list[AuthEvent] = []
    total_lines = 0
    skipped_lines = 0

    for line_number, raw_line in enumerate(lines, start=1):
        total_lines += 1
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        prefix_match = _PREFIX_RE.match(line)
        if not prefix_match:
            skipped_lines += 1
            continue

        auth_match = _AUTH_RE.match(prefix_match.group("message"))
        if not auth_match:
            skipped_lines += 1
            continue

        try:
            source_ip = str(ipaddress.ip_address(auth_match.group("source_ip")))
            timestamp = _parse_timestamp(prefix_match.group("timestamp"), year)
            source_port = int(auth_match.group("source_port"))
            if not 1 <= source_port <= 65_535:
                raise ValueError("source port is outside the TCP range")
        except (ValueError, TypeError):
            skipped_lines += 1
            continue

        action = auth_match.group("action")
        events.append(
            AuthEvent(
                line_number=line_number,
                timestamp=timestamp,
                hostname=prefix_match.group("hostname"),
                username=auth_match.group("username"),
                source_ip=source_ip,
                source_port=source_port,
                status="failure" if action == "Failed password" else "success",
                auth_method=action.split()[-1],
                raw=line,
            )
        )

    return ParseResult(
        events=tuple(events),
        total_lines=total_lines,
        skipped_lines=skipped_lines,
    )


def parse_log(path: Path, assumed_year: int | None = None) -> ParseResult:
    """Read and parse a UTF-8-compatible authentication log."""

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, assumed_year=assumed_year)
