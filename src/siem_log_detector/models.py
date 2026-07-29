"""Domain models shared by the parser, detector, and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

AuthStatus = Literal["failure", "success"]
Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """A normalized SSH authentication event."""

    line_number: int
    timestamp: datetime
    hostname: str
    username: str
    source_ip: str
    source_port: int
    status: AuthStatus
    auth_method: str
    raw: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""

        return {
            "line_number": self.line_number,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "status": self.status,
            "auth_method": self.auth_method,
        }


@dataclass(frozen=True, slots=True)
class Alert:
    """A detection result with investigation context."""

    rule_id: str
    title: str
    severity: Severity
    mitre_techniques: tuple[str, ...]
    source_ip: str
    hostnames: tuple[str, ...]
    username: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    unique_users: tuple[str, ...]
    description: str
    recommended_actions: tuple[str, ...]
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre_techniques": list(self.mitre_techniques),
            "source_ip": self.source_ip,
            "hostnames": list(self.hostnames),
            "username": self.username,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "unique_users": list(self.unique_users),
            "description": self.description,
            "recommended_actions": list(self.recommended_actions),
            "evidence": list(self.evidence),
        }
