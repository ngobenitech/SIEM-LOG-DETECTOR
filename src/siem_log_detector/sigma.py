"""Sigma rule interoperability for SIEM log detector rules."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from siem_log_detector.detector import DetectionConfig


@dataclass(frozen=True, slots=True)
class SigmaRule:
    """Minimal representation of a Sigma rule with SIEM detector config.

    Attributes:
        title: Rule title.
        id: Unique rule identifier.
        status: Rule status (stable, experimental, deprecated).
        description: Human-readable description.
        author: Rule author.
        date: ISO date string.
        logsource: Log source mapping.
        detection: Sigma detection logic.
        falsepositives: Known false positive patterns.
        level: Rule severity level.
        siem_config: Internal detection configuration thresholds.
    """

    title: str
    id: str
    status: str = "stable"
    description: str = ""
    author: str = ""
    date: str = ""
    references: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    level: str = "medium"
    siem_config: DetectionConfig | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "references": self.references,
            "logsource": self.logsource,
            "detection": self.detection,
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        if self.siem_config is not None:
            data["siem_config"] = self.siem_config.to_dict()
        return data


def import_sigma(path: Path) -> SigmaRule:
    """Read a Sigma rule YAML file and convert it to our internal format.

    Args:
        path: Path to a Sigma rule YAML file.

    Returns:
        SigmaRule object populated from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML is missing required fields.
    """
    if not path.exists():
        raise FileNotFoundError(path)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid Sigma rule YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")

    title = data.get("title", "")
    rule_id = data.get("id", "")
    if not title or not rule_id:
        raise ValueError("Sigma rule must contain 'title' and 'id' fields")

    siem_config = None
    raw_config = data.get("siem_config")
    if isinstance(raw_config, dict):
        try:
            siem_config = DetectionConfig(
                brute_force_threshold=int(raw_config.get("brute_force_threshold", 5)),
                brute_force_window_minutes=int(raw_config.get("brute_force_window_minutes", 5)),
                spray_user_threshold=int(raw_config.get("spray_user_threshold", 4)),
                spray_window_minutes=int(raw_config.get("spray_window_minutes", 10)),
                success_failure_threshold=int(raw_config.get("success_failure_threshold", 3)),
                success_window_minutes=int(raw_config.get("success_window_minutes", 10)),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid siem_config in Sigma rule: {exc}") from exc

    return SigmaRule(
        title=title,
        id=rule_id,
        status=str(data.get("status", "stable")),
        description=str(data.get("description", "")),
        author=str(data.get("author", "")),
        date=str(data.get("date", "")),
        references=list(data.get("references", []) or []),
        logsource=dict(data.get("logsource", {}) or {}),
        detection=copy.deepcopy(data.get("detection", {}) or {}),
        falsepositives=list(data.get("falsepositives", []) or []),
        level=str(data.get("level", "medium")),
        siem_config=siem_config,
    )


def export_sigma(rule_name: str) -> SigmaRule:
    """Export an internal detection rule as a Sigma YAML-compatible object.

    Args:
        rule_name: Internal rule identifier (e.g., SSH-BF-001).

    Returns:
        SigmaRule object representing the internal rule.

    Raises:
        ValueError: If the rule name is not recognized.
    """
    rule_map = {
        "SSH-BF-001": SigmaRule(
            title="Repeated SSH authentication failures",
            id="SSH-BF-001",
            status="stable",
            description=(
                "Detects multiple failed SSH login attempts from a single source IP "
                "within a short time window, indicating a possible brute force attack."
            ),
            author="siem-log-detector",
            date="2026-07-31",
            references=["https://attack.mitre.org/techniques/T1110/"],
            logsource={"product": "linux", "service": "sshd"},
            detection={
                "selection": {"action": "Failed password"},
                "condition": "selection",
            },
            falsepositives=["Administrators using password-based authentication"],
            level="high",
            siem_config=DetectionConfig(
                brute_force_threshold=5,
                brute_force_window_minutes=5,
                spray_user_threshold=4,
                spray_window_minutes=10,
                success_failure_threshold=3,
                success_window_minutes=10,
            ),
        ),
        "SSH-PS-002": SigmaRule(
            title="Possible SSH password spraying",
            id="SSH-PS-002",
            status="stable",
            description=(
                "Detects failed SSH authentication attempts against multiple distinct "
                "accounts from a single source, indicating password spraying."
            ),
            author="siem-log-detector",
            date="2026-07-31",
            references=["https://attack.mitre.org/techniques/T1110.003/"],
            logsource={"product": "linux", "service": "sshd"},
            detection={
                "selection": {"action": "Failed password"},
                "condition": "selection",
            },
            falsepositives=["Automated configuration management tools"],
            level="high",
            siem_config=DetectionConfig(
                brute_force_threshold=5,
                brute_force_window_minutes=5,
                spray_user_threshold=4,
                spray_window_minutes=10,
                success_failure_threshold=3,
                success_window_minutes=10,
            ),
        ),
        "SSH-SAF-003": SigmaRule(
            title="Successful SSH login after repeated failures",
            id="SSH-SAF-003",
            status="stable",
            description=(
                "Detects a successful SSH login that follows multiple failures from the "
                "same source, host, and username within a short window."
            ),
            author="siem-log-detector",
            date="2026-07-31",
            references=[
                "https://attack.mitre.org/techniques/T1110/",
                "https://attack.mitre.org/techniques/T1078/",
            ],
            logsource={"product": "linux", "service": "sshd"},
            detection={
                "selection": {"action": "Accepted password"},
                "condition": "selection",
            },
            falsepositives=["Users correcting mistyped passwords"],
            level="critical",
            siem_config=DetectionConfig(
                brute_force_threshold=5,
                brute_force_window_minutes=5,
                spray_user_threshold=4,
                spray_window_minutes=10,
                success_failure_threshold=3,
                success_window_minutes=10,
            ),
        ),
    }

    if rule_name not in rule_map:
        raise ValueError(
            f"Unknown rule '{rule_name}'. Known rules: {', '.join(sorted(rule_map))}"
        )

    return rule_map[rule_name]


def write_sigma(rule: SigmaRule, path: Path) -> None:
    """Write a SigmaRule object to a YAML file.

    Args:
        rule: SigmaRule to serialize.
        path: Destination file path.
    """
    data = rule.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)
