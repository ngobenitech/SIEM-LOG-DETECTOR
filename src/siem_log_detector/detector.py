"""Time-window correlation rules for normalized SSH events."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta

from siem_log_detector.models import Alert, AuthEvent


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Thresholds used by the built-in rules."""

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 5
    spray_user_threshold: int = 4
    spray_window_minutes: int = 10
    success_failure_threshold: int = 3
    success_window_minutes: int = 10

    def __post_init__(self) -> None:
        for field_name, value in (
            ("brute_force_threshold", self.brute_force_threshold),
            ("brute_force_window_minutes", self.brute_force_window_minutes),
            ("spray_user_threshold", self.spray_user_threshold),
            ("spray_window_minutes", self.spray_window_minutes),
            ("success_failure_threshold", self.success_failure_threshold),
            ("success_window_minutes", self.success_window_minutes),
        ):
            if value < 1:
                raise ValueError(f"{field_name} must be at least 1")

    def to_dict(self) -> dict[str, int]:
        """Return configuration values for report metadata."""

        return {
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window_minutes": self.brute_force_window_minutes,
            "spray_user_threshold": self.spray_user_threshold,
            "spray_window_minutes": self.spray_window_minutes,
            "success_failure_threshold": self.success_failure_threshold,
            "success_window_minutes": self.success_window_minutes,
        }


def _peak_window(
    events: Iterable[AuthEvent],
    window: timedelta,
    score: Callable[[tuple[AuthEvent, ...]], tuple[int, int]],
) -> tuple[AuthEvent, ...]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    left = 0
    best: tuple[AuthEvent, ...] = ()
    best_score = (0, 0)

    for right, current in enumerate(ordered):
        while current.timestamp - ordered[left].timestamp > window:
            left += 1
        candidate = tuple(ordered[left : right + 1])
        candidate_score = score(candidate)
        if candidate_score > best_score:
            best = candidate
            best_score = candidate_score

    return best


def _raw_evidence(events: Iterable[AuthEvent], limit: int = 10) -> tuple[str, ...]:
    return tuple(event.raw for event in list(events)[:limit])


def _detect_brute_force(
    failures: Iterable[AuthEvent], config: DetectionConfig
) -> list[Alert]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=config.brute_force_window_minutes)
    for source_ip, source_events in by_ip.items():
        peak = _peak_window(source_events, window, lambda items: (len(items), 0))
        if len(peak) < config.brute_force_threshold:
            continue

        usernames = tuple(sorted({event.username for event in peak}))
        hostnames = tuple(sorted({event.hostname for event in peak}))
        alerts.append(
            Alert(
                rule_id="SSH-BF-001",
                title="Repeated SSH authentication failures",
                severity="high",
                mitre_techniques=("T1110", "T1110.001"),
                source_ip=source_ip,
                hostnames=hostnames,
                username=usernames[0] if len(usernames) == 1 else None,
                first_seen=peak[0].timestamp,
                last_seen=peak[-1].timestamp,
                event_count=len(peak),
                unique_users=usernames,
                description=(
                    f"{len(peak)} failed SSH logins from {source_ip} occurred "
                    f"within {config.brute_force_window_minutes} minutes."
                ),
                recommended_actions=(
                    "Validate whether the source address is expected.",
                    "Review the targeted accounts and adjacent authentication events.",
                    "Block or rate-limit the source if the activity is unauthorized.",
                ),
                evidence=_raw_evidence(peak),
            )
        )
    return alerts


def _detect_password_spray(
    failures: Iterable[AuthEvent], config: DetectionConfig
) -> list[Alert]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=config.spray_window_minutes)
    for source_ip, source_events in by_ip.items():
        peak = _peak_window(
            source_events,
            window,
            lambda items: (len({event.username for event in items}), len(items)),
        )
        usernames = tuple(sorted({event.username for event in peak}))
        if len(usernames) < config.spray_user_threshold:
            continue

        hostnames = tuple(sorted({event.hostname for event in peak}))
        alerts.append(
            Alert(
                rule_id="SSH-PS-002",
                title="Possible SSH password spraying",
                severity="high",
                mitre_techniques=("T1110.003",),
                source_ip=source_ip,
                hostnames=hostnames,
                username=None,
                first_seen=peak[0].timestamp,
                last_seen=peak[-1].timestamp,
                event_count=len(peak),
                unique_users=usernames,
                description=(
                    f"{source_ip} failed authentication against {len(usernames)} "
                    f"distinct accounts within {config.spray_window_minutes} minutes."
                ),
                recommended_actions=(
                    "Confirm whether the source is an approved scanner or jump host.",
                    "Check the targeted accounts for later successful authentication.",
                    "Review MFA, lockout, and source-blocking controls.",
                ),
                evidence=_raw_evidence(peak),
            )
        )
    return alerts


def _detect_success_after_failures(
    events: Iterable[AuthEvent], config: DetectionConfig
) -> list[Alert]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    failures_by_identity: dict[tuple[str, str, str], list[AuthEvent]] = defaultdict(
        list
    )
    emitted: set[tuple[str, str, str]] = set()
    alerts: list[Alert] = []
    window = timedelta(minutes=config.success_window_minutes)

    for event in ordered:
        identity = (event.hostname, event.source_ip, event.username)
        if event.status == "failure":
            failures_by_identity[identity].append(event)
            continue
        if identity in emitted:
            continue

        recent_failures = [
            failure
            for failure in failures_by_identity[identity]
            if timedelta(0) <= event.timestamp - failure.timestamp <= window
        ]
        if len(recent_failures) < config.success_failure_threshold:
            continue

        correlated = (*recent_failures, event)
        alerts.append(
            Alert(
                rule_id="SSH-SAF-003",
                title="Successful SSH login after repeated failures",
                severity="critical",
                mitre_techniques=("T1110", "T1078"),
                source_ip=event.source_ip,
                hostnames=(event.hostname,),
                username=event.username,
                first_seen=recent_failures[0].timestamp,
                last_seen=event.timestamp,
                event_count=len(correlated),
                unique_users=(event.username,),
                description=(
                    f"User {event.username!r} successfully authenticated from "
                    f"{event.source_ip} after {len(recent_failures)} failures "
                    f"within {config.success_window_minutes} minutes. This is a "
                    "correlation signal, not proof of compromise."
                ),
                recommended_actions=(
                    "Contact the account owner and validate the successful login.",
                    "Review the resulting session, commands, and privilege changes.",
                    (
                        "Contain the source and reset credentials if the login "
                        "is unauthorized."
                    ),
                ),
                evidence=_raw_evidence(correlated),
            )
        )
        emitted.add(identity)

    return alerts


def detect(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> tuple[Alert, ...]:
    """Run all built-in detection rules and return severity-sorted alerts."""

    active_config = config or DetectionConfig()
    normalized_events = tuple(events)
    failures = tuple(event for event in normalized_events if event.status == "failure")

    alerts = [
        *_detect_brute_force(failures, active_config),
        *_detect_password_spray(failures, active_config),
        *_detect_success_after_failures(normalized_events, active_config),
    ]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return tuple(
        sorted(
            alerts,
            key=lambda alert: (
                severity_order[alert.severity],
                alert.first_seen,
                alert.rule_id,
            ),
        )
    )
