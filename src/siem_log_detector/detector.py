"""Streaming, deque-backed correlation rules for normalized SSH events.

This module preserves the public API used by the unit tests while
replacing memory-heavy sorting with incremental, time-windowed state.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, Deque, List, Set, Tuple

from siem_log_detector.models import Alert, AuthEvent


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Thresholds and timing used by the built-in rules.

    These defaults preserve historical behaviour; more advanced
    baselining and tuning can be enabled later without changing the
    public configuration object shape.

    Attributes:
        brute_force_threshold: Failures from one source required for SSH-BF-001.
        brute_force_window_minutes: Correlation window for SSH-BF-001.
        spray_user_threshold: Distinct accounts required for SSH-PS-002.
        spray_window_minutes: Correlation window for SSH-PS-002.
        success_failure_threshold: Failures before success for SSH-SAF-003.
        success_window_minutes: Lookback window for SSH-SAF-003.
    """

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 5
    spray_user_threshold: int = 4
    spray_window_minutes: int = 10
    success_failure_threshold: int = 3
    success_window_minutes: int = 10

    def __post_init__(self) -> None:
        """Validate that all thresholds and windows are positive integers."""
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
        """Return configuration as a dictionary.

        Returns:
            Dictionary mapping configuration field names to integer values.
        """
        return {
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window_minutes": self.brute_force_window_minutes,
            "spray_user_threshold": self.spray_user_threshold,
            "spray_window_minutes": self.spray_window_minutes,
            "success_failure_threshold": self.success_failure_threshold,
            "success_window_minutes": self.success_window_minutes,
        }


def _raw_evidence(events: Iterable[AuthEvent], limit: int = 10) -> Tuple[str, ...]:
    """Extract raw log lines from events for alert evidence.

    Args:
        events: Iterable of authentication events.
        limit: Maximum number of evidence lines to include.

    Returns:
        Tuple of raw log line strings.
    """
    return tuple(event.raw for event in list(events)[:limit])


def detect(events: Iterable[AuthEvent], config: DetectionConfig | None = None) -> tuple[Alert, ...]:
    """Process events in a streaming fashion and return collected alerts.

    The behaviour is functionally equivalent to the original batch
    implementation used by the tests, but uses deques to bound memory
    for long-running processing.

    Args:
        events: Iterable of normalized authentication events.
        config: Detection thresholds and windows. Uses defaults if None.

    Returns:
        Tuple of Alert objects, sorted by severity and timestamp.
    """
    cfg = config or DetectionConfig()
    window_bf = timedelta(minutes=cfg.brute_force_window_minutes)
    window_ps = timedelta(minutes=cfg.spray_window_minutes)
    window_saf = timedelta(minutes=cfg.success_window_minutes)

    # Per-source-IP state for failures (used by brute force & spray rules)
    failures_by_ip: Dict[str, Deque[AuthEvent]] = {}
    usernames_by_ip: Dict[str, Set[str]] = {}
    last_alert_end_by_ip: Dict[Tuple[str, str], AuthEvent] = {}

    # Per-identity failures for success-after-failures
    failures_by_identity: Dict[Tuple[str, str, str], Deque[AuthEvent]] = {}
    emitted_identities: Set[Tuple[str, str, str]] = set()

    alerts: List[Alert] = []

    for event in events:
        # Maintain per-IP failure windows
        if event.status == "failure":
            dq = failures_by_ip.setdefault(event.source_ip, deque())
            dq.append(event)
            # prune old
            cutoff = event.timestamp - window_bf
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()

            # password-spray tracking (usernames within spray window)
            dq_ps = failures_by_ip.setdefault((event.source_ip + "_ps"), deque())
            dq_ps.append(event)
            cutoff_ps = event.timestamp - window_ps
            while dq_ps and dq_ps[0].timestamp < cutoff_ps:
                dq_ps.popleft()
            usernames = usernames_by_ip.setdefault(event.source_ip, set())
            # rebuild usernames set from current spray window
            usernames.clear()
            for e in dq_ps:
                usernames.add(e.username)

            # brute-force alert
            if len(dq) >= cfg.brute_force_threshold:
                # avoid repeated alerts for the exact same most-recent window
                key = ("bf", event.source_ip)
                last = last_alert_end_by_ip.get(key)
                last_end = last.timestamp if last is not None else None
                if last is None or event.timestamp > last_end:
                    peak_events = tuple(dq)
                    usernames_peak = tuple(sorted({e.username for e in peak_events}))
                    hostnames = tuple(sorted({e.hostname for e in peak_events}))
                    alerts.append(
                        Alert(
                            rule_id="SSH-BF-001",
                            title="Repeated SSH authentication failures",
                            severity="high",
                            mitre_techniques=("T1110", "T1110.001"),
                            source_ip=event.source_ip,
                            hostnames=hostnames,
                            username=usernames_peak[0] if len(usernames_peak) == 1 else None,
                            first_seen=peak_events[0].timestamp,
                            last_seen=peak_events[-1].timestamp,
                            event_count=len(peak_events),
                            unique_users=usernames_peak,
                            description=(
                                f"{len(peak_events)} failed SSH logins from {event.source_ip} occurred "
                                f"within {cfg.brute_force_window_minutes} minutes."
                            ),
                            recommended_actions=(
                                "Validate whether the source address is expected.",
                                "Review the targeted accounts and adjacent authentication events.",
                                "Block or rate-limit the source if the activity is unauthorized.",
                            ),
                            evidence=_raw_evidence(peak_events),
                        )
                    )
                    last_alert_end_by_ip[key] = peak_events[-1]

            # password-spray alert
            if len(usernames) >= cfg.spray_user_threshold:
                key = ("ps", event.source_ip)
                last = last_alert_end_by_ip.get(key)
                last_end = last.timestamp if last is not None else None
                # choose events covering the spray window
                peak_events = tuple(dq_ps)
                if last is None or peak_events and peak_events[-1].timestamp > last_end:
                    hostnames = tuple(sorted({e.hostname for e in peak_events}))
                    alerts.append(
                        Alert(
                            rule_id="SSH-PS-002",
                            title="Possible SSH password spraying",
                            severity="high",
                            mitre_techniques=("T1110.003",),
                            source_ip=event.source_ip,
                            hostnames=hostnames,
                            username=None,
                            first_seen=peak_events[0].timestamp,
                            last_seen=peak_events[-1].timestamp,
                            event_count=len(peak_events),
                            unique_users=tuple(sorted(usernames)),
                            description=(
                                f"{event.source_ip} failed authentication against {len(usernames)} "
                                f"distinct accounts within {cfg.spray_window_minutes} minutes."
                            ),
                            recommended_actions=(
                                "Confirm whether the source is an approved scanner or jump host.",
                                "Check the targeted accounts for later successful authentication.",
                                "Review MFA, lockout, and source-blocking controls.",
                            ),
                            evidence=_raw_evidence(peak_events),
                        )
                    )
                    last_alert_end_by_ip[key] = peak_events[-1]

            # record failure for success-after-failures tracking
            identity = (event.hostname, event.source_ip, event.username)
            idq = failures_by_identity.setdefault(identity, deque())
            idq.append(event)
            cutoff_id = event.timestamp - window_saf
            while idq and idq[0].timestamp < cutoff_id:
                idq.popleft()

        else:  # success event
            identity = (event.hostname, event.source_ip, event.username)
            idq = failures_by_identity.get(identity)
            if idq and identity not in emitted_identities:
                # consider only failures within the SAF window relative to success
                recent = [f for f in idq if timedelta(0) <= event.timestamp - f.timestamp <= window_saf]
                if len(recent) >= cfg.success_failure_threshold:
                    correlated = (*recent, event)
                    alerts.append(
                        Alert(
                            rule_id="SSH-SAF-003",
                            title="Successful SSH login after repeated failures",
                            severity="critical",
                            mitre_techniques=("T1110", "T1078"),
                            source_ip=event.source_ip,
                            hostnames=(event.hostname,),
                            username=event.username,
                            first_seen=recent[0].timestamp,
                            last_seen=event.timestamp,
                            event_count=len(correlated),
                            unique_users=(event.username,),
                            description=(
                                f"User {event.username!r} successfully authenticated from "
                                f"{event.source_ip} after {len(recent)} failures "
                                f"within {cfg.success_window_minutes} minutes. This is a "
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
                    emitted_identities.add(identity)

    # final sort to provide deterministic ordering for callers/tests
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts_sorted = sorted(alerts, key=lambda a: (severity_order[a.severity], a.first_seen, a.rule_id))
    return tuple(alerts_sorted)
