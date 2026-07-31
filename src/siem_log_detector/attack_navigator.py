"""MITRE ATT&CK Navigator layer generation."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from siem_log_detector.models import Alert

_ATTACK_VERSION = "15"
_NAVIGATOR_VERSION = "5.0.0"
_LAYER_VERSION = "4.4"
_DOMAIN = "enterprise-attack"

_TECHNIQUE_COLORS = {
    "critical": "#ff0000",
    "high": "#ff6600",
    "medium": "#ffcc00",
    "low": "#00ff00",
}

_TECHNIQUE_COMMENTS = {
    "T1110": "Brute force attacks (SSH-BF-001)",
    "T1110.001": "Password guessing (SSH-BF-001)",
    "T1110.003": "Password spraying (SSH-PS-002)",
    "T1078": "Valid accounts after failures (SSH-SAF-003)",
}


def build_navigator_layer(
    alerts: Iterable[Alert],
    name: str = "SIEM Log Detector Coverage",
    description: str = "Coverage of MITRE ATT&CK techniques detected by SSH log correlation rules.",
) -> dict[str, object]:
    """Build a MITRE ATT&CK Navigator layer JSON from alerts.

    Args:
        alerts: Iterable of Alert objects produced by the detector.
        name: Layer name displayed in the Navigator.
        description: Layer description.

    Returns:
        Dictionary compatible with MITRE ATT&CK Navigator layer format.
    """
    normalized = tuple(alerts)
    techniques: dict[str, dict[str, object]] = {}

    for alert in normalized:
        for technique in alert.mitre_techniques:
            if technique not in techniques:
                techniques[technique] = {
                    "techniqueID": technique,
                    "color": _TECHNIQUE_COLORS.get(alert.severity, "#cccccc"),
                    "score": 1,
                    "comment": _TECHNIQUE_COMMENTS.get(technique, alert.title),
                }
            else:
                existing = techniques[technique]
                existing_score = existing.get("score", 1)
                if isinstance(existing_score, int):
                    existing["score"] = existing_score + 1

    return {
        "name": name,
        "versions": {
            "attack": _ATTACK_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer": _LAYER_VERSION,
        },
        "domain": _DOMAIN,
        "description": description,
        "techniques": list(techniques.values()),
    }


def write_navigator_layer(
    alerts: Iterable[Alert],
    path: Path,
    name: str = "SIEM Log Detector Coverage",
    description: str = "Coverage of MITRE ATT&CK techniques detected by SSH log correlation rules.",
) -> None:
    """Generate and write a MITRE Navigator layer to a JSON file.

    Args:
        alerts: Iterable of Alert objects.
        path: Destination file path.
        name: Layer name.
        description: Layer description.
    """
    layer = build_navigator_layer(alerts, name=name, description=description)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(layer, handle, indent=2, sort_keys=False)
        handle.write("\n")
