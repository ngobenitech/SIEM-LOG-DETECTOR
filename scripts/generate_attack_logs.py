"""Generate realistic malicious SSH log samples for validation."""

from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "sample_logs" / "attacks"
BASE_TIME = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
HOSTNAME = "prod-web-01"
ATTACKER_IP = "203.0.113.66"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_password() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _random_username() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=6))


def generate_rapid_brute_force() -> list[str]:
    lines: list[str] = []
    for i in range(100):
        dt = BASE_TIME + timedelta(seconds=i * 1.2)
        password = _random_password()
        username = "root"
        lines.append(
            f"{_iso(dt)} {HOSTNAME} sshd[{1000 + i}]: Failed password for {username} "
            f"from {ATTACKER_IP} port {10000 + i} ssh2"
        )
    return lines


def generate_slow_brute_force() -> list[str]:
    lines: list[str] = []
    for i in range(37):
        dt = BASE_TIME + timedelta(minutes=i * 10)
        username = _random_username()
        password = _random_password()
        lines.append(
            f"{_iso(dt)} {HOSTNAME} sshd[{2000 + i}]: Failed password for {username} "
            f"from {ATTACKER_IP} port {20000 + i} ssh2"
        )
    return lines


def generate_password_spraying() -> list[str]:
    lines: list[str] = []
    usernames = ["alice", "bob", "carol", "dave"]
    for i in range(4):
        for username in usernames:
            dt = BASE_TIME + timedelta(seconds=i * 75)
            lines.append(
                f"{_iso(dt)} {HOSTNAME} sshd[{3000 + i}]: Failed password for {username} "
                f"from {ATTACKER_IP} port {30000 + i} ssh2"
            )
    return lines


def generate_success_after_failure() -> list[str]:
    lines: list[str] = []
    password = _random_password()
    for i in range(3):
        dt = BASE_TIME + timedelta(seconds=i * 5)
        lines.append(
            f"{_iso(dt)} {HOSTNAME} sshd[{4000 + i}]: Failed password for analyst "
            f"from {ATTACKER_IP} port {40000 + i} ssh2"
        )
    dt = BASE_TIME + timedelta(seconds=15)
    lines.append(
        f"{_iso(dt)} {HOSTNAME} sshd[4003]: Accepted password for analyst "
        f"from {ATTACKER_IP} port 40003 ssh2"
    )
    return lines


def write_scenario(name: str, lines: list[str]) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"{name}.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> None:
    random.seed(42)
    scenarios = {
        "rapid_brute_force": generate_rapid_brute_force(),
        "slow_brute_force": generate_slow_brute_force(),
        "password_spraying": generate_password_spraying(),
        "success_after_failure": generate_success_after_failure(),
    }

    for name, lines in scenarios.items():
        path = write_scenario(name, lines)
        print(f"Wrote {len(lines)} lines to {path}")


if __name__ == "__main__":
    main()
