"""Benchmark runner for the detection engine."""

from __future__ import annotations

import json
import random
import shutil
import sys
import time
from pathlib import Path

from siem_log_detector.detector import detect
from siem_log_detector.parser import parse_lines


BASE_LOG_LINE = (
    "2026-07-29T09:00:00Z web-01 sshd[1101]: Failed password for {user} "
    "from 198.51.100.{octet} port {port} ssh2\n"
)

USERS = ["root", "admin", "ubuntu", "deploy", "analyst", "guest", "oracle", "postgres"]


def generate_log(path: Path, target_size_mb: int = 10) -> None:
    """Generate a synthetic log file of approximately target_size_mb megabytes.

    Args:
        path: Destination file path.
        target_size_mb: Approximate size in megabytes.
    """
    target_bytes = target_size_mb * 1024 * 1024
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        while written < target_bytes:
            user = random.choice(USERS)
            octet = random.randint(1, 254)
            port = random.randint(1024, 65535)
            line = BASE_LOG_LINE.format(user=user, octet=octet, port=port)
            handle.write(line)
            written += len(line.encode("utf-8"))


def run_benchmark(log_path: Path) -> float:
    """Run the detector against log_path and return elapsed seconds.

    Args:
        log_path: Path to the synthetic log file.

    Returns:
        Elapsed time in seconds.
    """
    start = time.perf_counter()
    with log_path.open("r", encoding="utf-8") as handle:
        result = parse_lines(handle)
    detect(result.events)
    return time.perf_counter() - start


def main() -> int:
    """Generate benchmark data, run the engine, and compare to baseline.

    Returns:
        Exit code 0 on success, 1 if performance regression exceeds threshold.
    """
    repo_root = Path(__file__).resolve().parents[1]
    benchmark_dir = repo_root / "benchmarks"
    log_path = benchmark_dir / "sample-10mb.log"
    baseline_path = benchmark_dir / "baseline.json"

    benchmark_dir.mkdir(exist_ok=True)

    print(f"Generating 10 MB synthetic log at {log_path}...")
    generate_log(log_path, target_size_mb=10)
    log_size_mb = log_path.stat().st_size / (1024 * 1024)
    print(f"Generated {log_size_mb:.2f} MB log file.")

    print("Running benchmark...")
    elapsed = run_benchmark(log_path)
    print(f"Processed in {elapsed:.3f} seconds.")

    if not baseline_path.exists():
        baseline = {"elapsed_seconds": round(elapsed, 3), "log_size_mb": round(log_size_mb, 2)}
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline written to {baseline_path}")
        return 0

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_seconds = float(baseline["elapsed_seconds"])
    regression = (elapsed - baseline_seconds) / baseline_seconds if baseline_seconds else 0.0

    print(f"Baseline: {baseline_seconds:.3f} seconds")
    print(f"Regression: {regression:.1%}")

    threshold = 0.10
    if regression > threshold:
        print(f"ERROR: performance regression exceeds {threshold:.0%} threshold")
        return 1

    print("Performance within acceptable bounds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
