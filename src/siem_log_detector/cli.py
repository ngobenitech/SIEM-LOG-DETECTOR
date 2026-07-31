"""Command-line interface for the detector."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from siem_log_detector import __version__
from siem_log_detector.detector import DetectionConfig, detect
from siem_log_detector.enrichment import enrich_alerts
from siem_log_detector.models import AuthEvent
from siem_log_detector.parser import ParseResult, parse_log
from siem_log_detector.reporting import (
    build_report,
    format_csv,
    format_events_csv,
    format_events_json,
    format_json,
    format_splunk,
    format_table,
    write_output,
)
from siem_log_detector.attack_navigator import build_navigator_layer, write_navigator_layer
from siem_log_detector.sigma import export_sigma, import_sigma, write_sigma


class JsonFormatter(logging.Formatter):
    """Format log records as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, object] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class DynamicStreamHandler(logging.Handler):
    """Logging handler that always writes to the current sys.stdout."""

    terminator = "\n"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            stream = sys.stdout
            stream.write(msg + self.terminator)
            stream.flush()
        except Exception:
            self.handleError(record)


def setup_logging(level_name: str) -> logging.Logger:
    """Configure the siem_log_detector logger.

    Args:
        level_name: Logging level name (DEBUG, INFO, or WARN).

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("siem_log_detector")
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    if not logger.handlers:
        handler = DynamicStreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        logger.addHandler(handler)

    if level_name == "DEBUG":
        for handler in logger.handlers:
            handler.setFormatter(JsonFormatter())

    return logger


def load_config_from_yaml(path: Path) -> DetectionConfig:
    """Load detection thresholds from a YAML configuration file.

    Args:
        path: Path to a YAML file containing threshold values.

    Returns:
        DetectionConfig populated from the YAML file.

    Raises:
        ValueError: If the YAML contains invalid or missing values.
        FileNotFoundError: If the configuration file does not exist.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for --config. Install it with: pip install pyyaml"
        ) from exc

    with path.open("r", encoding="utf-8") as handle:
        try:
            data = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML configuration: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("configuration file must contain a YAML mapping")

    return DetectionConfig(
        brute_force_threshold=int(data.get("brute_force_threshold", 5)),
        brute_force_window_minutes=int(data.get("brute_force_window_minutes", 5)),
        spray_user_threshold=int(data.get("spray_user_threshold", 4)),
        spray_window_minutes=int(data.get("spray_window_minutes", 10)),
        success_failure_threshold=int(data.get("success_failure_threshold", 3)),
        success_window_minutes=int(data.get("success_window_minutes", 10)),
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI parser with subcommands.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="siem-detect",
        description=(
            "Parse OpenSSH authentication logs and correlate suspicious login patterns."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN"],
        default="INFO",
        help="logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="available commands")

    detect_parser = subparsers.add_parser("detect", help="Run detection on a log file")
    detect_parser.add_argument("log_file", type=Path, help="path to a Linux auth log")
    detect_parser.add_argument(
        "--config",
        type=Path,
        help="path to YAML rule configuration file",
    )
    detect_parser.add_argument(
        "--output-format",
        choices=["json", "csv", "table", "splunk"],
        default="table",
        help="output format (default: table)",
    )
    detect_parser.add_argument("--output", type=Path, help="also write output to this file")
    detect_parser.add_argument(
        "--year",
        type=int,
        help="year to assign to traditional syslog timestamps without a year",
    )
    detect_parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="failed logins from one IP required for SSH-BF-001 (default: 5)",
    )
    detect_parser.add_argument(
        "--brute-force-window",
        type=int,
        default=5,
        metavar="MINUTES",
        help="SSH-BF-001 correlation window (default: 5)",
    )
    detect_parser.add_argument(
        "--spray-user-threshold",
        type=int,
        default=4,
        help="distinct accounts required for SSH-PS-002 (default: 4)",
    )
    detect_parser.add_argument(
        "--spray-window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="SSH-PS-002 correlation window (default: 10)",
    )
    detect_parser.add_argument(
        "--success-failure-threshold",
        type=int,
        default=3,
        help="failures required before success for SSH-SAF-003 (default: 3)",
    )
    detect_parser.add_argument(
        "--success-window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="SSH-SAF-003 lookback window (default: 10)",
    )
    detect_parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="return exit code 1 when one or more alerts are detected",
    )
    detect_parser.add_argument(
        "--enrich",
        action="store_true",
        help="enrich alerts with AbuseIPDB threat intelligence",
    )

    validate_parser = subparsers.add_parser(
        "validate", help="Validate a YAML configuration file"
    )
    validate_parser.add_argument(
        "config_file",
        type=Path,
        help="path to YAML rule configuration file",
    )

    export_parser = subparsers.add_parser(
        "export", help="Convert logs to JSON or CSV without detection"
    )
    export_parser.add_argument("log_file", type=Path, help="path to a Linux auth log")
    export_parser.add_argument(
        "--output-format",
        choices=["json", "csv"],
        default="json",
        help="output format (default: json)",
    )
    export_parser.add_argument("--output", type=Path, help="write output to this file")
    export_parser.add_argument(
        "--year",
        type=int,
        help="year to assign to traditional syslog timestamps without a year",
    )

    sigma_parser = subparsers.add_parser("sigma", help="Sigma rule interoperability")
    sigma_subparsers = sigma_parser.add_subparsers(dest="sigma_command", help="Sigma commands")

    sigma_import_parser = sigma_subparsers.add_parser(
        "import", help="Import a Sigma rule YAML file"
    )
    sigma_import_parser.add_argument(
        "file", type=Path, help="path to a Sigma rule YAML file"
    )

    sigma_export_parser = sigma_subparsers.add_parser(
        "export", help="Export an internal rule as Sigma YAML"
    )
    sigma_export_parser.add_argument(
        "rule_name",
        help="internal rule identifier (e.g., SSH-BF-001, SSH-PS-002, SSH-SAF-003)",
    )
    sigma_export_parser.add_argument(
        "--output", type=Path, help="write exported rule to this file"
    )

    attack_parser = subparsers.add_parser(
        "attack", help="MITRE ATT&CK integration commands"
    )
    attack_subparsers = attack_parser.add_subparsers(dest="attack_command", help="Attack commands")

    coverage_parser = attack_subparsers.add_parser(
        "coverage", help="Generate MITRE ATT&CK Navigator heatmap JSON"
    )
    coverage_parser.add_argument("log_file", type=Path, help="path to a Linux auth log")
    coverage_parser.add_argument(
        "--output", type=Path, help="write Navigator layer to this file"
    )
    coverage_parser.add_argument(
        "--year",
        type=int,
        help="year to assign to traditional syslog timestamps without a year",
    )

    return parser


def _run_detect(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the detect subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0, 1, or 2).
    """
    try:
        config = DetectionConfig(
            brute_force_threshold=args.brute_force_threshold,
            brute_force_window_minutes=args.brute_force_window,
            spray_user_threshold=args.spray_user_threshold,
            spray_window_minutes=args.spray_window,
            success_failure_threshold=args.success_failure_threshold,
            success_window_minutes=args.success_window,
        )
    except ValueError as exc:
        logger.error("configuration error: %s", exc)
        return 1

    if args.config:
        try:
            config = load_config_from_yaml(args.config)
        except FileNotFoundError:
            logger.error("configuration file not found: %s", args.config)
            return 1
        except (ValueError, ImportError) as exc:
            logger.error("configuration error: %s", exc)
            return 1

    try:
        result: ParseResult = parse_log(args.log_file, assumed_year=args.year)
    except OSError as exc:
        logger.error("unable to read %s: %s", args.log_file, exc)
        return 2

    logger.info(
        "parsed %d events from %d lines (%d skipped)",
        len(result.events),
        result.total_lines,
        result.skipped_lines,
    )

    try:
        alerts = detect(result.events, config)
    except Exception as exc:
        logger.error("detection failed: %s", exc)
        return 2

    if getattr(args, "enrich", False):
        api_key = ""
        try:
            api_key = _load_abuseipdb_key()
        except Exception as exc:
            logger.warning("enrichment skipped: %s", exc)
        if api_key:
            alerts = enrich_alerts(alerts, api_key)

    logger.info("detected %d alerts", len(alerts))

    report = build_report(args.log_file, result, alerts, config)

    output_format = args.output_format
    if output_format == "json":
        content = format_json(report)
    elif output_format == "csv":
        content = format_csv(alerts)
    elif output_format == "splunk":
        content = format_splunk(alerts)
    else:
        summary = report["summary"]
        content = (
            f"Input: {args.log_file}\n"
            f"Parsed: {summary['parsed_events']} events from "
            f"{summary['total_lines']} lines "
            f"({summary['skipped_lines']} skipped)\n"
            f"Alerts: {summary['alerts']}\n\n"
            f"{format_table(alerts)}\n"
        )

    if args.output:
        try:
            write_output(args.output, content)
        except OSError as exc:
            logger.error("unable to write %s: %s", args.output, exc)
            return 2
        logger.info("Wrote %s report to %s", output_format.upper(), args.output)
    else:
        logger.info("%s", content.rstrip())

    if args.fail_on_alert and alerts:
        return 1

    return 0


def _load_abuseipdb_key() -> str:
    """Load the AbuseIPDB API key from environment or config.

    Returns:
        API key string, or empty string if not configured.

    Raises:
        ValueError: If the key path does not exist.
    """
    import os

    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if key:
        return key.strip()

    config_path = Path(".abuseipdb_key")
    if config_path.exists():
        return config_path.read_text(encoding="utf-8").strip()

    return ""


def _run_validate(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the validate subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0 for valid, 1 for invalid).
    """
    try:
        config = load_config_from_yaml(args.config_file)
    except FileNotFoundError:
        logger.error("configuration file not found: %s", args.config_file)
        return 1
    except (ValueError, ImportError) as exc:
        logger.error("configuration error: %s", exc)
        return 1

    logger.info("configuration is valid: %s", config.to_dict())
    return 0


def _run_export(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the export subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0 for success, 2 for parse error).
    """
    try:
        result: ParseResult = parse_log(args.log_file, assumed_year=args.year)
    except OSError as exc:
        logger.error("unable to read %s: %s", args.log_file, exc)
        return 2

    logger.info(
        "parsed %d events from %d lines (%d skipped)",
        len(result.events),
        result.total_lines,
        result.skipped_lines,
    )

    output_format = args.output_format
    if output_format == "json":
        content = format_events_json(result.events)
    else:
        content = format_events_csv(result.events)

    if args.output:
        try:
            write_output(args.output, content)
        except OSError as exc:
            logger.error("unable to write %s: %s", args.output, exc)
            return 2
        logger.info("wrote %s export to %s", output_format.upper(), args.output)
    else:
        logger.info("%s", content.rstrip())

    return 0


def _run_sigma_import(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the sigma import subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0 for success, 1 for error).
    """
    try:
        rule = import_sigma(args.file)
    except FileNotFoundError:
        logger.error("file not found: %s", args.file)
        return 1
    except ValueError as exc:
        logger.error("invalid Sigma rule: %s", exc)
        return 1

    logger.info("imported rule %s: %s", rule.id, rule.title)
    if rule.siem_config:
        logger.info("detection config: %s", rule.siem_config.to_dict())
    return 0


def _run_sigma_export(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the sigma export subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0 for success, 1 for error).
    """
    try:
        rule = export_sigma(args.rule_name)
    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    try:
        import yaml
    except ImportError as exc:
        logger.error("PyYAML is required for sigma export. Install it with: pip install pyyaml")
        return 1

    yaml_text = yaml.safe_dump(rule.to_dict(), default_flow_style=False, sort_keys=False)
    if args.output:
        try:
            write_output(args.output, yaml_text)
        except OSError as exc:
            logger.error("unable to write %s: %s", args.output, exc)
            return 2
        logger.info("wrote Sigma rule to %s", args.output)
    else:
        logger.info("%s", yaml_text.rstrip())
    return 0


def _run_attack_coverage(
    args: argparse.Namespace,
    logger: logging.Logger,
) -> int:
    """Execute the attack coverage subcommand.

    Args:
        args: Parsed command-line arguments.
        logger: Configured logger instance.

    Returns:
        Process exit code (0 for success, 2 for parse error).
    """
    try:
        result: ParseResult = parse_log(args.log_file, assumed_year=getattr(args, "year", None))
    except OSError as exc:
        logger.error("unable to read %s: %s", args.log_file, exc)
        return 2

    config = DetectionConfig()
    alerts = detect(result.events, config)
    logger.info("detected %d alerts for MITRE coverage", len(alerts))

    if args.output:
        try:
            write_navigator_layer(alerts, args.output)
        except OSError as exc:
            logger.error("unable to write %s: %s", args.output, exc)
            return 2
        logger.info("wrote MITRE Navigator layer to %s", args.output)
    else:
        layer = build_navigator_layer(alerts)
        logger.info("%s", json.dumps(layer, indent=2, sort_keys=False))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code.

    Args:
        argv: Optional command-line argument sequence. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 for success, 1 for configuration error, 2 for I/O error.
    """
    parser = build_argument_parser()

    if argv is None:
        argv = sys.argv[1:]

    argv_list = list(argv)

    if (
        len(argv_list) == 0
        or (
            len(argv_list) > 0
            and not argv_list[0].startswith("-")
            and argv_list[0] not in ("detect", "validate", "export", "sigma", "attack")
        )
    ):
        argv_list = ["detect"] + argv_list

    args = parser.parse_args(argv_list)
    logger = setup_logging(args.log_level)

    command = args.command if args.command else "detect"

    if command == "detect":
        return _run_detect(args, logger)
    if command == "validate":
        return _run_validate(args, logger)
    if command == "export":
        return _run_export(args, logger)
    if command == "sigma":
        sigma_command = getattr(args, "sigma_command", None)
        if sigma_command == "import":
            return _run_sigma_import(args, logger)
        if sigma_command == "export":
            return _run_sigma_export(args, logger)
        logger.error("unknown sigma command: %s", sigma_command)
        return 1
    if command == "attack":
        attack_command = getattr(args, "attack_command", None)
        if attack_command == "coverage":
            return _run_attack_coverage(args, logger)
        logger.error("unknown attack command: %s", attack_command)
        return 1

    logger.error("unknown command: %s", command)
    return 1
