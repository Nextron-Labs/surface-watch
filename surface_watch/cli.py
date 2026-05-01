from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from surface_watch import __version__
from surface_watch.config import compute_config_hash, load_config, write_example_config
from surface_watch.diff import detect_changes
from surface_watch.discovery import discover_targets
from surface_watch.logging_setup import configure_logging
from surface_watch.notify import (
    send_notifications,
    send_test_notification,
)
from surface_watch.scanner import scan_targets
from surface_watch.storage import (
    create_scan,
    finish_scan,
    get_previous_successful_scan_id,
    initialize_database,
    list_scans,
    load_changes,
    load_scan_snapshot,
    save_changes,
    save_discovered_targets,
    save_scan_results,
)

LOGGER = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.command == "init":
            return _run_init(args)
        if args.command == "discover":
            return _run_discover(args)
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "diff":
            return _run_diff(args)
        if args.command == "list-scans":
            return _run_list_scans(args)
        if args.command == "show-changes":
            return _run_show_changes(args)
        if args.command == "test-notification":
            return _run_test_notification(args)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Command failed: %s", exc)
        return 1

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="surface-watch")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser(
        "init", help="Create example config and initialize the database."
    )
    init_parser.add_argument("--config-path", type=Path, default=Path("config.yaml"))
    init_parser.add_argument("--force", action="store_true")

    discover_parser = subparsers.add_parser("discover", help="Run discovery only.")
    discover_parser.add_argument("--config", type=Path, required=True)
    discover_parser.add_argument(
        "--store", action="store_true", help="Store discovery results as a scan."
    )

    scan_parser = subparsers.add_parser(
        "scan", help="Run discovery, scanning, diffing and notifications."
    )
    scan_parser.add_argument("--config", type=Path, required=True)

    diff_parser = subparsers.add_parser("diff", help="Compare two scans manually.")
    diff_parser.add_argument("--config", type=Path, required=True)
    diff_parser.add_argument("--scan-id", type=int, required=True)
    diff_parser.add_argument("--previous-scan-id", type=int, required=True)

    list_parser = subparsers.add_parser("list-scans", help="List previous scans.")
    list_parser.add_argument("--config", type=Path, required=True)

    show_changes_parser = subparsers.add_parser("show-changes", help="Show changes for a scan.")
    show_changes_parser.add_argument("--config", type=Path, required=True)
    show_changes_parser.add_argument("--scan-id", type=int, required=True)

    test_parser = subparsers.add_parser(
        "test-notification",
        help="Send a test notification to configured webhook providers.",
    )
    test_parser.add_argument("--config", type=Path, required=True)

    return parser


def _run_init(args: argparse.Namespace) -> int:
    config_path = write_example_config(args.config_path, overwrite=args.force)
    config = load_config(config_path)
    initialize_database(config.project.database_path)
    print(f"Wrote example configuration to {config_path}")
    print(f"Initialized database at {config.project.database_path}")
    return 0


def _run_discover(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)

    targets = discover_targets(config)
    for target in targets:
        hostname = target.hostname or "-"
        ip = target.ip or "-"
        record_type = target.record_type or "-"
        print(f"{hostname}\t{ip}\t{target.source}\t{record_type}")

    if args.store:
        initialize_database(config.project.database_path)
        started_at = _utc_now()
        scan_id = create_scan(
            config.project.database_path,
            started_at=started_at,
            status="running",
            config_hash=compute_config_hash(config),
            tool_version=__version__,
        )
        save_discovered_targets(config.project.database_path, scan_id, targets)
        finish_scan(
            config.project.database_path,
            scan_id,
            finished_at=_utc_now(),
            status="discovery_only",
        )
        print(f"Stored discovery-only scan {scan_id}")

    return 0


def _run_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    started_at = _utc_now()
    scan_id = create_scan(
        config.project.database_path,
        started_at=started_at,
        status="running",
        config_hash=compute_config_hash(config),
        tool_version=__version__,
    )

    targets = []
    results = []
    detected_changes = []
    notified_providers: list[str] = []
    final_status = "failed"
    previous_scan_id = None

    try:
        targets = discover_targets(config)
        save_discovered_targets(config.project.database_path, scan_id, targets)

        if not config.scanning.enabled:
            final_status = "discovery_only"
            print(f"Scanning is disabled; stored discovery-only scan {scan_id}")
            return 0

        results = scan_targets(targets, config)
        save_scan_results(config.project.database_path, scan_id, results)

        final_status = _determine_scan_status(results)
        previous_scan_id = get_previous_successful_scan_id(config.project.database_path, scan_id)
        if previous_scan_id is not None:
            current_snapshot = load_scan_snapshot(config.project.database_path, scan_id)
            previous_snapshot = load_scan_snapshot(config.project.database_path, previous_scan_id)
            detected_changes = detect_changes(current_snapshot, previous_snapshot, config)
            save_changes(config.project.database_path, scan_id, detected_changes)

        if detected_changes:
            notified_providers = send_notifications(
                changes=detected_changes,
                scan_id=scan_id,
                timestamp=_utc_now(),
                config=config,
            )
    finally:
        finish_scan(
            config.project.database_path,
            scan_id,
            finished_at=_utc_now(),
            status=final_status,
        )

    print(f"Scan {scan_id} completed with status {final_status}")
    print(f"Discovered targets: {len(targets)}")
    print(f"Host scans: {len(results)}")
    print(f"Detected changes: {len(detected_changes)}")
    if previous_scan_id is None:
        print("No previous successful scan available; current run established the baseline.")
    if notified_providers:
        print(f"Notifications sent via: {', '.join(notified_providers)}")
    return 0 if final_status in {"success", "partial", "discovery_only"} else 1


def _run_diff(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    current_snapshot = load_scan_snapshot(config.project.database_path, args.scan_id)
    previous_snapshot = load_scan_snapshot(config.project.database_path, args.previous_scan_id)
    changes = detect_changes(current_snapshot, previous_snapshot, config)

    for change in changes:
        print(f"[{change.severity}] {change.change_type}: {change.message}")
    print(f"Detected {len(changes)} changes.")
    return 0


def _run_list_scans(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    for item in list_scans(config.project.database_path):
        started_at = item.started_at.isoformat() if item.started_at else "-"
        finished_at = item.finished_at.isoformat() if item.finished_at else "-"
        print(
            f"{item.scan_id}\t{item.status}\t{started_at}\t{finished_at}\t"
            f"{item.tool_version or '-'}"
        )
    return 0


def _run_show_changes(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    changes = load_changes(config.project.database_path, args.scan_id)
    for change in changes:
        print(f"[{change.severity}] {change.change_type}: {change.message}")
    print(f"Stored changes: {len(changes)}")
    return 0


def _run_test_notification(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)

    successful_providers = send_test_notification(config=config)
    if successful_providers:
        print(f"Test notification sent via: {', '.join(successful_providers)}")
        return 0
    print("No test notification was sent.")
    return 1


def _determine_scan_status(results: list) -> str:
    if not results:
        return "success"
    statuses = [result.status for result in results]
    if all(status == "success" for status in statuses):
        return "success"
    if all(status == "failed" for status in statuses):
        return "failed"
    return "partial"


def _utc_now() -> datetime:
    return datetime.now(UTC)


if __name__ == "__main__":
    raise SystemExit(main())
