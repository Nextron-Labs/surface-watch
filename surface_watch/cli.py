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
from surface_watch.models import (
    DiscoveredTarget,
    HostScanRecord,
    PortFinding,
    ScanSnapshot,
    is_ip_address,
    normalize_hostname,
)
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
DEFAULT_CONFIG_PATH = Path("config.yaml")
COMMANDS_REQUIRING_CONFIG = {
    "discover",
    "scan",
    "diff",
    "list-scans",
    "show-changes",
    "show-targets",
    "show-ports",
    "show-scan",
    "test-notification",
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "init" and getattr(args, "global_config", None) is not None:
        parser.error("init does not use --config; use --config-path to choose the output path")

    if args.command in COMMANDS_REQUIRING_CONFIG:
        args.config = _resolve_config_path(args, parser)
        if not args.config.is_file():
            parser.error(f"Config file not found: {args.config}")

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
        if args.command == "show-targets":
            return _run_show_targets(args)
        if args.command == "show-ports":
            return _run_show_ports(args)
        if args.command == "show-scan":
            return _run_show_scan(args)
        if args.command == "test-notification":
            return _run_test_notification(args)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Command failed: %s", exc)
        return 1

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="surface-watch")
    parser.add_argument(
        "--config",
        dest="global_config",
        type=Path,
        help=(
            "Path to config file for commands that operate on an existing project. "
            "Can be placed before or after the subcommand. Defaults to ./config.yaml "
            "when present."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    config_parent = argparse.ArgumentParser(add_help=False)
    config_parent.add_argument(
        "--config",
        dest="command_config",
        type=Path,
        help="Path to config file. Defaults to ./config.yaml when present.",
    )

    init_parser = subparsers.add_parser(
        "init", help="Create example config and initialize the database."
    )
    init_parser.add_argument("--config-path", type=Path, default=Path("config.yaml"))
    init_parser.add_argument("--force", action="store_true")

    discover_parser = subparsers.add_parser(
        "discover",
        help="Run discovery only.",
        parents=[config_parent],
    )
    discover_parser.add_argument(
        "--store", action="store_true", help="Store discovery results as a scan."
    )

    subparsers.add_parser(
        "scan",
        help="Run discovery, scanning, diffing and notifications.",
        parents=[config_parent],
    )

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two scans manually.",
        parents=[config_parent],
    )
    diff_parser.add_argument("--scan-id", type=int, required=True)
    diff_parser.add_argument("--previous-scan-id", type=int, required=True)

    subparsers.add_parser(
        "list-scans",
        help="List previous scans.",
        parents=[config_parent],
    )

    show_changes_parser = subparsers.add_parser(
        "show-changes",
        help="Show changes for a scan.",
        parents=[config_parent],
    )
    show_changes_parser.add_argument("--scan-id", type=int, required=True)

    show_targets_parser = subparsers.add_parser(
        "show-targets",
        help="List stored discovered targets for a scan.",
        parents=[config_parent],
    )
    show_targets_parser.add_argument("--scan-id", type=int, required=True)

    show_ports_parser = subparsers.add_parser(
        "show-ports",
        help="List stored port findings for a hostname or IP in a scan.",
        parents=[config_parent],
    )
    show_ports_parser.add_argument("--scan-id", type=int, required=True)
    show_ports_parser.add_argument(
        "--host",
        required=True,
        help="Hostname or IP address to inspect.",
    )

    show_scan_parser = subparsers.add_parser(
        "show-scan",
        help="Pretty-print stored hosts and ports for a scan.",
        parents=[config_parent],
    )
    show_scan_parser.add_argument("--scan-id", type=int, required=True)

    subparsers.add_parser(
        "test-notification",
        help="Send a test notification to configured webhook providers.",
        parents=[config_parent],
    )

    return parser


def _resolve_config_path(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> Path:
    if getattr(args, "command_config", None) is not None:
        return args.command_config
    if getattr(args, "global_config", None) is not None:
        return args.global_config
    if DEFAULT_CONFIG_PATH.is_file():
        return DEFAULT_CONFIG_PATH
    parser.error(
        f"{args.command} requires --config or a {DEFAULT_CONFIG_PATH} file in the current "
        "directory"
    )


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


def _run_show_targets(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    snapshot = load_scan_snapshot(config.project.database_path, args.scan_id)
    if not snapshot.targets:
        print(f"Scan {args.scan_id} has no stored discovered targets.")
        return 0

    rows = [
        (
            target.hostname or "-",
            target.ip or "-",
            target.source,
            target.parent_domain or "-",
            target.record_type or "-",
        )
        for target in _sorted_targets(snapshot.targets)
    ]
    _print_table(
        headers=("HOSTNAME", "IP", "SOURCE", "PARENT_DOMAIN", "RECORD_TYPE"),
        rows=rows,
    )
    print(f"Stored discovered targets: {len(snapshot.targets)}")
    return 0


def _run_show_ports(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    snapshot = load_scan_snapshot(config.project.database_path, args.scan_id)
    rows = _build_port_rows(snapshot, args.host)
    if rows is None:
        print(f"No stored host matched '{args.host}' in scan {args.scan_id}.")
        return 1
    if not rows:
        print(f"Scan {args.scan_id} has no stored port findings for {args.host}.")
        return 0

    _print_table(
        headers=("HOSTNAME", "IP", "PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"),
        rows=rows,
    )
    print(f"Stored port findings: {len(rows)}")
    return 0


def _run_show_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    configure_logging(config.project.log_level)
    initialize_database(config.project.database_path)

    snapshot = load_scan_snapshot(config.project.database_path, args.scan_id)
    print(f"Scan {snapshot.scan_id}")
    print(f"Status: {snapshot.status}")
    print(f"Started: {_format_datetime(snapshot.started_at)}")
    print(f"Finished: {_format_datetime(snapshot.finished_at)}")
    print(f"Discovered targets: {len(snapshot.targets)}")
    print(f"Host scan records: {len(snapshot.host_results)}")
    print(f"Open ports: {len(snapshot.port_findings)}")

    print()
    print("Discovered Targets")
    if snapshot.targets:
        _print_table(
            headers=("HOSTNAME", "IP", "SOURCE", "PARENT_DOMAIN", "RECORD_TYPE"),
            rows=[
                (
                    target.hostname or "-",
                    target.ip or "-",
                    target.source,
                    target.parent_domain or "-",
                    target.record_type or "-",
                )
                for target in _sorted_targets(snapshot.targets)
            ],
        )
    else:
        print("No stored discovered targets.")

    print()
    print("Hosts")
    if not snapshot.host_results:
        print("No stored host scan results.")
        return 0

    for host_record in _sorted_host_records(snapshot.host_results):
        print(f"{host_record.hostname or host_record.ip} ({host_record.ip})")
        print(f"  Status: {host_record.status}")

        sources, parent_domains, record_types = _collect_target_metadata(
            snapshot.targets,
            hostname=host_record.hostname,
            ip=host_record.ip,
        )
        if sources:
            print(f"  Sources: {', '.join(sources)}")
        if parent_domains:
            print(f"  Parent domains: {', '.join(parent_domains)}")
        if record_types:
            print(f"  Record types: {', '.join(record_types)}")
        if host_record.error:
            print(f"  Error: {host_record.error}")

        host_ports = _findings_for_ip(snapshot.port_findings, host_record.ip)
        if host_ports:
            print("  Ports:")
            for line in _format_table(
                headers=("PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"),
                rows=[
                    (
                        _format_port_identifier(finding),
                        finding.state,
                        finding.service_name or "-",
                        finding.product or "-",
                        finding.version or "-",
                    )
                    for finding in host_ports
                ],
                indent="    ",
            ):
                print(line)
        else:
            print("  Ports: none")
        print()

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


def _sorted_targets(targets: list[DiscoveredTarget]) -> list[DiscoveredTarget]:
    return sorted(
        targets,
        key=lambda target: (target.hostname or "", target.ip or "", target.source),
    )


def _sorted_host_records(host_records: list[HostScanRecord]) -> list[HostScanRecord]:
    return sorted(host_records, key=lambda record: (record.hostname or "", record.ip))


def _findings_for_ip(port_findings: list[PortFinding], ip: str) -> list[PortFinding]:
    return sorted(
        [finding for finding in port_findings if finding.ip == ip],
        key=lambda finding: (finding.protocol, finding.port),
    )


def _build_port_rows(
    snapshot: ScanSnapshot,
    requested_host: str,
) -> list[tuple[str, str, str, str, str, str, str]] | None:
    requested = requested_host.strip()
    if is_ip_address(requested):
        if not any(target.ip == requested for target in snapshot.targets) and not any(
            host_record.ip == requested for host_record in snapshot.host_results
        ):
            return None
        display_hostname = ", ".join(_hostnames_for_ip(snapshot, requested)) or "-"
        return [
            (
                display_hostname,
                finding.ip,
                _format_port_identifier(finding),
                finding.state,
                finding.service_name or "-",
                finding.product or "-",
                finding.version or "-",
            )
            for finding in _findings_for_ip(snapshot.port_findings, requested)
        ]

    normalized_hostname = normalize_hostname(requested)
    if normalized_hostname is None:
        return None

    matching_ips = sorted(
        {
            target.ip
            for target in snapshot.targets
            if target.hostname == normalized_hostname and target.ip is not None
        }
        | {
            host_record.ip
            for host_record in snapshot.host_results
            if host_record.hostname == normalized_hostname
        }
    )
    if not matching_ips:
        return None

    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for ip in matching_ips:
        for finding in _findings_for_ip(snapshot.port_findings, ip):
            rows.append(
                (
                    normalized_hostname,
                    finding.ip,
                    _format_port_identifier(finding),
                    finding.state,
                    finding.service_name or "-",
                    finding.product or "-",
                    finding.version or "-",
                )
            )
    return rows


def _hostnames_for_ip(snapshot: ScanSnapshot, ip: str) -> tuple[str, ...]:
    hostnames = {
        target.hostname
        for target in snapshot.targets
        if target.ip == ip and target.hostname is not None
    } | {
        host_record.hostname
        for host_record in snapshot.host_results
        if host_record.ip == ip and host_record.hostname is not None
    }
    return tuple(sorted(hostnames))


def _collect_target_metadata(
    targets: list[DiscoveredTarget],
    *,
    hostname: str | None,
    ip: str,
) -> tuple[list[str], list[str], list[str]]:
    sources: set[str] = set()
    parent_domains: set[str] = set()
    record_types: set[str] = set()

    for target in targets:
        if target.hostname != hostname or target.ip != ip:
            continue
        sources.update(target.sources)
        parent_domains.update(target.parent_domains)
        if target.record_type:
            record_types.add(target.record_type)

    return sorted(sources), sorted(parent_domains), sorted(record_types)


def _format_port_identifier(finding: PortFinding) -> str:
    return f"{finding.protocol}/{finding.port}"


def _format_table(
    *,
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    indent: str = "",
) -> list[str]:
    normalized_rows = [[str(value) for value in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in normalized_rows))
        for index, header in enumerate(headers)
    ]
    lines = [
        indent + "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        indent + "  ".join("-" * width for width in widths),
    ]
    for row in normalized_rows:
        lines.append(
            indent + "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        )
    return lines


def _print_table(*, headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    for line in _format_table(headers=headers, rows=rows):
        print(line)


def _format_datetime(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "-"


if __name__ == "__main__":
    raise SystemExit(main())
