from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from surface_watch.config import SEVERITY_ORDER, SurfaceWatchConfig, max_severity
from surface_watch.models import Change, HostScanRecord, PortFinding, ScanSnapshot

SERVICE_CHANGE_TYPES = {
    "service_changed",
    "product_changed",
    "version_changed",
    "product_version_changed",
}


def detect_changes(
    current: ScanSnapshot,
    previous: ScanSnapshot,
    config: SurfaceWatchConfig,
) -> list[Change]:
    changes: list[Change] = []
    changes.extend(_detect_discovery_changes(current, previous, config))
    changes.extend(_detect_host_scan_status_changes(current, previous, config))
    changes.extend(_detect_port_changes(current, previous, config))
    changes.extend(_detect_service_changes(current, previous, config))
    return sorted(
        changes,
        key=lambda change: (
            -SEVERITY_ORDER[change.severity],
            change.change_type,
            change.hostname or "",
            change.ip or "",
            change.port or -1,
        ),
    )


def _detect_discovery_changes(
    current: ScanSnapshot,
    previous: ScanSnapshot,
    config: SurfaceWatchConfig,
) -> list[Change]:
    changes: list[Change] = []
    current_hosts, current_ips, current_ip_only = _group_targets(current)
    previous_hosts, previous_ips, previous_ip_only = _group_targets(previous)

    for hostname in sorted(current_hosts.keys() - previous_hosts.keys()):
        current_host_ips = sorted(current_hosts[hostname])
        ip_summary = ", ".join(current_host_ips) or "no resolved IP"
        changes.append(
            _make_change(
                "new_host",
                config,
                hostname=hostname,
                ip=current_host_ips[0] if current_host_ips else None,
                old_value=None,
                new_value=",".join(current_host_ips) if current_host_ips else hostname,
                message=f"New host discovered: {hostname} -> {ip_summary}",
            )
        )

    for hostname in sorted(previous_hosts.keys() - current_hosts.keys()):
        previous_host_ips = sorted(previous_hosts[hostname])
        ip_summary = ", ".join(previous_host_ips) or "no resolved IP"
        changes.append(
            _make_change(
                "disappeared_host",
                config,
                hostname=hostname,
                ip=previous_host_ips[0] if previous_host_ips else None,
                old_value=",".join(previous_host_ips) if previous_host_ips else hostname,
                new_value=None,
                message=f"Host disappeared: {hostname} ({ip_summary})",
            )
        )

    for hostname in sorted(current_hosts.keys() & previous_hosts.keys()):
        new_ips = sorted(current_hosts[hostname] - previous_hosts[hostname])
        removed_ips = sorted(previous_hosts[hostname] - current_hosts[hostname])
        for ip in new_ips:
            changes.append(
                _make_change(
                    "new_ip_for_host",
                    config,
                    hostname=hostname,
                    ip=ip,
                    old_value=None,
                    new_value=ip,
                    message=f"New IP for host {hostname}: {ip}",
                )
            )
        for ip in removed_ips:
            changes.append(
                _make_change(
                    "removed_ip_from_host",
                    config,
                    hostname=hostname,
                    ip=ip,
                    old_value=ip,
                    new_value=None,
                    message=f"Removed IP from host {hostname}: {ip}",
                )
            )

    for ip in sorted(current_ip_only - previous_ip_only):
        changes.append(
            _make_change(
                "new_host",
                config,
                hostname=None,
                ip=ip,
                old_value=None,
                new_value=ip,
                message=f"New IP target discovered: {ip}",
            )
        )
    for ip in sorted(previous_ip_only - current_ip_only):
        changes.append(
            _make_change(
                "disappeared_host",
                config,
                hostname=None,
                ip=ip,
                old_value=ip,
                new_value=None,
                message=f"IP target disappeared: {ip}",
            )
        )

    return changes


def _detect_host_scan_status_changes(
    current: ScanSnapshot,
    previous: ScanSnapshot,
    config: SurfaceWatchConfig,
) -> list[Change]:
    changes: list[Change] = []
    current_map = {(record.hostname, record.ip): record for record in current.host_results}
    previous_map = {(record.hostname, record.ip): record for record in previous.host_results}

    for identity in sorted(current_map.keys() & previous_map.keys()):
        current_record = current_map[identity]
        previous_record = previous_map[identity]
        if previous_record.status == "success" and current_record.status != "success":
            host_label = current_record.hostname or current_record.ip
            changes.append(
                _make_change(
                    "host_scan_failed",
                    config,
                    hostname=current_record.hostname,
                    ip=current_record.ip,
                    old_value=previous_record.status,
                    new_value=current_record.status,
                    message=f"Host scan failed: {host_label} ({current_record.ip})",
                )
            )
        elif previous_record.status != "success" and current_record.status == "success":
            host_label = current_record.hostname or current_record.ip
            changes.append(
                _make_change(
                    "host_scan_recovered",
                    config,
                    hostname=current_record.hostname,
                    ip=current_record.ip,
                    old_value=previous_record.status,
                    new_value=current_record.status,
                    message=f"Host scan recovered: {host_label} ({current_record.ip})",
                )
            )
    return changes


def _detect_port_changes(
    current: ScanSnapshot,
    previous: ScanSnapshot,
    config: SurfaceWatchConfig,
) -> list[Change]:
    changes: list[Change] = []
    current_ports = _port_map(current.port_findings)
    previous_ports = _port_map(previous.port_findings)

    current_successful_ips = _successful_ips(current.host_results)
    previous_successful_ips = _successful_ips(previous.host_results)
    previous_failed_only_ips = _failed_only_ips(previous.host_results)

    for identity, finding in sorted(current_ports.items()):
        if finding.ip not in current_successful_ips:
            continue
        if identity not in previous_ports and finding.ip not in previous_failed_only_ips:
            host_label = _format_host(finding.ip, current.host_results)
            changes.append(
                _make_change(
                    "new_open_port",
                    config,
                    hostname=_hostname_for_ip(current.host_results, finding.ip),
                    ip=finding.ip,
                    protocol=finding.protocol,
                    port=finding.port,
                    old_value=None,
                    new_value=_port_label(finding),
                    message=f"New open port {finding.protocol}/{finding.port} on {host_label}",
                    service_values=[finding.service_name, finding.product, finding.version],
                )
            )

    for identity, finding in sorted(previous_ports.items()):
        if finding.ip not in previous_successful_ips or finding.ip not in current_successful_ips:
            continue
        if identity not in current_ports:
            host_label = _format_host(finding.ip, previous.host_results)
            changes.append(
                _make_change(
                    "closed_port",
                    config,
                    hostname=_hostname_for_ip(current.host_results, finding.ip)
                    or _hostname_for_ip(previous.host_results, finding.ip),
                    ip=finding.ip,
                    protocol=finding.protocol,
                    port=finding.port,
                    old_value=_port_label(finding),
                    new_value=None,
                    message=f"Closed port {finding.protocol}/{finding.port} on {host_label}",
                    service_values=[finding.service_name, finding.product, finding.version],
                )
            )
    return changes


def _detect_service_changes(
    current: ScanSnapshot,
    previous: ScanSnapshot,
    config: SurfaceWatchConfig,
) -> list[Change]:
    changes: list[Change] = []
    current_ports = _port_map(current.port_findings)
    previous_ports = _port_map(previous.port_findings)

    comparable_ips = _successful_ips(current.host_results) & _successful_ips(previous.host_results)
    for identity in sorted(current_ports.keys() & previous_ports.keys()):
        current_finding = current_ports[identity]
        previous_finding = previous_ports[identity]
        if current_finding.ip not in comparable_ips:
            continue

        service_change = _build_service_change(
            current_finding=current_finding,
            previous_finding=previous_finding,
            host_results=current.host_results,
            config=config,
        )
        if service_change is not None:
            changes.append(service_change)
    return changes


def _build_service_change(
    *,
    current_finding: PortFinding,
    previous_finding: PortFinding,
    host_results: list[HostScanRecord],
    config: SurfaceWatchConfig,
) -> Change | None:
    hostname = _hostname_for_ip(host_results, current_finding.ip)
    host_label = _format_host(current_finding.ip, host_results)
    port_label = f"{current_finding.protocol}/{current_finding.port}"

    if _meaningful_difference(previous_finding.service_name, current_finding.service_name):
        return _make_change(
            "service_changed",
            config,
            hostname=hostname,
            ip=current_finding.ip,
            protocol=current_finding.protocol,
            port=current_finding.port,
            old_value=previous_finding.service_name,
            new_value=current_finding.service_name,
            message=(
                f"Service changed on {host_label} {port_label}: "
                f"{previous_finding.service_name} -> {current_finding.service_name}"
            ),
            service_values=[
                previous_finding.service_name,
                current_finding.service_name,
                previous_finding.product,
                current_finding.product,
                previous_finding.version,
                current_finding.version,
            ],
        )

    product_changed = _meaningful_difference(previous_finding.product, current_finding.product)
    version_changed = _meaningful_difference(previous_finding.version, current_finding.version)

    if product_changed and version_changed:
        return _make_change(
            "product_version_changed",
            config,
            hostname=hostname,
            ip=current_finding.ip,
            protocol=current_finding.protocol,
            port=current_finding.port,
            old_value=_service_version_label(previous_finding),
            new_value=_service_version_label(current_finding),
            message=(
                f"Service version changed on {host_label} {port_label}: "
                f"{_service_version_label(previous_finding)} -> "
                f"{_service_version_label(current_finding)}"
            ),
            service_values=[
                previous_finding.product,
                current_finding.product,
                previous_finding.version,
                current_finding.version,
            ],
        )
    if product_changed:
        return _make_change(
            "product_changed",
            config,
            hostname=hostname,
            ip=current_finding.ip,
            protocol=current_finding.protocol,
            port=current_finding.port,
            old_value=previous_finding.product,
            new_value=current_finding.product,
            message=(
                f"Product changed on {host_label} {port_label}: "
                f"{previous_finding.product} -> {current_finding.product}"
            ),
            service_values=[previous_finding.product, current_finding.product],
        )
    if version_changed:
        return _make_change(
            "version_changed",
            config,
            hostname=hostname,
            ip=current_finding.ip,
            protocol=current_finding.protocol,
            port=current_finding.port,
            old_value=previous_finding.version,
            new_value=current_finding.version,
            message=(
                f"Version changed on {host_label} {port_label}: "
                f"{previous_finding.version} -> {current_finding.version}"
            ),
            service_values=[
                previous_finding.service_name,
                current_finding.service_name,
                previous_finding.version,
                current_finding.version,
            ],
        )
    return None


def _group_targets(
    snapshot: ScanSnapshot,
) -> tuple[dict[str, set[str]], dict[str, set[str]], set[str]]:
    host_to_ips: dict[str, set[str]] = defaultdict(set)
    ip_to_hosts: dict[str, set[str]] = defaultdict(set)
    ip_only: set[str] = set()

    for target in snapshot.targets:
        if target.hostname and target.ip:
            host_to_ips[target.hostname].add(target.ip)
            ip_to_hosts[target.ip].add(target.hostname)
        elif target.hostname:
            host_to_ips[target.hostname]
        elif target.ip:
            ip_only.add(target.ip)

    return host_to_ips, ip_to_hosts, ip_only


def _port_map(findings: Iterable[PortFinding]) -> dict[tuple[str, str, int], PortFinding]:
    port_map: dict[tuple[str, str, int], PortFinding] = {}
    for finding in findings:
        port_map[finding.port_identity] = finding
    return port_map


def _successful_ips(host_results: Iterable[HostScanRecord]) -> set[str]:
    return {record.ip for record in host_results if record.status == "success"}


def _failed_only_ips(host_results: Iterable[HostScanRecord]) -> set[str]:
    statuses_by_ip: dict[str, set[str]] = defaultdict(set)
    for record in host_results:
        statuses_by_ip[record.ip].add(record.status)
    return {
        ip
        for ip, statuses in statuses_by_ip.items()
        if statuses and statuses <= {"failed", "partial"}
    }


def _hostname_for_ip(host_results: Iterable[HostScanRecord], ip: str) -> str | None:
    hostnames = sorted(
        {record.hostname for record in host_results if record.ip == ip and record.hostname}
    )
    return hostnames[0] if hostnames else None


def _format_host(ip: str, host_results: Iterable[HostScanRecord]) -> str:
    hostname = _hostname_for_ip(host_results, ip)
    if hostname:
        return f"{hostname} ({ip})"
    return ip


def _port_label(finding: PortFinding) -> str:
    return f"{finding.protocol}/{finding.port}"


def _service_version_label(finding: PortFinding) -> str:
    parts = [part for part in [finding.product, finding.version] if part]
    return " ".join(parts) or finding.service_name or "unknown"


def _meaningful_difference(previous: str | None, current: str | None) -> bool:
    return bool(previous and current and previous != current)


def _make_change(
    change_type: str,
    config: SurfaceWatchConfig,
    *,
    hostname: str | None,
    ip: str | None,
    protocol: str | None = None,
    port: int | None = None,
    old_value: str | None,
    new_value: str | None,
    message: str,
    service_values: list[str | None] | None = None,
) -> Change:
    severity = config.change_detection.severity.get(change_type, "info")
    severity = _apply_risk_policy(
        base_severity=severity,
        change_type=change_type,
        protocol=protocol,
        port=port,
        service_values=service_values or [],
        config=config,
    )
    return Change(
        change_type=change_type,
        severity=severity,
        hostname=hostname,
        ip=ip,
        protocol=protocol,
        port=port,
        old_value=old_value,
        new_value=new_value,
        message=message,
    )


def _apply_risk_policy(
    *,
    base_severity: str,
    change_type: str,
    protocol: str | None,
    port: int | None,
    service_values: list[str | None],
    config: SurfaceWatchConfig,
) -> str:
    severity = base_severity

    if port is not None and protocol is not None:
        protocol_mapping = config.risk_policy.risky_ports.get(protocol.lower(), {})
        if port in protocol_mapping and change_type in {
            "new_open_port",
            "service_changed",
            "product_changed",
            "version_changed",
            "product_version_changed",
        }:
            severity = max_severity(severity, protocol_mapping[port])

    haystack = " ".join(value.lower() for value in service_values if value)
    if haystack:
        for policy in config.risk_policy.service_keywords.values():
            if any(keyword in haystack for keyword in policy.keywords):
                severity = max_severity(severity, policy.severity)

    return severity
