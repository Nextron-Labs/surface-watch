from __future__ import annotations

from datetime import UTC, datetime

from surface_watch.config import parse_config_data
from surface_watch.diff import detect_changes
from surface_watch.models import DiscoveredTarget, HostScanRecord, PortFinding, ScanSnapshot


def _snapshot(
    *,
    scan_id: int,
    targets: list[DiscoveredTarget],
    host_results: list[HostScanRecord],
    port_findings: list[PortFinding],
) -> ScanSnapshot:
    now = datetime(2026, 5, 1, 8, 0, tzinfo=UTC)
    return ScanSnapshot(
        scan_id=scan_id,
        status="success",
        started_at=now,
        finished_at=now,
        targets=targets,
        host_results=host_results,
        port_findings=port_findings,
    )


def test_detects_discovery_and_port_changes_with_risk_policy() -> None:
    config = parse_config_data(
        {
            "risk_policy": {
                "risky_ports": {"tcp": {3389: "critical"}},
            }
        }
    )

    previous = _snapshot(
        scan_id=1,
        targets=[DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a")],
        host_results=[HostScanRecord("www.example.com", "203.0.113.10", "success")],
        port_findings=[],
    )
    current = _snapshot(
        scan_id=2,
        targets=[
            DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a"),
            DiscoveredTarget("staging.example.com", "203.0.113.55", "domain_a"),
        ],
        host_results=[
            HostScanRecord("www.example.com", "203.0.113.10", "success"),
            HostScanRecord("staging.example.com", "203.0.113.55", "success"),
        ],
        port_findings=[
            PortFinding(
                ip="203.0.113.10",
                protocol="tcp",
                port=3389,
                state="open",
                service_name="ms-wbt-server",
            )
        ],
    )

    changes = detect_changes(current, previous, config)

    assert any(
        change.change_type == "new_host" and change.hostname == "staging.example.com"
        for change in changes
    )
    risky_port_change = next(change for change in changes if change.change_type == "new_open_port")
    assert risky_port_change.port == 3389
    assert risky_port_change.severity == "critical"


def test_detects_removed_ip_and_closed_port() -> None:
    config = parse_config_data({})
    previous = _snapshot(
        scan_id=1,
        targets=[DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")],
        host_results=[HostScanRecord("vpn.example.com", "203.0.113.10", "success")],
        port_findings=[PortFinding(ip="203.0.113.10", protocol="tcp", port=22, state="open")],
    )
    current = _snapshot(
        scan_id=2,
        targets=[],
        host_results=[HostScanRecord("vpn.example.com", "203.0.113.10", "success")],
        port_findings=[],
    )

    changes = detect_changes(current, previous, config)
    assert any(change.change_type == "disappeared_host" for change in changes)
    assert any(change.change_type == "closed_port" and change.port == 22 for change in changes)


def test_detects_host_scan_failure_and_recovery_without_closed_port_noise() -> None:
    config = parse_config_data({})
    previous = _snapshot(
        scan_id=1,
        targets=[DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")],
        host_results=[HostScanRecord("vpn.example.com", "203.0.113.10", "success")],
        port_findings=[PortFinding(ip="203.0.113.10", protocol="tcp", port=443, state="open")],
    )
    current_failed = _snapshot(
        scan_id=2,
        targets=[DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")],
        host_results=[
            HostScanRecord("vpn.example.com", "203.0.113.10", "failed", error="timed out")
        ],
        port_findings=[],
    )
    failed_changes = detect_changes(current_failed, previous, config)
    assert any(change.change_type == "host_scan_failed" for change in failed_changes)
    assert not any(change.change_type == "closed_port" for change in failed_changes)

    recovered = _snapshot(
        scan_id=3,
        targets=[DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")],
        host_results=[HostScanRecord("vpn.example.com", "203.0.113.10", "success")],
        port_findings=[PortFinding(ip="203.0.113.10", protocol="tcp", port=443, state="open")],
    )
    recovered_changes = detect_changes(recovered, current_failed, config)
    assert any(change.change_type == "host_scan_recovered" for change in recovered_changes)


def test_ignores_version_noise_when_previous_version_is_missing() -> None:
    config = parse_config_data({})
    previous = _snapshot(
        scan_id=1,
        targets=[DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a")],
        host_results=[HostScanRecord("www.example.com", "203.0.113.10", "success")],
        port_findings=[
            PortFinding(
                ip="203.0.113.10",
                protocol="tcp",
                port=443,
                state="open",
                service_name="https",
                product="nginx",
                version=None,
            )
        ],
    )
    current = _snapshot(
        scan_id=2,
        targets=[DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a")],
        host_results=[HostScanRecord("www.example.com", "203.0.113.10", "success")],
        port_findings=[
            PortFinding(
                ip="203.0.113.10",
                protocol="tcp",
                port=443,
                state="open",
                service_name="https",
                product="nginx",
                version="1.24",
            )
        ],
    )

    changes = detect_changes(current, previous, config)
    assert not any(
        change.change_type in {"version_changed", "product_version_changed"} for change in changes
    )


def test_detects_product_version_change_when_both_values_exist() -> None:
    config = parse_config_data({})
    previous = _snapshot(
        scan_id=1,
        targets=[DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a")],
        host_results=[HostScanRecord("www.example.com", "203.0.113.10", "success")],
        port_findings=[
            PortFinding(
                ip="203.0.113.10",
                protocol="tcp",
                port=443,
                state="open",
                service_name="https",
                product="nginx",
                version="1.22",
            )
        ],
    )
    current = _snapshot(
        scan_id=2,
        targets=[DiscoveredTarget("www.example.com", "203.0.113.10", "domain_a")],
        host_results=[HostScanRecord("www.example.com", "203.0.113.10", "success")],
        port_findings=[
            PortFinding(
                ip="203.0.113.10",
                protocol="tcp",
                port=443,
                state="open",
                service_name="https",
                product="nginx",
                version="1.24",
            )
        ],
    )

    changes = detect_changes(current, previous, config)
    assert any(change.change_type == "version_changed" for change in changes)
