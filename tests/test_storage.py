from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from surface_watch.models import Change, DiscoveredTarget, PortFinding, ScanResult
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


def test_storage_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "surface-watch.sqlite3"
    initialize_database(database_path)

    started_at = datetime(2026, 5, 1, 8, 0, tzinfo=UTC)
    first_scan_id = create_scan(
        database_path,
        started_at=started_at,
        status="running",
        config_hash="hash-1",
        tool_version="0.1.0",
    )
    save_discovered_targets(
        database_path,
        first_scan_id,
        [
            DiscoveredTarget(
                hostname="vpn.example.com",
                ip="203.0.113.10",
                source="explicit_host",
                parent_domain=None,
                record_type="A",
            )
        ],
    )
    save_scan_results(
        database_path,
        first_scan_id,
        [
            ScanResult(
                target="vpn.example.com",
                hostname="vpn.example.com",
                target_ip="203.0.113.10",
                resolved_ips=["203.0.113.10"],
                scan_started_at=started_at,
                scan_finished_at=started_at,
                status="success",
                error=None,
                open_ports=[
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
        ],
    )
    save_changes(
        database_path,
        first_scan_id,
        [
            Change(
                change_type="new_open_port",
                severity="high",
                hostname="vpn.example.com",
                ip="203.0.113.10",
                protocol="tcp",
                port=443,
                old_value=None,
                new_value="tcp/443",
                message="New open port tcp/443 on vpn.example.com (203.0.113.10)",
            )
        ],
    )
    finish_scan(
        database_path,
        first_scan_id,
        finished_at=started_at,
        status="success",
    )

    second_scan_id = create_scan(
        database_path,
        started_at=started_at,
        status="running",
        config_hash="hash-2",
        tool_version="0.1.0",
    )
    finish_scan(
        database_path,
        second_scan_id,
        finished_at=started_at,
        status="partial",
    )

    assert get_previous_successful_scan_id(database_path, second_scan_id) == first_scan_id

    snapshot = load_scan_snapshot(database_path, first_scan_id)
    assert snapshot.status == "success"
    assert len(snapshot.targets) == 1
    assert len(snapshot.host_results) == 1
    assert len(snapshot.port_findings) == 1
    assert snapshot.port_findings[0].product == "nginx"

    changes = load_changes(database_path, first_scan_id)
    assert len(changes) == 1
    assert changes[0].change_type == "new_open_port"

    scans = list_scans(database_path)
    assert [scan.scan_id for scan in scans] == [second_scan_id, first_scan_id]
