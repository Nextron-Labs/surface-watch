from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from surface_watch import __version__
from surface_watch.cli import main
from surface_watch.config import EXAMPLE_CONFIG_YAML
from surface_watch.models import DiscoveredTarget, PortFinding, ScanResult
from surface_watch.storage import (
    create_scan,
    finish_scan,
    initialize_database,
    save_discovered_targets,
    save_scan_results,
)


def test_main_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"surface-watch {__version__}"


def test_main_accepts_global_config_before_subcommand(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "custom.yaml"
    config_path.write_text(EXAMPLE_CONFIG_YAML)

    captured: dict[str, Path] = {}
    fake_config = SimpleNamespace(
        project=SimpleNamespace(log_level="INFO", database_path=tmp_path / "surface-watch.sqlite3")
    )

    def fake_load_config(path: Path) -> SimpleNamespace:
        captured["path"] = path
        return fake_config

    monkeypatch.setattr("surface_watch.cli.load_config", fake_load_config)
    monkeypatch.setattr("surface_watch.cli.configure_logging", lambda _: None)
    monkeypatch.setattr("surface_watch.cli.initialize_database", lambda _: None)
    monkeypatch.setattr("surface_watch.cli.list_scans", lambda _: [])

    assert main(["--config", str(config_path), "list-scans"]) == 0
    assert captured["path"] == config_path


def test_main_uses_local_config_yaml_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(EXAMPLE_CONFIG_YAML)

    monkeypatch.setattr("surface_watch.cli.configure_logging", lambda _: None)
    monkeypatch.setattr("surface_watch.cli.initialize_database", lambda _: None)
    monkeypatch.setattr("surface_watch.cli.list_scans", lambda _: [])

    assert main(["list-scans"]) == 0


def test_main_reports_missing_config_clearly(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        main(["list-scans"])

    assert exc_info.value.code == 2
    assert "list-scans requires --config or a config.yaml file in the current directory" in (
        capsys.readouterr().err
    )


def test_init_rejects_global_config(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--config", "config.yaml", "init"])

    assert exc_info.value.code == 2
    assert "init does not use --config; use --config-path to choose the output path" in (
        capsys.readouterr().err
    )


def test_show_targets_lists_discovered_targets(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path, scan_id = _prepare_scan_fixture(tmp_path)
    monkeypatch.setattr("surface_watch.cli.configure_logging", lambda _: None)

    assert main(["--config", str(config_path), "show-targets", "--scan-id", str(scan_id)]) == 0

    output = capsys.readouterr().out
    assert "HOSTNAME" in output
    assert "vpn.example.com" in output
    assert "app.example.com" in output
    assert "Stored discovered targets: 2" in output


def test_show_ports_lists_ports_for_host(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path, scan_id = _prepare_scan_fixture(tmp_path)
    monkeypatch.setattr("surface_watch.cli.configure_logging", lambda _: None)

    command = [
        "--config",
        str(config_path),
        "show-ports",
        "--scan-id",
        str(scan_id),
        "--host",
        "vpn.example.com",
    ]
    assert main(command) == 0

    output = capsys.readouterr().out
    assert "PORT" in output
    assert "tcp/22" in output
    assert "tcp/443" in output
    assert "Stored port findings: 2" in output


def test_show_scan_pretty_prints_hosts_and_ports(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path, scan_id = _prepare_scan_fixture(tmp_path)
    monkeypatch.setattr("surface_watch.cli.configure_logging", lambda _: None)

    assert main(["--config", str(config_path), "show-scan", "--scan-id", str(scan_id)]) == 0

    output = capsys.readouterr().out
    assert f"Scan {scan_id}" in output
    assert "Status: partial" in output
    assert "Discovered targets: 2" in output
    assert "Host scan records: 2" in output
    assert "Open ports: 2" in output
    assert "Discovered Targets" in output
    assert "Hosts" in output
    assert "vpn.example.com (203.0.113.10)" in output
    assert "tcp/443" in output
    assert "Error: timed out" in output
    assert "Ports: none" in output


def _prepare_scan_fixture(tmp_path: Path) -> tuple[Path, int]:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE_CONFIG_YAML)

    database_path = tmp_path / "surface-watch.sqlite3"
    initialize_database(database_path)

    timestamp = datetime(2026, 5, 1, 8, 0, tzinfo=UTC)
    scan_id = create_scan(
        database_path,
        started_at=timestamp,
        status="running",
        config_hash="hash-1",
        tool_version=__version__,
    )
    save_discovered_targets(
        database_path,
        scan_id,
        [
            DiscoveredTarget(
                hostname="vpn.example.com",
                ip="203.0.113.10",
                source="explicit_host",
                parent_domain="example.com",
                record_type="A",
            ),
            DiscoveredTarget(
                hostname="app.example.com",
                ip="203.0.113.20",
                source="domain_a",
                parent_domain="example.com",
                record_type="A",
            ),
        ],
    )
    save_scan_results(
        database_path,
        scan_id,
        [
            ScanResult(
                target="vpn.example.com",
                hostname="vpn.example.com",
                target_ip="203.0.113.10",
                resolved_ips=["203.0.113.10"],
                scan_started_at=timestamp,
                scan_finished_at=timestamp,
                status="success",
                error=None,
                open_ports=[
                    PortFinding(
                        ip="203.0.113.10",
                        protocol="tcp",
                        port=22,
                        state="open",
                        service_name="ssh",
                        product="OpenSSH",
                        version="9.6",
                    ),
                    PortFinding(
                        ip="203.0.113.10",
                        protocol="tcp",
                        port=443,
                        state="open",
                        service_name="https",
                        product="nginx",
                        version="1.24",
                    ),
                ],
            ),
            ScanResult(
                target="app.example.com",
                hostname="app.example.com",
                target_ip="203.0.113.20",
                resolved_ips=["203.0.113.20"],
                scan_started_at=timestamp,
                scan_finished_at=timestamp,
                status="failed",
                error="timed out",
                open_ports=[],
            ),
        ],
    )
    finish_scan(
        database_path,
        scan_id,
        finished_at=timestamp,
        status="partial",
    )
    return config_path, scan_id


def test_init_creates_default_wordlist(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"

    assert main(["init", "--config-path", str(config_path)]) == 0

    wordlist_path = tmp_path / "wordlists" / "subdomains-small.txt"
    assert wordlist_path.is_file()
    assert "cpanel" in wordlist_path.read_text(encoding="utf-8").splitlines()
