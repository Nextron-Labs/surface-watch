from __future__ import annotations

from pathlib import Path

import pytest

from surface_watch.config import compute_config_hash, parse_config_data, write_example_config


def test_parse_config_normalizes_hosts_and_paths(tmp_path: Path) -> None:
    config = parse_config_data(
        {
            "project": {
                "database_path": "./data/surface-watch.sqlite3",
                "log_level": "debug",
            },
            "scope": {
                "domains": ["Example.COM", "example.com"],
                "explicit_hosts": ["VPN.EXAMPLE.COM."],
                "explicit_ips": ["203.0.113.10"],
                "excluded_hosts": ["Do-Not-Scan.EXAMPLE.com"],
            },
            "risk_policy": {
                "risky_ports": {"tcp": {3389: "critical"}},
                "service_keywords": {
                    "remote_access": {
                        "severity": "high",
                        "keywords": ["RDP", "ssh"],
                    }
                },
            },
        },
        base_dir=tmp_path,
    )

    assert config.project.database_path == (tmp_path / "data" / "surface-watch.sqlite3").resolve()
    assert config.project.log_level == "DEBUG"
    assert config.scope.domains == ["example.com"]
    assert config.scope.explicit_hosts == ["vpn.example.com"]
    assert config.scope.excluded_hosts == ["do-not-scan.example.com"]
    assert config.change_detection.notify_on["new_open_port"] is True
    assert config.change_detection.notify_on["product_changed"] is False
    assert config.risk_policy.risky_ports["tcp"][3389] == "critical"
    assert config.risk_policy.service_keywords["remote_access"].keywords == ["rdp", "ssh"]


def test_compute_config_hash_is_stable_for_equivalent_input(tmp_path: Path) -> None:
    first = parse_config_data({"project": {"database_path": "./db.sqlite3"}}, base_dir=tmp_path)
    second = parse_config_data({"project": {"database_path": "./db.sqlite3"}}, base_dir=tmp_path)

    assert compute_config_hash(first) == compute_config_hash(second)


def test_write_example_config_refuses_to_overwrite(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    write_example_config(config_path)

    with pytest.raises(FileExistsError):
        write_example_config(config_path)
