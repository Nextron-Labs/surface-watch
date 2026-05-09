from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from surface_watch.config import parse_config_data
from surface_watch.models import DiscoveredTarget
from surface_watch.scanner import (
    _can_use_syn_scan,
    _stderr_indicates_host_timeout,
    build_nmap_command,
    scan_target,
)


def test_build_nmap_command_adds_ipv6_flag_for_ipv6_targets() -> None:
    config = parse_config_data({})

    command = build_nmap_command("nmap", config, "2a06:fb00:1::1:66")

    assert "-6" in command


def test_scan_target_marks_timeout_shaped_zero_port_result_as_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = parse_config_data({"scanning": {"timing": {"host_timeout": "30m"}}})
    target = DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")
    started_at = datetime(2026, 5, 6, 8, 0, tzinfo=UTC)
    finished_at = started_at + timedelta(minutes=30)

    xml_output = """
    <nmaprun>
      <host>
        <status state="up" reason="syn-ack" />
        <address addr="203.0.113.10" addrtype="ipv4" />
        <ports />
      </host>
    </nmaprun>
    """

    monkeypatch.setattr(
        "surface_watch.scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=xml_output, stderr=""),
    )
    _set_scan_times(monkeypatch, started_at, finished_at)

    result = scan_target(target, config, nmap_binary="nmap")

    assert result.status == "failed"
    assert result.open_ports == []
    assert result.error is not None
    assert "--host-timeout 30m" in result.error


def test_scan_target_marks_timeout_shaped_result_with_ports_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = parse_config_data({"scanning": {"timing": {"host_timeout": "30m"}}})
    target = DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")
    started_at = datetime(2026, 5, 6, 8, 0, tzinfo=UTC)
    finished_at = started_at + timedelta(minutes=30)

    xml_output = """
    <nmaprun>
      <host>
        <status state="up" reason="syn-ack" />
        <address addr="203.0.113.10" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open" />
            <service name="https" product="nginx" version="1.24" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    monkeypatch.setattr(
        "surface_watch.scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=xml_output, stderr=""),
    )
    _set_scan_times(monkeypatch, started_at, finished_at)

    result = scan_target(target, config, nmap_binary="nmap")

    assert result.status == "partial"
    assert len(result.open_ports) == 1
    assert result.error is not None
    assert "--host-timeout 30m" in result.error


def test_scan_target_marks_zero_host_result_as_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = parse_config_data({})
    target = DiscoveredTarget("pns31.cloudns.net", "2a06:fb00:1::1:66", "domain_ns")
    started_at = datetime(2026, 5, 6, 8, 0, tzinfo=UTC)
    finished_at = started_at + timedelta(seconds=1)

    monkeypatch.setattr(
        "surface_watch.scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="<nmaprun />",
            stderr=(
                "2a06:fb00:1::1:66 looks like an IPv6 target specification -- you have to use "
                "the -6 option.\nWARNING: No targets were specified, so 0 hosts scanned."
            ),
        ),
    )
    _set_scan_times(monkeypatch, started_at, finished_at)

    result = scan_target(target, config, nmap_binary="nmap")

    assert result.status == "failed"
    assert result.error is not None
    assert "0 hosts scanned" in result.error


def _set_scan_times(
    monkeypatch: pytest.MonkeyPatch,
    started_at: datetime,
    finished_at: datetime,
) -> None:
    timestamps = iter((started_at, finished_at))
    monkeypatch.setattr("surface_watch.scanner.utc_now", lambda: next(timestamps))


def test_can_use_syn_scan_returns_false_on_non_unix_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("surface_watch.scanner.platform.system", lambda: "Windows")
    assert _can_use_syn_scan() is False


def test_can_use_syn_scan_returns_true_for_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("surface_watch.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    assert _can_use_syn_scan() is True


def test_stderr_indicates_host_timeout_detects_timeout_patterns() -> None:
    assert _stderr_indicates_host_timeout("Host timeout reached") is True
    assert _stderr_indicates_host_timeout("Warning: retransmission cap hit") is True
    assert _stderr_indicates_host_timeout("Normal scan output") is False


def test_scan_target_uses_stderr_timeout_indicator(monkeypatch: pytest.MonkeyPatch) -> None:
    config = parse_config_data({})
    target = DiscoveredTarget("vpn.example.com", "203.0.113.10", "explicit_host")
    started_at = datetime(2026, 5, 6, 8, 0, tzinfo=UTC)
    finished_at = started_at + timedelta(seconds=5)

    xml_output = """
    <nmaprun>
      <host>
        <status state="up" reason="syn-ack" />
        <address addr="203.0.113.10" addrtype="ipv4" />
        <ports />
      </host>
    </nmaprun>
    """

    monkeypatch.setattr(
        "surface_watch.scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=xml_output, stderr="Warning: retransmission cap hit (10)"
        ),
    )
    _set_scan_times(monkeypatch, started_at, finished_at)

    result = scan_target(target, config, nmap_binary="nmap")

    assert result.status == "failed"
    assert "retransmission cap hit" in (result.error or "")
