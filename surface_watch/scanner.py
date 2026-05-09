from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from pathlib import Path

from surface_watch.config import SurfaceWatchConfig
from surface_watch.models import DiscoveredTarget, PortFinding, ScanResult, utc_now

LOGGER = logging.getLogger(__name__)
_DURATION_PART_RE = re.compile(r"(\d+)(ms|s|m|h|d)?", re.IGNORECASE)


def scan_targets(targets: list[DiscoveredTarget], config: SurfaceWatchConfig) -> list[ScanResult]:
    nmap_binary = _resolve_nmap_binary(config.scanning.nmap_path)
    unique_targets = _deduplicate_targets(targets)
    return [scan_target(target, config, nmap_binary=nmap_binary) for target in unique_targets]


def scan_target(
    target: DiscoveredTarget,
    config: SurfaceWatchConfig,
    *,
    nmap_binary: str | None = None,
) -> ScanResult:
    if target.ip is None:
        started_at = utc_now()
        finished_at = utc_now()
        return ScanResult(
            target=target.hostname or "unknown-target",
            hostname=target.hostname,
            target_ip=None,
            resolved_ips=[],
            scan_started_at=started_at,
            scan_finished_at=finished_at,
            status="failed",
            error="Target does not include a resolved IP address.",
            open_ports=[],
        )

    binary = nmap_binary or _resolve_nmap_binary(config.scanning.nmap_path)
    command = build_nmap_command(binary, config, target.ip)
    LOGGER.info("Scanning target %s (%s)", target.hostname or target.ip, target.ip)

    started_at = utc_now()
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    finished_at = utc_now()

    stdout = process.stdout or ""
    stderr = (process.stderr or "").strip()
    elapsed_seconds = (finished_at - started_at).total_seconds()

    try:
        parsed_ips, open_ports = parse_nmap_xml(stdout)
    except ET.ParseError as exc:
        error_message = stderr or f"Failed to parse nmap XML output: {exc}"
        LOGGER.warning("nmap XML parsing failed for %s: %s", target.ip, error_message)
        return ScanResult(
            target=target.hostname or target.ip,
            hostname=target.hostname,
            target_ip=target.ip,
            resolved_ips=[target.ip],
            scan_started_at=started_at,
            scan_finished_at=finished_at,
            status="failed",
            error=error_message,
            open_ports=[],
        )

    resolved_ips = parsed_ips or [target.ip]
    for finding in open_ports:
        if not finding.ip:
            finding.ip = target.ip
    status, error = _classify_scan_result(
        process_returncode=process.returncode,
        stderr=stderr,
        parsed_ips=parsed_ips,
        open_ports=open_ports,
        elapsed_seconds=elapsed_seconds,
        host_timeout=config.scanning.timing.host_timeout,
    )

    return ScanResult(
        target=target.hostname or target.ip,
        hostname=target.hostname,
        target_ip=target.ip,
        resolved_ips=resolved_ips,
        scan_started_at=started_at,
        scan_finished_at=finished_at,
        status=status,
        error=error,
        open_ports=open_ports,
    )


def build_nmap_command(nmap_binary: str, config: SurfaceWatchConfig, target: str) -> list[str]:
    if config.scanning.scan_mode != "full_tcp":
        raise ValueError(f"Unsupported scan mode for v1: {config.scanning.scan_mode}")

    command = [nmap_binary]
    if _is_ipv6_target(target):
        command.append("-6")

    default_args = list(config.scanning.default_args)
    for flag in ("-Pn", "--open"):
        if flag not in default_args:
            default_args.append(flag)
    command.extend(default_args)

    command.append("-sS" if _can_use_syn_scan() else "-sT")
    command.extend(["-p", config.scanning.ports.tcp])
    command.extend(["--max-retries", str(config.scanning.timing.max_retries)])
    command.extend(["--host-timeout", config.scanning.timing.host_timeout])
    command.append(_normalize_timing_template(config.scanning.timing.template))

    if config.scanning.service_detection.enabled:
        command.append("-sV")
        command.extend(
            ["--version-intensity", str(config.scanning.service_detection.version_intensity)]
        )
    if config.scanning.os_detection.enabled:
        command.append("-O")
    if config.scanning.ports.udp:
        LOGGER.warning(
            "UDP port configuration is present but UDP scanning is not implemented in v1."
        )

    command.extend(config.scanning.extra_args)
    command.extend(["-oX", "-", target])
    return command


def parse_nmap_xml(xml_output: str) -> tuple[list[str], list[PortFinding]]:
    root = ET.fromstring(xml_output)

    resolved_ips: list[str] = []
    open_ports: dict[tuple[str, str, int], PortFinding] = {}
    for host in root.findall("./host"):
        for address in host.findall("./address"):
            addr_type = address.get("addrtype", "")
            value = address.get("addr", "").strip()
            if addr_type in {"ipv4", "ipv6"} and value:
                resolved_ips.append(value)

        for port_element in host.findall("./ports/port"):
            protocol = (port_element.get("protocol") or "tcp").strip().lower()
            port_id = int(port_element.get("portid", "0"))
            state_element = port_element.find("./state")
            state = (state_element.get("state") if state_element is not None else "unknown").lower()
            if state != "open":
                continue

            service_element = port_element.find("./service")
            finding = PortFinding(
                ip=resolved_ips[0] if resolved_ips else "",
                protocol=protocol,
                port=port_id,
                state=state,
                service_name=service_element.get("name") if service_element is not None else None,
                product=service_element.get("product") if service_element is not None else None,
                version=service_element.get("version") if service_element is not None else None,
                extra_info=service_element.get("extrainfo")
                if service_element is not None
                else None,
                tunnel=service_element.get("tunnel") if service_element is not None else None,
                method=service_element.get("method") if service_element is not None else None,
                confidence=_parse_confidence(
                    service_element.get("conf") if service_element is not None else None
                ),
            )
            open_ports[finding.port_identity] = finding

    return list(dict.fromkeys(resolved_ips)), list(open_ports.values())


def _resolve_nmap_binary(nmap_path: str) -> str:
    if os.path.sep in nmap_path:
        binary = Path(nmap_path).expanduser()
        if not binary.exists():
            raise FileNotFoundError(f"Configured nmap binary does not exist: {binary}")
        return str(binary)

    resolved = shutil.which(nmap_path)
    if resolved is None:
        raise FileNotFoundError(f"nmap binary not found in PATH: {nmap_path}")
    return resolved


def _deduplicate_targets(targets: list[DiscoveredTarget]) -> list[DiscoveredTarget]:
    unique: dict[tuple[str | None, str | None], DiscoveredTarget] = {}
    for target in targets:
        if target.ip is None:
            continue
        unique.setdefault((target.hostname, target.ip), target)
    return list(unique.values())


def _normalize_timing_template(value: str) -> str:
    normalized = value.strip().upper()
    if normalized.startswith("-T"):
        return normalized
    if normalized.startswith("T"):
        return f"-{normalized}"
    return f"-T{normalized}"


def _can_use_syn_scan() -> bool:
    if platform.system() not in {"Linux", "Darwin"}:
        return False
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return True
    # Check for CAP_NET_RAW by attempting to create a raw socket
    try:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.close()
        return True
    except (OSError, PermissionError):
        return False


def _parse_confidence(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(value)


def _classify_scan_result(
    *,
    process_returncode: int,
    stderr: str,
    parsed_ips: list[str],
    open_ports: list[PortFinding],
    elapsed_seconds: float,
    host_timeout: str,
) -> tuple[str, str | None]:
    if process_returncode != 0:
        if open_ports:
            return ("partial", stderr or f"nmap exited with return code {process_returncode}")
        return ("failed", stderr or f"nmap exited with return code {process_returncode}")

    if _stderr_indicates_invalid_target(stderr):
        return (
            "failed",
            _combine_error_details(
                stderr,
                "nmap did not scan the target successfully; refusing to record a zero-host result as success.",
            ),
        )

    if _likely_hit_host_timeout(elapsed_seconds, host_timeout) or _stderr_indicates_host_timeout(stderr):
        if open_ports:
            return (
                "partial",
                _combine_error_details(
                    stderr,
                    f"nmap likely hit --host-timeout {host_timeout}; recording the host result as partial.",
                ),
            )
        return (
            "failed",
            _combine_error_details(
                stderr,
                f"nmap likely hit --host-timeout {host_timeout}; refusing to record a successful zero-port result.",
            ),
        )

    if stderr and not parsed_ips and not open_ports:
        return ("failed", stderr)

    return ("success", stderr or None)


def _stderr_indicates_invalid_target(stderr: str) -> bool:
    normalized = stderr.lower()
    return any(
        pattern in normalized
        for pattern in (
            "0 hosts scanned",
            "no targets were specified",
            "looks like an ipv6 target specification",
            "you have to use the -6 option",
        )
    )


def _stderr_indicates_host_timeout(stderr: str) -> bool:
    normalized = stderr.lower()
    return any(
        pattern in normalized
        for pattern in (
            "host timeout",
            "timed out",
            "retransmission cap hit",
        )
    )


def _likely_hit_host_timeout(elapsed_seconds: float, host_timeout: str) -> bool:
    timeout_seconds = _parse_duration_seconds(host_timeout)
    if timeout_seconds is None or timeout_seconds <= 0:
        return False
    tolerance_seconds = min(5.0, max(1.0, timeout_seconds * 0.01))
    return elapsed_seconds >= max(0.0, timeout_seconds - tolerance_seconds)


def _parse_duration_seconds(value: str) -> float | None:
    normalized = value.strip().lower()
    if not normalized:
        return None

    total_seconds = 0.0
    position = 0
    for match in _DURATION_PART_RE.finditer(normalized):
        if match.start() != position:
            return None
        position = match.end()
        amount = int(match.group(1))
        unit = (match.group(2) or "s").lower()
        multiplier = {
            "ms": 0.001,
            "s": 1.0,
            "m": 60.0,
            "h": 3600.0,
            "d": 86400.0,
        }.get(unit)
        if multiplier is None:
            return None
        total_seconds += amount * multiplier

    if position != len(normalized):
        return None
    return total_seconds


def _combine_error_details(*parts: str) -> str | None:
    messages: list[str] = []
    seen: set[str] = set()
    for part in parts:
        normalized = part.strip()
        if not normalized or normalized in seen:
            continue
        messages.append(normalized)
        seen.add(normalized)
    if not messages:
        return None
    return "\n".join(messages)


def _is_ipv6_target(value: str) -> bool:
    try:
        return ip_address(value).version == 6
    except ValueError:
        return False
