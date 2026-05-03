from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
ScanStatus = Literal["running", "success", "failed", "partial", "discovery_only"]
HostResultStatus = Literal["success", "failed", "partial"]
Protocol = Literal["tcp", "udp"]


def utc_now() -> datetime:
    return datetime.now(UTC)


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def normalize_hostname(value: str | None) -> str | None:
    normalized = normalize_optional_text(value)
    if normalized is None:
        return None
    return normalized.rstrip(".").lower()


def normalize_csv_text(value: str | None) -> str | None:
    normalized_items: list[str] = []
    for part in (value or "").split(","):
        normalized_part = normalize_optional_text(part)
        if normalized_part is None:
            continue
        lowered = normalized_part.lower()
        if lowered not in normalized_items:
            normalized_items.append(lowered)
    if not normalized_items:
        return None
    return ",".join(normalized_items)


def normalize_csv_hostnames(value: str | None) -> str | None:
    normalized_items: list[str] = []
    for part in (value or "").split(","):
        normalized_part = normalize_hostname(part)
        if normalized_part is None:
            continue
        if normalized_part not in normalized_items:
            normalized_items.append(normalized_part)
    if not normalized_items:
        return None
    return ",".join(normalized_items)


def split_csv_text(value: str | None) -> tuple[str, ...]:
    normalized = normalize_csv_text(value)
    if normalized is None:
        return ()
    return tuple(normalized.split(","))


def split_csv_hostnames(value: str | None) -> tuple[str, ...]:
    normalized = normalize_csv_hostnames(value)
    if normalized is None:
        return ()
    return tuple(normalized.split(","))


def is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


@dataclass(slots=True)
class DiscoveredTarget:
    hostname: str | None
    ip: str | None
    source: str
    parent_domain: str | None = None
    record_type: str | None = None

    def __post_init__(self) -> None:
        self.hostname = normalize_hostname(self.hostname)
        self.ip = normalize_optional_text(self.ip)
        self.source = normalize_csv_text(self.source) or ""
        self.parent_domain = normalize_csv_hostnames(self.parent_domain)
        record_type = normalize_optional_text(self.record_type)
        self.record_type = record_type.upper() if record_type else None

    @property
    def identity(self) -> tuple[str | None, str | None]:
        return (self.hostname, self.ip)

    @property
    def sources(self) -> tuple[str, ...]:
        return split_csv_text(self.source)

    @property
    def parent_domains(self) -> tuple[str, ...]:
        return split_csv_hostnames(self.parent_domain)


@dataclass(slots=True)
class PortFinding:
    ip: str
    protocol: Protocol
    port: int
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None

    def __post_init__(self) -> None:
        self.ip = self.ip.strip()
        self.protocol = self.protocol.lower()  # type: ignore[assignment]
        self.state = self.state.strip().lower()
        self.service_name = normalize_optional_text(self.service_name)
        self.product = normalize_optional_text(self.product)
        self.version = normalize_optional_text(self.version)
        self.extra_info = normalize_optional_text(self.extra_info)
        self.tunnel = normalize_optional_text(self.tunnel)
        self.method = normalize_optional_text(self.method)

    @property
    def port_identity(self) -> tuple[str, str, int]:
        return (self.ip, self.protocol, self.port)

    @property
    def service_identity(self) -> tuple[str, str, int, str | None, str | None, str | None]:
        return (
            self.ip,
            self.protocol,
            self.port,
            self.service_name,
            self.product,
            self.version,
        )


@dataclass(slots=True)
class HostScanRecord:
    hostname: str | None
    ip: str
    status: HostResultStatus
    error: str | None = None

    def __post_init__(self) -> None:
        self.hostname = normalize_hostname(self.hostname)
        self.ip = self.ip.strip()
        self.status = self.status.lower()  # type: ignore[assignment]
        self.error = normalize_optional_text(self.error)

    @property
    def identity(self) -> tuple[str | None, str]:
        return (self.hostname, self.ip)


@dataclass(slots=True)
class ScanResult:
    target: str
    resolved_ips: list[str]
    scan_started_at: datetime
    scan_finished_at: datetime
    status: HostResultStatus
    error: str | None
    open_ports: list[PortFinding] = field(default_factory=list)
    hostname: str | None = None
    target_ip: str | None = None

    def __post_init__(self) -> None:
        self.target = self.target.strip()
        self.resolved_ips = [ip.strip() for ip in self.resolved_ips if ip and ip.strip()]
        self.status = self.status.lower()  # type: ignore[assignment]
        self.error = normalize_optional_text(self.error)
        self.hostname = normalize_hostname(self.hostname)
        self.target_ip = normalize_optional_text(self.target_ip)

    @property
    def host_records(self) -> list[HostScanRecord]:
        host_ips = list(dict.fromkeys(self.resolved_ips))
        if not host_ips and self.target_ip:
            host_ips = [self.target_ip]
        return [
            HostScanRecord(hostname=self.hostname, ip=ip, status=self.status, error=self.error)
            for ip in host_ips
        ]


@dataclass(slots=True)
class Change:
    change_type: str
    severity: Severity
    hostname: str | None = None
    ip: str | None = None
    protocol: str | None = None
    port: int | None = None
    old_value: str | None = None
    new_value: str | None = None
    message: str = ""
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.change_type = self.change_type.strip().lower()
        self.severity = self.severity.lower()  # type: ignore[assignment]
        self.hostname = normalize_hostname(self.hostname)
        self.ip = normalize_optional_text(self.ip)
        self.protocol = normalize_optional_text(self.protocol)
        if self.protocol is not None:
            self.protocol = self.protocol.lower()
        self.old_value = normalize_optional_text(self.old_value)
        self.new_value = normalize_optional_text(self.new_value)
        self.message = self.message.strip()


@dataclass(slots=True)
class ScanSnapshot:
    scan_id: int
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    targets: list[DiscoveredTarget] = field(default_factory=list)
    host_results: list[HostScanRecord] = field(default_factory=list)
    port_findings: list[PortFinding] = field(default_factory=list)


@dataclass(slots=True)
class ScanMetadata:
    scan_id: int
    started_at: datetime | None
    finished_at: datetime | None
    status: str
    config_hash: str | None
    tool_version: str | None
