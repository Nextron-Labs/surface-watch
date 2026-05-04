from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

from surface_watch.models import Severity, normalize_hostname

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_NOTIFY_RULES: dict[str, bool] = {
    "new_host": True,
    "disappeared_host": False,
    "new_ip_for_host": True,
    "removed_ip_from_host": False,
    "cname_changed": False,
    "mx_changed": False,
    "ns_changed": False,
    "srv_record_changed": False,
    "host_scan_failed": True,
    "host_scan_recovered": True,
    "host_timeout": True,
    "host_unreachable": True,
    "host_reachable_again": True,
    "new_open_port": True,
    "closed_port": False,
    "port_state_changed": False,
    "new_protocol_on_host": True,
    "service_changed": False,
    "product_changed": False,
    "version_changed": False,
    "product_version_changed": False,
    "banner_changed": False,
    "tls_detected": False,
    "tls_removed": False,
    "certificate_subject_changed": False,
    "certificate_issuer_changed": False,
    "certificate_expiry_changed": False,
    "http_title_changed": False,
    "http_server_header_changed": False,
    "http_redirect_changed": False,
    "risky_port_exposed": True,
    "admin_port_exposed": True,
    "database_port_exposed": True,
    "remote_access_port_exposed": True,
}

DEFAULT_SEVERITY_RULES: dict[str, str] = {
    "new_host": "medium",
    "disappeared_host": "low",
    "new_ip_for_host": "medium",
    "removed_ip_from_host": "low",
    "cname_changed": "low",
    "mx_changed": "low",
    "ns_changed": "low",
    "srv_record_changed": "medium",
    "host_scan_failed": "medium",
    "host_scan_recovered": "info",
    "host_timeout": "medium",
    "host_unreachable": "medium",
    "host_reachable_again": "info",
    "new_open_port": "high",
    "closed_port": "info",
    "port_state_changed": "low",
    "new_protocol_on_host": "high",
    "service_changed": "medium",
    "product_changed": "low",
    "version_changed": "low",
    "product_version_changed": "low",
    "banner_changed": "low",
    "tls_detected": "medium",
    "tls_removed": "medium",
    "certificate_subject_changed": "low",
    "certificate_issuer_changed": "low",
    "certificate_expiry_changed": "medium",
    "http_title_changed": "low",
    "http_server_header_changed": "low",
    "http_redirect_changed": "low",
    "risky_port_exposed": "high",
    "admin_port_exposed": "high",
    "database_port_exposed": "high",
    "remote_access_port_exposed": "high",
}

EXAMPLE_CONFIG_YAML = """project:
  name: "Example External Surface Watch"
  database_path: "./surface-watch.sqlite3"
  log_level: "INFO"

scope:
  domains:
    - "example.com"
    - "example.org"

  explicit_hosts:
    - "vpn.example.com"
    - "mail.example.com"

  explicit_ips:
    - "203.0.113.10"

  excluded_hosts:
    - "do-not-scan.example.com"

  excluded_ips:
    - "203.0.113.99"

discovery:
  enabled: true

  dns_record_types:
    - "A"
    - "AAAA"
    - "CNAME"
    - "MX"
    - "NS"
    - "TXT"
    - "SRV"

  include_mx_hosts: true
  include_ns_hosts: true
  include_srv_hosts: true

  brute_force_subdomains:
    enabled: false
    wordlist_path: "./wordlists/subdomains-small.txt"

  passive_sources:
    enabled: false
    dnsdumpster:
      enabled: false
      api_key_env: "DNSDUMPSTER_API_KEY"
      timeout_seconds: 15.0
      min_interval_seconds: 2.0
      max_pages: 1
      restrict_to_domain_suffix: true
      include_a_records: true
      include_cname_records: true
      include_mx_hosts: false
      include_ns_hosts: false
    chaos:
      enabled: false
      api_key_env: "PDCP_API_KEY"
      timeout_seconds: 15.0
    otx:
      enabled: false
      api_key_env: "OTX_API_KEY"
      timeout_seconds: 15.0

scanning:
  enabled: true

  nmap_path: "nmap"
  scan_mode: "full_tcp"

  ports:
    tcp: "1-65535"
    udp: ""

  timing:
    template: "T3"
    host_timeout: "30m"
    max_retries: 3

  service_detection:
    enabled: true
    version_intensity: 5

  os_detection:
    enabled: false

  default_args:
    - "-Pn"
    - "--open"

  extra_args: []

change_detection:
  compare_against: "previous_successful_scan"

  notify_on:
    new_host: true
    disappeared_host: false
    new_ip_for_host: true
    removed_ip_from_host: false
    new_open_port: true
    closed_port: false
    service_changed: false
    product_changed: false
    version_changed: false
    product_version_changed: false
    host_scan_failed: true
    host_scan_recovered: true

  severity:
    new_host: "medium"
    disappeared_host: "low"
    new_ip_for_host: "medium"
    removed_ip_from_host: "low"
    new_open_port: "high"
    closed_port: "info"
    service_changed: "medium"
    product_changed: "low"
    version_changed: "low"
    product_version_changed: "low"
    host_scan_failed: "medium"
    host_scan_recovered: "info"

notifications:
  enabled: true

  minimum_severity: "medium"

  providers:
    slack:
      enabled: false
      webhook_url_env: "SLACK_WEBHOOK_URL"

    teams:
      enabled: false
      webhook_url_env: "TEAMS_WEBHOOK_URL"

    discord:
      enabled: false
      webhook_url_env: "DISCORD_WEBHOOK_URL"

  message:
    include_full_diff: true
    include_scan_id: true
    include_timestamp: true
    include_summary: true

risk_policy:
  risky_ports:
    tcp:
      21: "medium"
      22: "medium"
      23: "high"
      25: "medium"
      135: "critical"
      139: "critical"
      445: "critical"
      3389: "critical"
      5432: "high"
      5900: "high"
      6379: "critical"
      9200: "critical"
      9300: "critical"
      11211: "critical"
      1433: "high"
      1521: "high"
      27017: "critical"
      3306: "high"

  service_keywords:
    database:
      severity: "high"
      keywords:
        - "mysql"
        - "postgres"
        - "mongodb"
        - "redis"
        - "mssql"
        - "oracle"

    remote_access:
      severity: "high"
      keywords:
        - "rdp"
        - "vnc"
        - "telnet"
        - "ssh"
"""

EXAMPLE_SUBDOMAIN_WORDLIST = """# Starter wordlist for optional brute-force subdomain discovery.
# Keep this list short and bias toward high-signal names.
www
api
app
admin
portal
vpn
mail
webmail
autodiscover
autoconfig
smtp
mx
remote
cpanel
whm
webdisk
status
support
staging
dev
"""


@dataclass(slots=True)
class ProjectConfig:
    name: str
    database_path: Path
    log_level: str = "INFO"


@dataclass(slots=True)
class ScopeConfig:
    domains: list[str]
    explicit_hosts: list[str]
    explicit_ips: list[str]
    excluded_hosts: list[str]
    excluded_ips: list[str]


@dataclass(slots=True)
class BruteForceSubdomainsConfig:
    enabled: bool = False
    wordlist_path: Path | None = None


@dataclass(slots=True)
class DNSDumpsterConfig:
    enabled: bool = False
    api_key_env: str = "DNSDUMPSTER_API_KEY"
    timeout_seconds: float = 15.0
    min_interval_seconds: float = 2.0
    max_pages: int = 1
    restrict_to_domain_suffix: bool = True
    include_a_records: bool = True
    include_cname_records: bool = True
    include_mx_hosts: bool = False
    include_ns_hosts: bool = False


@dataclass(slots=True)
class ChaosConfig:
    enabled: bool = False
    api_key_env: str = "PDCP_API_KEY"
    timeout_seconds: float = 15.0


@dataclass(slots=True)
class OTXConfig:
    enabled: bool = False
    api_key_env: str = "OTX_API_KEY"
    timeout_seconds: float = 15.0


@dataclass(slots=True)
class PassiveSourcesConfig:
    enabled: bool = False
    dnsdumpster: DNSDumpsterConfig | None = None
    chaos: ChaosConfig | None = None
    otx: OTXConfig | None = None


@dataclass(slots=True)
class DiscoveryConfig:
    enabled: bool
    dns_record_types: list[str]
    include_mx_hosts: bool
    include_ns_hosts: bool
    include_srv_hosts: bool
    brute_force_subdomains: BruteForceSubdomainsConfig
    passive_sources: PassiveSourcesConfig


@dataclass(slots=True)
class PortsConfig:
    tcp: str
    udp: str = ""


@dataclass(slots=True)
class ScanningTimingConfig:
    template: str
    host_timeout: str
    max_retries: int


@dataclass(slots=True)
class ServiceDetectionConfig:
    enabled: bool
    version_intensity: int


@dataclass(slots=True)
class OsDetectionConfig:
    enabled: bool = False


@dataclass(slots=True)
class ScanningConfig:
    enabled: bool
    nmap_path: str
    scan_mode: str
    ports: PortsConfig
    timing: ScanningTimingConfig
    service_detection: ServiceDetectionConfig
    os_detection: OsDetectionConfig
    default_args: list[str]
    extra_args: list[str]


@dataclass(slots=True)
class ChangeDetectionConfig:
    compare_against: str
    notify_on: dict[str, bool]
    severity: dict[str, str]


@dataclass(slots=True)
class ProviderConfig:
    enabled: bool
    webhook_url_env: str


@dataclass(slots=True)
class MessageConfig:
    include_full_diff: bool
    include_scan_id: bool
    include_timestamp: bool
    include_summary: bool


@dataclass(slots=True)
class NotificationsConfig:
    enabled: bool
    minimum_severity: Severity
    providers: dict[str, ProviderConfig]
    message: MessageConfig


@dataclass(slots=True)
class ServiceKeywordPolicy:
    severity: Severity
    keywords: list[str]


@dataclass(slots=True)
class RiskPolicyConfig:
    risky_ports: dict[str, dict[int, Severity]]
    service_keywords: dict[str, ServiceKeywordPolicy]


@dataclass(slots=True)
class SurfaceWatchConfig:
    project: ProjectConfig
    scope: ScopeConfig
    discovery: DiscoveryConfig
    scanning: ScanningConfig
    change_detection: ChangeDetectionConfig
    notifications: NotificationsConfig
    risk_policy: RiskPolicyConfig
    source_path: Path | None = None


def load_config(path: Path) -> SurfaceWatchConfig:
    config_path = path.expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        raw_data = yaml.safe_load(handle) or {}
    if not isinstance(raw_data, dict):
        raise ValueError("Configuration root must be a mapping.")
    config = parse_config_data(raw_data, config_path.parent)
    config.source_path = config_path
    return config


def parse_config_data(data: dict[str, Any], base_dir: Path | None = None) -> SurfaceWatchConfig:
    base_path = (base_dir or Path.cwd()).expanduser().resolve()

    project_section = dict(data.get("project", {}))
    scope_section = dict(data.get("scope", {}))
    discovery_section = dict(data.get("discovery", {}))
    scanning_section = dict(data.get("scanning", {}))
    change_section = dict(data.get("change_detection", {}))
    notifications_section = dict(data.get("notifications", {}))
    risk_policy_section = dict(data.get("risk_policy", {}))

    project = ProjectConfig(
        name=str(project_section.get("name", "Surface Watch")).strip(),
        database_path=_resolve_path(
            project_section.get("database_path", "./surface-watch.sqlite3"), base_path
        ),
        log_level=str(project_section.get("log_level", "INFO")).strip().upper(),
    )

    scope = ScopeConfig(
        domains=_normalize_host_list(scope_section.get("domains", [])),
        explicit_hosts=_normalize_host_list(scope_section.get("explicit_hosts", [])),
        explicit_ips=_normalize_string_list(scope_section.get("explicit_ips", [])),
        excluded_hosts=_normalize_host_list(scope_section.get("excluded_hosts", [])),
        excluded_ips=_normalize_string_list(scope_section.get("excluded_ips", [])),
    )

    brute_force_section = dict(discovery_section.get("brute_force_subdomains", {}))
    passive_sources_section = dict(discovery_section.get("passive_sources", {}))
    dnsdumpster_section = dict(passive_sources_section.get("dnsdumpster", {}))
    chaos_section = dict(passive_sources_section.get("chaos", {}))
    otx_section = dict(passive_sources_section.get("otx", {}))
    discovery = DiscoveryConfig(
        enabled=bool(discovery_section.get("enabled", True)),
        dns_record_types=_normalize_record_types(
            discovery_section.get("dns_record_types", ["A", "AAAA", "CNAME", "MX", "NS", "SRV"])
        ),
        include_mx_hosts=bool(discovery_section.get("include_mx_hosts", True)),
        include_ns_hosts=bool(discovery_section.get("include_ns_hosts", True)),
        include_srv_hosts=bool(discovery_section.get("include_srv_hosts", True)),
        brute_force_subdomains=BruteForceSubdomainsConfig(
            enabled=bool(brute_force_section.get("enabled", False)),
            wordlist_path=_optional_resolved_path(
                brute_force_section.get("wordlist_path"), base_path
            ),
        ),
        passive_sources=PassiveSourcesConfig(
            enabled=bool(passive_sources_section.get("enabled", False)),
            dnsdumpster=DNSDumpsterConfig(
                enabled=bool(dnsdumpster_section.get("enabled", False)),
                api_key_env=str(
                    dnsdumpster_section.get("api_key_env", "DNSDUMPSTER_API_KEY")
                ).strip(),
                timeout_seconds=float(dnsdumpster_section.get("timeout_seconds", 15.0)),
                min_interval_seconds=float(
                    dnsdumpster_section.get("min_interval_seconds", 2.0)
                ),
                max_pages=int(dnsdumpster_section.get("max_pages", 1)),
                restrict_to_domain_suffix=bool(
                    dnsdumpster_section.get("restrict_to_domain_suffix", True)
                ),
                include_a_records=bool(dnsdumpster_section.get("include_a_records", True)),
                include_cname_records=bool(
                    dnsdumpster_section.get("include_cname_records", True)
                ),
                include_mx_hosts=bool(dnsdumpster_section.get("include_mx_hosts", False)),
                include_ns_hosts=bool(dnsdumpster_section.get("include_ns_hosts", False)),
            ),
            chaos=ChaosConfig(
                enabled=bool(chaos_section.get("enabled", False)),
                api_key_env=str(chaos_section.get("api_key_env", "PDCP_API_KEY")).strip(),
                timeout_seconds=float(chaos_section.get("timeout_seconds", 15.0)),
            ),
            otx=OTXConfig(
                enabled=bool(otx_section.get("enabled", False)),
                api_key_env=str(otx_section.get("api_key_env", "OTX_API_KEY")).strip(),
                timeout_seconds=float(otx_section.get("timeout_seconds", 15.0)),
            ),
        ),
    )

    ports_section = dict(scanning_section.get("ports", {}))
    timing_section = dict(scanning_section.get("timing", {}))
    service_detection_section = dict(scanning_section.get("service_detection", {}))
    os_detection_section = dict(scanning_section.get("os_detection", {}))
    scanning = ScanningConfig(
        enabled=bool(scanning_section.get("enabled", True)),
        nmap_path=str(scanning_section.get("nmap_path", "nmap")).strip(),
        scan_mode=str(scanning_section.get("scan_mode", "full_tcp")).strip().lower(),
        ports=PortsConfig(
            tcp=str(ports_section.get("tcp", "1-65535")).strip(),
            udp=str(ports_section.get("udp", "")).strip(),
        ),
        timing=ScanningTimingConfig(
            template=str(timing_section.get("template", "T3")).strip().upper(),
            host_timeout=str(timing_section.get("host_timeout", "30m")).strip(),
            max_retries=int(timing_section.get("max_retries", 3)),
        ),
        service_detection=ServiceDetectionConfig(
            enabled=bool(service_detection_section.get("enabled", True)),
            version_intensity=int(service_detection_section.get("version_intensity", 5)),
        ),
        os_detection=OsDetectionConfig(enabled=bool(os_detection_section.get("enabled", False))),
        default_args=_normalize_string_list(
            scanning_section.get("default_args", ["-Pn", "--open"])
        ),
        extra_args=_normalize_string_list(scanning_section.get("extra_args", [])),
    )

    notify_on = DEFAULT_NOTIFY_RULES | {
        str(key).strip().lower(): bool(value)
        for key, value in dict(change_section.get("notify_on", {})).items()
    }
    severity = DEFAULT_SEVERITY_RULES | {
        str(key).strip().lower(): _normalize_severity(value)
        for key, value in dict(change_section.get("severity", {})).items()
    }
    change_detection = ChangeDetectionConfig(
        compare_against=str(
            change_section.get("compare_against", "previous_successful_scan")
        ).strip(),
        notify_on=notify_on,
        severity=severity,
    )

    providers_section = dict(notifications_section.get("providers", {}))
    message_section = dict(notifications_section.get("message", {}))
    notifications = NotificationsConfig(
        enabled=bool(notifications_section.get("enabled", True)),
        minimum_severity=_normalize_severity(
            notifications_section.get("minimum_severity", "medium")
        ),
        providers={
            name: ProviderConfig(
                enabled=bool(section.get("enabled", False)),
                webhook_url_env=str(section.get("webhook_url_env", "")).strip(),
            )
            for name, section in {
                "slack": dict(providers_section.get("slack", {})),
                "teams": dict(providers_section.get("teams", {})),
                "discord": dict(providers_section.get("discord", {})),
            }.items()
        },
        message=MessageConfig(
            include_full_diff=bool(message_section.get("include_full_diff", True)),
            include_scan_id=bool(message_section.get("include_scan_id", True)),
            include_timestamp=bool(message_section.get("include_timestamp", True)),
            include_summary=bool(message_section.get("include_summary", True)),
        ),
    )

    risky_ports: dict[str, dict[int, Severity]] = {}
    for protocol, mappings in dict(risk_policy_section.get("risky_ports", {})).items():
        risky_ports[protocol.lower()] = {
            int(port): _normalize_severity(level) for port, level in dict(mappings).items()
        }

    service_keywords: dict[str, ServiceKeywordPolicy] = {}
    for name, section in dict(risk_policy_section.get("service_keywords", {})).items():
        keyword_section = dict(section)
        service_keywords[name] = ServiceKeywordPolicy(
            severity=_normalize_severity(keyword_section.get("severity", "medium")),
            keywords=[
                str(keyword).strip().lower()
                for keyword in keyword_section.get("keywords", [])
                if str(keyword).strip()
            ],
        )

    risk_policy = RiskPolicyConfig(risky_ports=risky_ports, service_keywords=service_keywords)

    return SurfaceWatchConfig(
        project=project,
        scope=scope,
        discovery=discovery,
        scanning=scanning,
        change_detection=change_detection,
        notifications=notifications,
        risk_policy=risk_policy,
    )


def compute_config_hash(config: SurfaceWatchConfig) -> str:
    payload = json.dumps(_serialize(config), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_example_config(path: Path, overwrite: bool = False) -> Path:
    target_path = path.expanduser().resolve()
    if target_path.exists() and not overwrite:
        raise FileExistsError(f"Configuration file already exists: {target_path}")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(EXAMPLE_CONFIG_YAML, encoding="utf-8")
    _write_example_wordlist(target_path.parent / "wordlists" / "subdomains-small.txt", overwrite)
    return target_path


def _write_example_wordlist(path: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(EXAMPLE_SUBDOMAIN_WORDLIST, encoding="utf-8")


def severity_at_least(candidate: str, minimum: str) -> bool:
    return (
        SEVERITY_ORDER[_normalize_severity(candidate)]
        >= SEVERITY_ORDER[_normalize_severity(minimum)]
    )


def max_severity(*values: str) -> Severity:
    normalized = [_normalize_severity(value) for value in values if value]
    if not normalized:
        return "info"
    return max(normalized, key=lambda severity: SEVERITY_ORDER[severity])  # type: ignore[return-value]


def _serialize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {field.name: _serialize(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


def _normalize_host_list(values: Any) -> list[str]:
    normalized = [normalize_hostname(str(value)) for value in values or []]
    return [value for value in dict.fromkeys(normalized) if value]


def _normalize_string_list(values: Any) -> list[str]:
    normalized = [str(value).strip() for value in values or []]
    return [value for value in dict.fromkeys(normalized) if value]


def _normalize_record_types(values: Any) -> list[str]:
    normalized = [str(value).strip().upper() for value in values or []]
    return [value for value in dict.fromkeys(normalized) if value]


def _normalize_severity(value: Any) -> Severity:
    normalized = str(value).strip().lower()
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Unsupported severity value: {value!r}")
    return normalized  # type: ignore[return-value]


def _resolve_path(value: Any, base_path: Path) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base_path / path
    return path.resolve()


def _optional_resolved_path(value: Any, base_path: Path) -> Path | None:
    if value in (None, ""):
        return None
    return _resolve_path(value, base_path)
