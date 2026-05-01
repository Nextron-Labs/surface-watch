from __future__ import annotations

import logging
from pathlib import Path

import dns.exception
import dns.resolver

from surface_watch.config import SurfaceWatchConfig
from surface_watch.models import DiscoveredTarget, normalize_hostname

LOGGER = logging.getLogger(__name__)


def discover_targets(config: SurfaceWatchConfig) -> list[DiscoveredTarget]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0

    discovered: dict[tuple[str | None, str | None], DiscoveredTarget] = {}

    for host in config.scope.explicit_hosts:
        _add_host_addresses(
            discovered=discovered,
            resolver=resolver,
            hostname=host,
            source="explicit_host",
            parent_domain=None,
        )

    for ip in config.scope.explicit_ips:
        _add_target(
            discovered,
            DiscoveredTarget(
                hostname=None,
                ip=ip,
                source="explicit_ip",
                parent_domain=None,
                record_type=None,
            ),
        )

    if config.discovery.enabled:
        for domain in config.scope.domains:
            _discover_domain_targets(discovered, resolver, domain, config)
        if config.discovery.brute_force_subdomains.enabled:
            _brute_force_subdomains(discovered, resolver, config)

    excluded_hosts = set(config.scope.excluded_hosts)
    excluded_ips = set(config.scope.excluded_ips)

    filtered = [
        target
        for target in discovered.values()
        if target.hostname not in excluded_hosts and target.ip not in excluded_ips
    ]
    filtered.sort(key=lambda target: (target.hostname or "", target.ip or "", target.source))
    return filtered


def _discover_domain_targets(
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    resolver: dns.resolver.Resolver,
    domain: str,
    config: SurfaceWatchConfig,
) -> None:
    record_types = set(config.discovery.dns_record_types)
    if "A" in record_types or "AAAA" in record_types:
        _add_host_addresses(
            discovered=discovered,
            resolver=resolver,
            hostname=domain,
            source="domain_a",
            parent_domain=domain,
            include_ipv4="A" in record_types,
            include_ipv6="AAAA" in record_types,
        )

    if "CNAME" in record_types:
        _resolve_cname_aliases(discovered, resolver, domain, parent_domain=domain)

    if "MX" in record_types and config.discovery.include_mx_hosts:
        for hostname in _resolve_mx_hosts(resolver, domain):
            _add_host_addresses(
                discovered=discovered,
                resolver=resolver,
                hostname=hostname,
                source="domain_mx",
                parent_domain=domain,
                record_type="MX",
            )

    if "NS" in record_types and config.discovery.include_ns_hosts:
        for hostname in _resolve_ns_hosts(resolver, domain):
            _add_host_addresses(
                discovered=discovered,
                resolver=resolver,
                hostname=hostname,
                source="domain_ns",
                parent_domain=domain,
                record_type="NS",
            )

    if "SRV" in record_types and config.discovery.include_srv_hosts:
        for hostname in _resolve_srv_hosts(resolver, domain):
            _add_host_addresses(
                discovered=discovered,
                resolver=resolver,
                hostname=hostname,
                source="domain_srv",
                parent_domain=domain,
                record_type="SRV",
            )


def _add_host_addresses(
    *,
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    resolver: dns.resolver.Resolver,
    hostname: str,
    source: str,
    parent_domain: str | None,
    include_ipv4: bool = True,
    include_ipv6: bool = True,
    record_type: str | None = None,
) -> None:
    normalized_hostname = normalize_hostname(hostname)
    if normalized_hostname is None:
        return

    if include_ipv4:
        for ip in _resolve_addresses(resolver, normalized_hostname, "A"):
            _add_target(
                discovered,
                DiscoveredTarget(
                    hostname=normalized_hostname,
                    ip=ip,
                    source=source,
                    parent_domain=parent_domain,
                    record_type=record_type or "A",
                ),
            )
    if include_ipv6:
        for ip in _resolve_addresses(resolver, normalized_hostname, "AAAA"):
            _add_target(
                discovered,
                DiscoveredTarget(
                    hostname=normalized_hostname,
                    ip=ip,
                    source=source if source != "domain_a" else "domain_aaaa",
                    parent_domain=parent_domain,
                    record_type=record_type or "AAAA",
                ),
            )


def _resolve_cname_aliases(
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    resolver: dns.resolver.Resolver,
    hostname: str,
    *,
    parent_domain: str,
) -> None:
    aliases = _resolve_hostnames(resolver, hostname, "CNAME")
    for alias in aliases:
        for record_type in ("A", "AAAA"):
            for ip in _resolve_addresses(resolver, alias, record_type):
                _add_target(
                    discovered,
                    DiscoveredTarget(
                        hostname=hostname,
                        ip=ip,
                        source="domain_a" if record_type == "A" else "domain_aaaa",
                        parent_domain=parent_domain,
                        record_type=record_type,
                    ),
                )


def _resolve_mx_hosts(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    records = _query_records(resolver, domain, "MX")
    hosts = [normalize_hostname(record.exchange.to_text()) for record in records]
    return [host for host in dict.fromkeys(hosts) if host]


def _resolve_ns_hosts(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    return _resolve_hostnames(resolver, domain, "NS")


def _resolve_srv_hosts(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    hostnames: list[str] = []
    candidate_names = [
        domain,
        f"_sip._tcp.{domain}",
        f"_sip._tls.{domain}",
        f"_xmpp-client._tcp.{domain}",
        f"_xmpp-server._tcp.{domain}",
    ]
    for candidate in candidate_names:
        records = _query_records(resolver, candidate, "SRV")
        for record in records:
            hostname = normalize_hostname(record.target.to_text())
            if hostname:
                hostnames.append(hostname)
    return [hostname for hostname in dict.fromkeys(hostnames)]


def _resolve_hostnames(
    resolver: dns.resolver.Resolver,
    hostname: str,
    record_type: str,
) -> list[str]:
    records = _query_records(resolver, hostname, record_type)
    hostnames = [normalize_hostname(record.to_text()) for record in records]
    return [name for name in dict.fromkeys(hostnames) if name]


def _resolve_addresses(
    resolver: dns.resolver.Resolver,
    hostname: str,
    record_type: str,
) -> list[str]:
    records = _query_records(resolver, hostname, record_type)
    addresses = [record.to_text().strip() for record in records]
    return [address for address in dict.fromkeys(addresses) if address]


def _query_records(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> list[object]:
    try:
        answer = resolver.resolve(name, record_type, search=False)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ) as exc:
        LOGGER.debug("DNS lookup failed for %s %s: %s", record_type, name, exc)
        return []
    return list(answer)


def _brute_force_subdomains(
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    resolver: dns.resolver.Resolver,
    config: SurfaceWatchConfig,
) -> None:
    wordlist_path = config.discovery.brute_force_subdomains.wordlist_path
    if wordlist_path is None or not wordlist_path.exists():
        LOGGER.warning("Subdomain wordlist is missing; brute-force discovery is skipped.")
        return

    words = _load_wordlist(wordlist_path)
    for domain in config.scope.domains:
        for word in words:
            hostname = f"{word}.{domain}"
            _add_host_addresses(
                discovered=discovered,
                resolver=resolver,
                hostname=hostname,
                source="brute_force_subdomain",
                parent_domain=domain,
            )


def _load_wordlist(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    return [word for word in dict.fromkeys(words) if word and not word.startswith("#")]


def _add_target(
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    target: DiscoveredTarget,
) -> None:
    discovered.setdefault(target.identity, target)
