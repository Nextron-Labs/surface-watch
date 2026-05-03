from __future__ import annotations

import logging
from pathlib import Path

import dns.exception
import dns.resolver

from surface_watch.config import SurfaceWatchConfig
from surface_watch.models import DiscoveredTarget, normalize_hostname
from surface_watch.passive_sources import (
    ChaosClient,
    DNSDumpsterClient,
    OTXClient,
    PassiveDiscoveryProvider,
)

LOGGER = logging.getLogger(__name__)


def discover_targets(
    config: SurfaceWatchConfig,
    *,
    dnsdumpster_client: PassiveDiscoveryProvider | None = None,
    passive_providers: list[PassiveDiscoveryProvider] | None = None,
) -> list[DiscoveredTarget]:
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

        _discover_passive_targets(
            discovered=discovered,
            resolver=resolver,
            config=config,
            dnsdumpster_client=dnsdumpster_client,
            passive_providers=passive_providers,
        )

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


def _discover_passive_targets(
    *,
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    resolver: dns.resolver.Resolver,
    config: SurfaceWatchConfig,
    dnsdumpster_client: PassiveDiscoveryProvider | None,
    passive_providers: list[PassiveDiscoveryProvider] | None,
) -> None:
    passive_sources = config.discovery.passive_sources
    if not passive_sources.enabled:
        return

    providers = passive_providers or _build_passive_providers(config, dnsdumpster_client)
    if not providers:
        return

    merged_candidates: dict[str, dict[str, set[str]]] = {}
    for domain in config.scope.domains:
        for provider in providers:
            try:
                candidates = provider.discover_domain_candidates(domain)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning(
                    "Passive provider %s failed for %s: %s",
                    provider.__class__.__name__,
                    domain,
                    exc,
                )
                continue

            for candidate in candidates:
                normalized_hostname = _normalize_passive_hostname(candidate.hostname)
                if normalized_hostname is None:
                    continue
                if not _hostname_within_domain(normalized_hostname, domain):
                    continue

                entry = merged_candidates.setdefault(
                    normalized_hostname,
                    {"sources": set(), "parent_domains": set()},
                )
                entry["sources"].add(candidate.source)
                entry["parent_domains"].add(candidate.parent_domain)

    for hostname, metadata in merged_candidates.items():
        _add_host_addresses(
            discovered=discovered,
            resolver=resolver,
            hostname=hostname,
            source=",".join(sorted(metadata["sources"])),
            parent_domain=",".join(sorted(metadata["parent_domains"])),
        )


def _build_passive_providers(
    config: SurfaceWatchConfig,
    dnsdumpster_client: PassiveDiscoveryProvider | None,
) -> list[PassiveDiscoveryProvider]:
    providers: list[PassiveDiscoveryProvider] = []
    passive_sources = config.discovery.passive_sources

    if dnsdumpster_client is not None:
        providers.append(dnsdumpster_client)
    elif passive_sources.dnsdumpster is not None and passive_sources.dnsdumpster.enabled:
        providers.append(DNSDumpsterClient(passive_sources.dnsdumpster))

    if passive_sources.chaos is not None and passive_sources.chaos.enabled:
        providers.append(ChaosClient(passive_sources.chaos))

    if passive_sources.otx is not None and passive_sources.otx.enabled:
        providers.append(OTXClient(passive_sources.otx))

    return providers


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


def _normalize_passive_hostname(value: str | None) -> str | None:
    normalized = normalize_hostname(value)
    while normalized and normalized.startswith("*."):
        normalized = normalized[2:]
    return normalized or None


def _hostname_within_domain(hostname: str, domain: str) -> bool:
    normalized_hostname = normalize_hostname(hostname)
    normalized_domain = normalize_hostname(domain)
    if normalized_hostname is None or normalized_domain is None:
        return False
    return (
        normalized_hostname == normalized_domain
        or normalized_hostname.endswith(f".{normalized_domain}")
    )


def _load_wordlist(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    return [word for word in dict.fromkeys(words) if word and not word.startswith("#")]


def _add_target(
    discovered: dict[tuple[str | None, str | None], DiscoveredTarget],
    target: DiscoveredTarget,
) -> None:
    existing = discovered.get(target.identity)
    if existing is None:
        discovered[target.identity] = target
        return

    merged_sources = list(dict.fromkeys([*existing.sources, *target.sources]))
    existing.source = ",".join(merged_sources)

    merged_parent_domains = list(dict.fromkeys([*existing.parent_domains, *target.parent_domains]))
    existing.parent_domain = ",".join(merged_parent_domains) if merged_parent_domains else None

    if existing.record_type is None and target.record_type is not None:
        existing.record_type = target.record_type
