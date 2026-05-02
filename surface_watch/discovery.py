from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib import error, parse, request

import dns.exception
import dns.resolver

from surface_watch import __version__
from surface_watch.config import DNSDumpsterConfig, SurfaceWatchConfig
from surface_watch.models import DiscoveredTarget, normalize_hostname

LOGGER = logging.getLogger(__name__)


class PassiveDiscoveryClient(Protocol):
    def discover_domain_targets(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
    ) -> list[DiscoveredTarget]: ...


class DNSDumpsterClient:
    def __init__(
        self,
        config: DNSDumpsterConfig,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._sleep = sleep
        self._monotonic = monotonic
        self._last_request_at: float | None = None

    def discover_domain_targets(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
    ) -> list[DiscoveredTarget]:
        api_key = os.getenv(self.config.api_key_env, "").strip()
        if not api_key:
            LOGGER.warning(
                "DNSDumpster is enabled but the environment variable %s is unset; skipping.",
                self.config.api_key_env,
            )
            return []

        targets: list[DiscoveredTarget] = []
        for page in range(1, max(self.config.max_pages, 1) + 1):
            payload = self._request_domain_page(domain, page, api_key)
            if payload is None:
                break

            page_targets = self._extract_targets_from_payload(payload, domain, resolver)
            targets.extend(page_targets)

            if page >= self.config.max_pages:
                break
            if not self._payload_has_host_records(payload):
                break

        return _deduplicate_target_list(targets)

    def _request_domain_page(
        self,
        domain: str,
        page: int,
        api_key: str,
    ) -> dict[str, Any] | None:
        self._enforce_rate_limit()

        url = f"https://api.dnsdumpster.com/domain/{parse.quote(domain, safe='')}"
        if page > 1:
            url = f"{url}?page={page}"

        http_request = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"surface-watch/{__version__}",
                "X-API-Key": api_key,
            },
            method="GET",
        )

        try:
            with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            if exc.code == 429:
                LOGGER.warning(
                    "DNSDumpster rate limit exceeded for %s; "
                    "skipping the rest of passive discovery.",
                    domain,
                )
            elif exc.code in {401, 403}:
                LOGGER.warning(
                    "DNSDumpster rejected the API key for %s; skipping passive discovery.",
                    domain,
                )
            else:
                LOGGER.warning(
                    "DNSDumpster request for %s failed with HTTP %s.",
                    domain,
                    exc.code,
                )
            return None
        except (error.URLError, TimeoutError, ValueError, OSError) as exc:
            LOGGER.warning("DNSDumpster request for %s failed: %s", domain, exc)
            return None
        finally:
            self._last_request_at = self._monotonic()

        if not isinstance(payload, dict):
            LOGGER.warning("DNSDumpster returned an unexpected payload for %s.", domain)
            return None
        return payload

    def _extract_targets_from_payload(
        self,
        payload: dict[str, Any],
        domain: str,
        resolver: dns.resolver.Resolver,
    ) -> list[DiscoveredTarget]:
        targets: list[DiscoveredTarget] = []
        for section_name, include_section in (
            ("a", self.config.include_a_records),
            ("cname", self.config.include_cname_records),
            ("mx", self.config.include_mx_hosts),
            ("ns", self.config.include_ns_hosts),
        ):
            if not include_section:
                continue
            section_targets = self._extract_section_targets(
                payload=payload,
                section_name=section_name,
                domain=domain,
                resolver=resolver,
            )
            targets.extend(section_targets)

        return _deduplicate_target_list(targets)

    def _extract_section_targets(
        self,
        *,
        payload: dict[str, Any],
        section_name: str,
        domain: str,
        resolver: dns.resolver.Resolver,
    ) -> list[DiscoveredTarget]:
        entries = payload.get(section_name, [])
        if not isinstance(entries, list):
            return []

        targets: list[DiscoveredTarget] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            hostname = normalize_hostname(
                str(entry.get("host") or entry.get("name") or entry.get("domain") or "")
            )
            if hostname is None:
                continue
            if self.config.restrict_to_domain_suffix and not _hostname_within_domain(
                hostname, domain
            ):
                continue

            ips = _extract_dnsdumpster_ips(entry)
            if ips:
                for ip in ips:
                    targets.append(
                        DiscoveredTarget(
                            hostname=hostname,
                            ip=ip,
                            source=f"dnsdumpster_{section_name}",
                            parent_domain=domain,
                            record_type=section_name.upper(),
                        )
                    )
                continue

            fallback_targets = _resolve_dnsdumpster_hostname(
                resolver=resolver,
                hostname=hostname,
                domain=domain,
                source=f"dnsdumpster_{section_name}",
                record_type=section_name.upper(),
            )
            targets.extend(fallback_targets)

        return targets

    def _payload_has_host_records(self, payload: dict[str, Any]) -> bool:
        for key in ("a", "cname", "mx", "ns"):
            section = payload.get(key, [])
            if isinstance(section, list) and section:
                return True
        return False

    def _enforce_rate_limit(self) -> None:
        if self._last_request_at is None:
            return
        elapsed = self._monotonic() - self._last_request_at
        remaining = self.config.min_interval_seconds - elapsed
        if remaining > 0:
            self._sleep(remaining)


def discover_targets(
    config: SurfaceWatchConfig,
    *,
    dnsdumpster_client: PassiveDiscoveryClient | None = None,
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
    dnsdumpster_client: PassiveDiscoveryClient | None,
) -> None:
    passive_sources = config.discovery.passive_sources
    if not passive_sources.enabled:
        return

    dnsdumpster_config = passive_sources.dnsdumpster
    if dnsdumpster_config is None or not dnsdumpster_config.enabled:
        return

    client = dnsdumpster_client or DNSDumpsterClient(dnsdumpster_config)
    for domain in config.scope.domains:
        for target in client.discover_domain_targets(domain, resolver):
            _add_target(discovered, target)


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


def _resolve_dnsdumpster_hostname(
    *,
    resolver: dns.resolver.Resolver,
    hostname: str,
    domain: str,
    source: str,
    record_type: str,
) -> list[DiscoveredTarget]:
    targets: list[DiscoveredTarget] = []
    for lookup_record_type in ("A", "AAAA"):
        for ip in _resolve_addresses(resolver, hostname, lookup_record_type):
            targets.append(
                DiscoveredTarget(
                    hostname=hostname,
                    ip=ip,
                    source=source,
                    parent_domain=domain,
                    record_type=record_type,
                )
            )
    return targets


def _extract_dnsdumpster_ips(entry: dict[str, Any]) -> list[str]:
    ip_entries = entry.get("ips", [])
    if not isinstance(ip_entries, list):
        return []

    ips: list[str] = []
    for ip_entry in ip_entries:
        if isinstance(ip_entry, dict):
            value = str(ip_entry.get("ip", "")).strip()
        else:
            value = str(ip_entry).strip()
        if value:
            ips.append(value)
    return [ip for ip in dict.fromkeys(ips)]


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
    discovered.setdefault(target.identity, target)


def _deduplicate_target_list(targets: list[DiscoveredTarget]) -> list[DiscoveredTarget]:
    deduplicated: dict[
        tuple[str | None, str | None, str, str | None, str | None],
        DiscoveredTarget,
    ] = {}
    for target in targets:
        key = (
            target.hostname,
            target.ip,
            target.source,
            target.parent_domain,
            target.record_type,
        )
        deduplicated.setdefault(key, target)
    return list(deduplicated.values())
