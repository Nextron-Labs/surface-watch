from __future__ import annotations

from urllib import error

from surface_watch.config import ChaosConfig, DNSDumpsterConfig, OTXConfig, parse_config_data
from surface_watch.discovery import discover_targets
from surface_watch.models import DiscoveredTarget
from surface_watch.passive_sources.base import PassiveHostnameCandidate
from surface_watch.passive_sources.chaos import ChaosClient
from surface_watch.passive_sources.dnsdumpster import DNSDumpsterClient
from surface_watch.passive_sources.otx import OTXClient


class FakeDNSDumpsterClient(DNSDumpsterClient):
    def __init__(self, config: DNSDumpsterConfig, payload: dict[str, object]) -> None:
        super().__init__(config=config, sleep=lambda _: None, monotonic=lambda: 0.0)
        self.payload = payload

    def _request_domain_page(
        self,
        domain: str,
        page: int,
        api_key: str,
    ) -> dict[str, object] | None:
        assert domain == "example.com"
        assert api_key == "test-key"
        return self.payload if page == 1 else None


class FakeChaosClient(ChaosClient):
    def __init__(self, config: ChaosConfig, payload: dict[str, object]) -> None:
        super().__init__(config)
        self.payload = payload

    def _request_subdomains(self, domain: str, api_key: str) -> dict[str, object] | None:
        assert domain == "example.com"
        assert api_key == "test-key"
        return self.payload


class FakeOTXClient(OTXClient):
    def __init__(self, config: OTXConfig, payload: dict[str, object]) -> None:
        super().__init__(config)
        self.payload = payload

    def _request_passive_dns(self, domain: str, api_key: str) -> dict[str, object] | None:
        assert domain == "example.com"
        assert api_key == "test-key"
        return self.payload


class StaticPassiveProvider:
    def __init__(self, *candidates: PassiveHostnameCandidate) -> None:
        self.candidates = list(candidates)

    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]:
        assert domain == "example.com"
        return list(self.candidates)


class FailingPassiveProvider:
    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]:
        assert domain == "example.com"
        raise RuntimeError("provider exploded")


def test_dnsdumpster_client_extracts_hostname_candidates(monkeypatch) -> None:
    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "test-key")
    payload = {
        "a": [
            {
                "host": "app.example.com",
                "ips": [{"ip": "198.51.100.10"}],
            }
        ],
        "mx": [
            {
                "host": "example-com.mail.protection.outlook.com",
                "ips": [{"ip": "198.51.100.20"}],
            }
        ],
    }
    client = FakeDNSDumpsterClient(
        DNSDumpsterConfig(
            enabled=True,
            include_a_records=True,
            include_mx_hosts=True,
        ),
        payload,
    )

    candidates = client.discover_domain_candidates("example.com")

    assert [candidate.hostname for candidate in candidates] == [
        "app.example.com",
        "example-com.mail.protection.outlook.com",
    ]
    assert all(candidate.source == "dnsdumpster" for candidate in candidates)


def test_chaos_client_skips_when_api_key_is_missing(monkeypatch) -> None:
    monkeypatch.delenv("PDCP_API_KEY", raising=False)

    client = FakeChaosClient(ChaosConfig(enabled=True), {"subdomains": ["vpn"]})

    assert client.discover_domain_candidates("example.com") == []


def test_chaos_client_handles_empty_and_malformed_responses(monkeypatch) -> None:
    monkeypatch.setenv("PDCP_API_KEY", "test-key")

    empty_client = FakeChaosClient(ChaosConfig(enabled=True), {"subdomains": []})
    malformed_client = FakeChaosClient(ChaosConfig(enabled=True), {"subdomains": {}})

    assert empty_client.discover_domain_candidates("example.com") == []
    assert malformed_client.discover_domain_candidates("example.com") == []


def test_chaos_client_handles_request_failures(monkeypatch) -> None:
    monkeypatch.setenv("PDCP_API_KEY", "test-key")

    def raise_url_error(*args: object, **kwargs: object) -> object:
        raise error.URLError("timeout")

    monkeypatch.setattr("surface_watch.passive_sources.chaos.request.urlopen", raise_url_error)

    client = ChaosClient(ChaosConfig(enabled=True))

    assert client.discover_domain_candidates("example.com") == []


def test_otx_client_handles_missing_key_empty_and_malformed_responses(monkeypatch) -> None:
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    missing_key_client = FakeOTXClient(OTXConfig(enabled=True), {"passive_dns": []})
    assert missing_key_client.discover_domain_candidates("example.com") == []

    monkeypatch.setenv("OTX_API_KEY", "test-key")
    empty_client = FakeOTXClient(OTXConfig(enabled=True), {"passive_dns": []})
    malformed_client = FakeOTXClient(OTXConfig(enabled=True), {"passive_dns": {}})

    assert empty_client.discover_domain_candidates("example.com") == []
    assert malformed_client.discover_domain_candidates("example.com") == []


def test_discover_targets_ignores_passive_providers_when_disabled(monkeypatch) -> None:
    config = parse_config_data(
        {
            "scope": {"domains": ["example.com"]},
            "discovery": {
                "enabled": True,
                "passive_sources": {
                    "enabled": False,
                },
            },
        }
    )

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: None,
    )

    targets = discover_targets(
        config,
        passive_providers=[
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="chaos",
                    parent_domain="example.com",
                )
            )
        ],
    )

    assert targets == []


def test_discover_targets_merges_multiple_passive_providers_and_preserves_sources(
    monkeypatch,
) -> None:
    config = parse_config_data(
        {
            "scope": {
                "domains": ["example.com"],
                "excluded_hosts": ["skip.example.com"],
            },
            "discovery": {
                "enabled": True,
                "passive_sources": {
                    "enabled": True,
                },
            },
        }
    )

    address_map = {
        "mail.example.com": ["198.51.100.20"],
        "portal.example.com": ["198.51.100.30"],
        "skip.example.com": ["198.51.100.40"],
        "vpn.example.com": ["198.51.100.10"],
    }

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: None,
    )
    monkeypatch.setattr(
        "surface_watch.discovery._resolve_addresses",
        lambda resolver, hostname, record_type: address_map.get(hostname, [])
        if record_type == "A"
        else [],
    )

    targets = discover_targets(
        config,
        passive_providers=[
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="dnsdumpster",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="mail.example.com",
                    source="dnsdumpster",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="skip.example.com",
                    source="dnsdumpster",
                    parent_domain="example.com",
                ),
            ),
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="mail.example.com",
                    source="chaos",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="portal.example.com",
                    source="chaos",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="*.vpn.example.com",
                    source="chaos",
                    parent_domain="example.com",
                ),
            ),
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="otx",
                    parent_domain="example.com",
                )
            ),
        ],
    )

    assert [target.hostname for target in targets] == [
        "mail.example.com",
        "portal.example.com",
        "vpn.example.com",
    ]
    assert [target.ip for target in targets] == [
        "198.51.100.20",
        "198.51.100.30",
        "198.51.100.10",
    ]
    sources_by_host = {target.hostname: target.sources for target in targets}
    assert sources_by_host["mail.example.com"] == ("chaos", "dnsdumpster")
    assert sources_by_host["portal.example.com"] == ("chaos",)
    assert sources_by_host["vpn.example.com"] == ("chaos", "dnsdumpster", "otx")
    assert all(target.parent_domains == ("example.com",) for target in targets)


def test_discover_targets_filters_out_of_scope_and_unresolvable_passive_hosts(monkeypatch) -> None:
    config = parse_config_data(
        {
            "scope": {"domains": ["example.com"]},
            "discovery": {
                "enabled": True,
                "passive_sources": {
                    "enabled": True,
                },
            },
        }
    )

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: None,
    )
    monkeypatch.setattr(
        "surface_watch.discovery._resolve_addresses",
        lambda resolver, hostname, record_type: ["198.51.100.10"]
        if hostname == "vpn.example.com" and record_type == "A"
        else [],
    )

    targets = discover_targets(
        config,
        passive_providers=[
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="chaos",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="stale.example.com",
                    source="otx",
                    parent_domain="example.com",
                ),
                PassiveHostnameCandidate(
                    hostname="api.other-example.net",
                    source="dnsdumpster",
                    parent_domain="example.com",
                ),
            )
        ],
    )

    assert len(targets) == 1
    assert targets[0].hostname == "vpn.example.com"
    assert targets[0].ip == "198.51.100.10"


def test_discover_targets_continues_when_one_provider_fails(monkeypatch) -> None:
    config = parse_config_data(
        {
            "scope": {"domains": ["example.com"]},
            "discovery": {
                "enabled": True,
                "passive_sources": {
                    "enabled": True,
                },
            },
        }
    )

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: None,
    )
    monkeypatch.setattr(
        "surface_watch.discovery._resolve_addresses",
        lambda resolver, hostname, record_type: ["198.51.100.10"]
        if hostname == "vpn.example.com" and record_type == "A"
        else [],
    )

    targets = discover_targets(
        config,
        passive_providers=[
            FailingPassiveProvider(),
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="otx",
                    parent_domain="example.com",
                )
            ),
        ],
    )

    assert len(targets) == 1
    assert targets[0].hostname == "vpn.example.com"
    assert targets[0].sources == ("otx",)


def test_discover_targets_merges_with_active_dns_source_attribution(monkeypatch) -> None:
    config = parse_config_data(
        {
            "scope": {"domains": ["example.com"]},
            "discovery": {
                "enabled": True,
                "passive_sources": {
                    "enabled": True,
                },
            },
        }
    )

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: discovered.setdefault(
            ("vpn.example.com", "198.51.100.10"),
            DiscoveredTarget(
                hostname="vpn.example.com",
                ip="198.51.100.10",
                source="domain_a",
                parent_domain="example.com",
                record_type="A",
            ),
        ),
    )
    monkeypatch.setattr(
        "surface_watch.discovery._resolve_addresses",
        lambda resolver, hostname, record_type: ["198.51.100.10"]
        if hostname == "vpn.example.com" and record_type == "A"
        else [],
    )

    targets = discover_targets(
        config,
        passive_providers=[
            StaticPassiveProvider(
                PassiveHostnameCandidate(
                    hostname="vpn.example.com",
                    source="chaos",
                    parent_domain="example.com",
                )
            )
        ],
    )

    assert len(targets) == 1
    assert targets[0].hostname == "vpn.example.com"
    assert targets[0].sources == ("domain_a", "chaos")
