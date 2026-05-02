from __future__ import annotations

import dns.resolver

from surface_watch.config import DNSDumpsterConfig, parse_config_data
from surface_watch.discovery import DNSDumpsterClient, discover_targets
from surface_watch.models import DiscoveredTarget


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


class StubPassiveDiscoveryClient:
    def discover_domain_targets(
        self,
        domain: str,
        resolver: dns.resolver.Resolver,
    ) -> list[DiscoveredTarget]:
        assert domain == "example.com"
        return [
            DiscoveredTarget(
                hostname="app.example.com",
                ip="198.51.100.10",
                source="dnsdumpster_a",
                parent_domain=domain,
                record_type="A",
            ),
            DiscoveredTarget(
                hostname="skip.example.com",
                ip="198.51.100.20",
                source="dnsdumpster_a",
                parent_domain=domain,
                record_type="A",
            ),
        ]


def test_dnsdumpster_client_filters_external_hosts_by_default(monkeypatch) -> None:
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
            restrict_to_domain_suffix=True,
        ),
        payload,
    )

    targets = client.discover_domain_targets("example.com", dns.resolver.Resolver())

    assert len(targets) == 1
    assert targets[0].hostname == "app.example.com"
    assert targets[0].ip == "198.51.100.10"
    assert targets[0].source == "dnsdumpster_a"


def test_discover_targets_merges_passive_results_and_applies_exclusions(monkeypatch) -> None:
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
                    "dnsdumpster": {
                        "enabled": True,
                    },
                },
            },
        }
    )

    monkeypatch.setattr(
        "surface_watch.discovery._discover_domain_targets",
        lambda discovered, resolver, domain, config: None,
    )

    targets = discover_targets(config, dnsdumpster_client=StubPassiveDiscoveryClient())

    assert len(targets) == 1
    assert targets[0].hostname == "app.example.com"
    assert targets[0].ip == "198.51.100.10"
