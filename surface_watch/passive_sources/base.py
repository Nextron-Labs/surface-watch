from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from surface_watch.models import normalize_hostname, normalize_optional_text


@dataclass(slots=True)
class PassiveHostnameCandidate:
    hostname: str
    source: str
    parent_domain: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_hostname = normalize_hostname(self.hostname)
        normalized_source = normalize_optional_text(self.source)
        normalized_parent_domain = normalize_hostname(self.parent_domain)
        if normalized_hostname is None:
            raise ValueError("Passive hostname candidate requires a hostname.")
        if normalized_source is None:
            raise ValueError("Passive hostname candidate requires a source.")
        if normalized_parent_domain is None:
            raise ValueError("Passive hostname candidate requires a parent domain.")

        self.hostname = normalized_hostname
        self.source = normalized_source.lower()
        self.parent_domain = normalized_parent_domain


class PassiveDiscoveryProvider(Protocol):
    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]: ...
