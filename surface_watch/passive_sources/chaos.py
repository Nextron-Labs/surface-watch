from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import error, parse, request

from surface_watch import __version__
from surface_watch.config import ChaosConfig
from surface_watch.passive_sources.base import PassiveHostnameCandidate

LOGGER = logging.getLogger(__name__)


class ChaosClient:
    def __init__(self, config: ChaosConfig) -> None:
        self.config = config

    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]:
        api_key = os.getenv(self.config.api_key_env, "").strip()
        if not api_key:
            LOGGER.warning(
                "Chaos is enabled but the environment variable %s is unset; skipping.",
                self.config.api_key_env,
            )
            return []

        payload = self._request_subdomains(domain, api_key)
        if payload is None:
            return []

        return self._extract_candidates(payload, domain)

    def _request_subdomains(self, domain: str, api_key: str) -> dict[str, Any] | None:
        url = f"https://dns.projectdiscovery.io/dns/{parse.quote(domain, safe='')}/subdomains"
        http_request = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": api_key,
                "User-Agent": f"surface-watch/{__version__}",
            },
            method="GET",
        )

        try:
            with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                LOGGER.warning("Chaos rejected the API key for %s; skipping.", domain)
            elif exc.code == 429:
                LOGGER.warning("Chaos rate limit exceeded for %s; skipping.", domain)
            else:
                LOGGER.warning("Chaos request for %s failed with HTTP %s.", domain, exc.code)
            return None
        except (error.URLError, TimeoutError, ValueError, OSError) as exc:
            LOGGER.warning("Chaos request for %s failed: %s", domain, exc)
            return None

        if not isinstance(payload, dict):
            LOGGER.warning("Chaos returned an unexpected payload for %s.", domain)
            return None
        return payload

    def _extract_candidates(
        self,
        payload: dict[str, Any],
        domain: str,
    ) -> list[PassiveHostnameCandidate]:
        subdomains = payload.get("subdomains", [])
        if not isinstance(subdomains, list):
            LOGGER.warning("Chaos returned malformed subdomain data for %s.", domain)
            return []

        candidates: list[PassiveHostnameCandidate] = []
        for item in subdomains:
            if not isinstance(item, str):
                continue
            candidate_hostname = _qualify_subdomain(domain, item)
            if candidate_hostname is None:
                continue
            candidates.append(
                PassiveHostnameCandidate(
                    hostname=candidate_hostname,
                    source="chaos",
                    parent_domain=domain,
                )
            )
        return candidates


def _qualify_subdomain(domain: str, subdomain: str) -> str | None:
    normalized = subdomain.strip().rstrip(".")
    if not normalized:
        return None
    if normalized == "*":
        return f"*.{domain}"
    if normalized.endswith(domain):
        return normalized
    return f"{normalized}.{domain}"
