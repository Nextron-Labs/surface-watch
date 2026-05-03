from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import error, parse, request

from surface_watch import __version__
from surface_watch.config import OTXConfig
from surface_watch.models import normalize_hostname
from surface_watch.passive_sources.base import PassiveHostnameCandidate

LOGGER = logging.getLogger(__name__)


class OTXClient:
    def __init__(self, config: OTXConfig) -> None:
        self.config = config

    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]:
        api_key = os.getenv(self.config.api_key_env, "").strip()
        if not api_key:
            LOGGER.warning(
                "OTX is enabled but the environment variable %s is unset; skipping.",
                self.config.api_key_env,
            )
            return []

        payload = self._request_passive_dns(domain, api_key)
        if payload is None:
            return []

        return self._extract_candidates(payload, domain)

    def _request_passive_dns(self, domain: str, api_key: str) -> dict[str, Any] | None:
        url = (
            "https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{parse.quote(domain, safe='')}/passive_dns"
        )
        http_request = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"surface-watch/{__version__}",
                "X-OTX-API-KEY": api_key,
            },
            method="GET",
        )

        try:
            with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                LOGGER.warning("OTX rejected the API key for %s; skipping.", domain)
            elif exc.code == 429:
                LOGGER.warning("OTX rate limit exceeded for %s; skipping.", domain)
            else:
                LOGGER.warning("OTX request for %s failed with HTTP %s.", domain, exc.code)
            return None
        except (error.URLError, TimeoutError, ValueError, OSError) as exc:
            LOGGER.warning("OTX request for %s failed: %s", domain, exc)
            return None

        if not isinstance(payload, dict):
            LOGGER.warning("OTX returned an unexpected payload for %s.", domain)
            return None
        return payload

    def _extract_candidates(
        self,
        payload: dict[str, Any],
        domain: str,
    ) -> list[PassiveHostnameCandidate]:
        raw_records = payload.get("passive_dns", [])
        if not isinstance(raw_records, list):
            LOGGER.warning("OTX returned malformed passive DNS data for %s.", domain)
            return []

        candidates: list[PassiveHostnameCandidate] = []
        for entry in raw_records:
            if not isinstance(entry, dict):
                continue

            hostname = _extract_otx_hostname(entry)
            if hostname is None:
                continue

            metadata = {
                key: str(entry[key])
                for key in ("first", "last", "asn", "address", "record_type")
                if key in entry and str(entry[key]).strip()
            }
            candidates.append(
                PassiveHostnameCandidate(
                    hostname=hostname,
                    source="otx",
                    parent_domain=domain,
                    metadata=metadata,
                )
            )
        return candidates


def _extract_otx_hostname(entry: dict[str, Any]) -> str | None:
    for key in ("hostname", "host", "hostname_raw", "indicator"):
        value = normalize_hostname(str(entry.get(key, "")))
        if value:
            return value
    return None
