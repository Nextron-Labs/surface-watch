from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from typing import Any
from urllib import error, parse, request

from surface_watch import __version__
from surface_watch.config import DNSDumpsterConfig
from surface_watch.models import normalize_hostname
from surface_watch.passive_sources.base import PassiveHostnameCandidate

LOGGER = logging.getLogger(__name__)


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

    def discover_domain_candidates(self, domain: str) -> list[PassiveHostnameCandidate]:
        api_key = os.getenv(self.config.api_key_env, "").strip()
        if not api_key:
            LOGGER.warning(
                "DNSDumpster is enabled but the environment variable %s is unset; skipping.",
                self.config.api_key_env,
            )
            return []

        candidates: list[PassiveHostnameCandidate] = []
        for page in range(1, max(self.config.max_pages, 1) + 1):
            payload = self._request_domain_page(domain, page, api_key)
            if payload is None:
                break

            candidates.extend(self._extract_candidates_from_payload(payload, domain))

            if page >= self.config.max_pages:
                break
            if not self._payload_has_host_records(payload):
                break

        return _deduplicate_candidate_list(candidates)

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

    def _extract_candidates_from_payload(
        self,
        payload: dict[str, Any],
        domain: str,
    ) -> list[PassiveHostnameCandidate]:
        candidates: list[PassiveHostnameCandidate] = []
        for section_name, include_section in (
            ("a", self.config.include_a_records),
            ("cname", self.config.include_cname_records),
            ("mx", self.config.include_mx_hosts),
            ("ns", self.config.include_ns_hosts),
        ):
            if not include_section:
                continue
            entries = payload.get(section_name, [])
            if not isinstance(entries, list):
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                hostname = normalize_hostname(
                    str(entry.get("host") or entry.get("name") or entry.get("domain") or "")
                )
                if hostname is None:
                    continue
                candidates.append(
                    PassiveHostnameCandidate(
                        hostname=hostname,
                        source="dnsdumpster",
                        parent_domain=domain,
                        metadata={"section": section_name},
                    )
                )

        return _deduplicate_candidate_list(candidates)

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


def _deduplicate_candidate_list(
    candidates: list[PassiveHostnameCandidate],
) -> list[PassiveHostnameCandidate]:
    deduplicated: dict[tuple[str, str, str], PassiveHostnameCandidate] = {}
    for candidate in candidates:
        key = (candidate.hostname, candidate.source, candidate.parent_domain)
        deduplicated.setdefault(key, candidate)
    return list(deduplicated.values())
