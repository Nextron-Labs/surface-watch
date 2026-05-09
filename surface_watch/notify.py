from __future__ import annotations

import json
import logging
import os
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime
from urllib import error, request

from surface_watch import __version__
from surface_watch.config import SurfaceWatchConfig, severity_at_least
from surface_watch.models import Change

LOGGER = logging.getLogger(__name__)

SEVERITY_HEADINGS = ["critical", "high", "medium", "low", "info"]


def filter_changes_for_notification(
    changes: list[Change],
    config: SurfaceWatchConfig,
) -> list[Change]:
    filtered: list[Change] = []
    for change in changes:
        if not config.change_detection.notify_on.get(change.change_type, False):
            continue
        if not severity_at_least(change.severity, config.notifications.minimum_severity):
            continue
        filtered.append(change)
    return filtered


def send_notifications(
    *,
    changes: list[Change],
    scan_id: int,
    timestamp: datetime,
    config: SurfaceWatchConfig,
    sender: Callable[[str, str, str], bool] | None = None,
) -> list[str]:
    if not config.notifications.enabled:
        LOGGER.info("Notifications are disabled.")
        return []

    filtered_changes = filter_changes_for_notification(changes, config)
    if not filtered_changes:
        LOGGER.info("No changes matched the notification rules.")
        return []

    message = build_notification_message(
        changes=filtered_changes,
        scan_id=scan_id,
        timestamp=timestamp,
        config=config,
    )
    transport = sender or _send_to_provider

    successful_providers: list[str] = []
    for provider_name, provider_config in config.notifications.providers.items():
        if not provider_config.enabled:
            continue
        webhook_url = os.getenv(provider_config.webhook_url_env, "").strip()
        if not webhook_url:
            LOGGER.warning(
                "Notification provider %s is enabled but environment variable %s is unset.",
                provider_name,
                provider_config.webhook_url_env,
            )
            continue
        if transport(provider_name, webhook_url, message):
            successful_providers.append(provider_name)

    return successful_providers


def send_test_notification(
    *,
    config: SurfaceWatchConfig,
    sender: Callable[[str, str, str], bool] | None = None,
) -> list[str]:
    if not config.notifications.enabled:
        LOGGER.info("Notifications are disabled.")
        return []

    message = (
        "Surface Watch test notification\n\nThis confirms that webhook delivery is configured."
    )
    transport = sender or _send_to_provider
    successful_providers: list[str] = []
    for provider_name, provider_config in config.notifications.providers.items():
        if not provider_config.enabled:
            continue
        webhook_url = os.getenv(provider_config.webhook_url_env, "").strip()
        if not webhook_url:
            LOGGER.warning(
                "Notification provider %s is enabled but environment variable %s is unset.",
                provider_name,
                provider_config.webhook_url_env,
            )
            continue
        if transport(provider_name, webhook_url, message):
            successful_providers.append(provider_name)
    return successful_providers


def build_notification_message(
    *,
    changes: list[Change],
    scan_id: int,
    timestamp: datetime,
    config: SurfaceWatchConfig,
) -> str:
    lines: list[str] = ["Surface Watch detected changes", ""]

    if config.notifications.message.include_scan_id:
        lines.append(f"Scan: {scan_id}")
    if config.notifications.message.include_timestamp:
        lines.append(f"Time: {timestamp.isoformat()}")
    if (
        config.notifications.message.include_scan_id
        or config.notifications.message.include_timestamp
    ):
        lines.append("")

    if config.notifications.message.include_summary:
        lines.append("Summary:")
        summary = _build_summary(changes)
        for label, count in summary:
            lines.append(f"- {label}: {count}")
        lines.append("")

    if config.notifications.message.include_full_diff:
        grouped = defaultdict(list)
        for change in changes:
            grouped[change.severity].append(change)
        for severity in SEVERITY_HEADINGS:
            bucket = grouped.get(severity)
            if not bucket:
                continue
            lines.append(f"{severity.capitalize()}:")
            for change in bucket:
                lines.append(f"- {change.message}")
            lines.append("")

    return "\n".join(line for line in lines).strip()


def _build_summary(changes: list[Change]) -> list[tuple[str, int]]:
    counter = Counter(change.change_type for change in changes)
    service_count = sum(
        counter[change_type]
        for change_type in {
            "service_changed",
            "product_changed",
            "version_changed",
            "product_version_changed",
        }
    )
    return [
        ("New hosts", counter["new_host"]),
        ("Disappeared hosts", counter["disappeared_host"]),
        ("New open ports", counter["new_open_port"]),
        ("Closed ports", counter["closed_port"]),
        ("Service changes", service_count),
    ]


def _send_to_provider(provider_name: str, webhook_url: str, message: str) -> bool:
    if provider_name == "discord" and len(message) > 2000:
        chunks = _chunk_message(message, 2000)
        all_ok = True
        for chunk in chunks:
            if not _send_single_payload(provider_name, webhook_url, chunk):
                all_ok = False
        return all_ok
    return _send_single_payload(provider_name, webhook_url, message)


def _send_single_payload(provider_name: str, webhook_url: str, message: str) -> bool:
    payload = _payload_for_provider(provider_name, message)
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"surface-watch/{__version__}",
        },
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=10) as response:
            if 200 <= response.status < 300:
                LOGGER.info("Notification sent via %s.", provider_name)
                return True
            LOGGER.error(
                "Notification via %s returned HTTP status %s.", provider_name, response.status
            )
    except error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        LOGGER.error(
            "Notification via %s failed with HTTP error %s. Response: %s",
            provider_name,
            exc.code,
            body_text or "(no body)",
        )
    except error.URLError as exc:
        LOGGER.error("Notification via %s failed: %s", provider_name, exc.reason)
    except OSError as exc:
        LOGGER.error("Notification via %s failed: %s", provider_name, exc)
    return False


def _chunk_message(message: str, limit: int) -> list[str]:
    if len(message) <= limit:
        return [message]
    chunks: list[str] = []
    lines = message.split("\n")
    current = ""
    for line in lines:
        # Split any overly long line into limit-sized pieces
        line_pieces: list[str] = []
        while len(line) > limit:
            line_pieces.append(line[:limit])
            line = line[limit:]
        if line:
            line_pieces.append(line)

        for piece in line_pieces:
            if len(current) + len(piece) + 1 > limit and current:
                chunks.append(current)
                current = piece
            else:
                current = f"{current}\n{piece}" if current else piece
    if current:
        chunks.append(current)
    return chunks


def _payload_for_provider(provider_name: str, message: str) -> dict[str, object]:
    if provider_name == "slack":
        return {"text": message}
    if provider_name == "discord":
        return {"content": message}
    if provider_name == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Surface Watch detected changes",
            "title": "Surface Watch detected changes",
            "text": message.replace("\n", "<br/>"),
        }
    raise ValueError(f"Unsupported notification provider: {provider_name}")
