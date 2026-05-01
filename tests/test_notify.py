from __future__ import annotations

from datetime import UTC, datetime

from surface_watch.config import parse_config_data
from surface_watch.models import Change
from surface_watch.notify import (
    build_notification_message,
    filter_changes_for_notification,
    send_notifications,
)


def test_filter_changes_respects_rules_and_minimum_severity() -> None:
    config = parse_config_data(
        {
            "notifications": {"minimum_severity": "high"},
            "change_detection": {"notify_on": {"new_open_port": True, "new_host": True}},
        }
    )
    changes = [
        Change(
            change_type="new_host",
            severity="medium",
            hostname="staging.example.com",
            ip="203.0.113.55",
            message="New host discovered: staging.example.com -> 203.0.113.55",
        ),
        Change(
            change_type="new_open_port",
            severity="critical",
            hostname="vpn.example.com",
            ip="203.0.113.10",
            protocol="tcp",
            port=3389,
            message="New open port tcp/3389 on vpn.example.com (203.0.113.10)",
        ),
    ]

    filtered = filter_changes_for_notification(changes, config)
    assert len(filtered) == 1
    assert filtered[0].change_type == "new_open_port"


def test_build_notification_message_includes_summary_and_grouping() -> None:
    config = parse_config_data({})
    message = build_notification_message(
        changes=[
            Change(
                change_type="new_open_port",
                severity="high",
                hostname="vpn.example.com",
                ip="203.0.113.10",
                protocol="tcp",
                port=3389,
                message="New open port tcp/3389 on vpn.example.com (203.0.113.10)",
            ),
            Change(
                change_type="new_host",
                severity="medium",
                hostname="staging.example.com",
                ip="203.0.113.55",
                message="New host discovered: staging.example.com -> 203.0.113.55",
            ),
        ],
        scan_id=12,
        timestamp=datetime(2026, 5, 1, 8, 0, tzinfo=UTC),
        config=config,
    )

    assert "Surface Watch detected changes" in message
    assert "Scan: 12" in message
    assert "- New hosts: 1" in message
    assert "High:" in message
    assert "Medium:" in message


def test_send_notifications_groups_one_message_per_scan(monkeypatch) -> None:
    config = parse_config_data(
        {
            "notifications": {
                "enabled": True,
                "minimum_severity": "medium",
                "providers": {
                    "slack": {"enabled": True, "webhook_url_env": "SLACK_WEBHOOK_URL"},
                    "teams": {"enabled": False, "webhook_url_env": "TEAMS_WEBHOOK_URL"},
                    "discord": {"enabled": False, "webhook_url_env": "DISCORD_WEBHOOK_URL"},
                },
            }
        }
    )
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.invalid/webhook")

    sent_messages: list[tuple[str, str, str]] = []

    def fake_sender(provider_name: str, webhook_url: str, message: str) -> bool:
        sent_messages.append((provider_name, webhook_url, message))
        return True

    providers = send_notifications(
        changes=[
            Change(
                change_type="new_host",
                severity="medium",
                hostname="staging.example.com",
                ip="203.0.113.55",
                message="New host discovered: staging.example.com -> 203.0.113.55",
            ),
            Change(
                change_type="new_open_port",
                severity="high",
                hostname="vpn.example.com",
                ip="203.0.113.10",
                protocol="tcp",
                port=3389,
                message="New open port tcp/3389 on vpn.example.com (203.0.113.10)",
            ),
        ],
        scan_id=21,
        timestamp=datetime(2026, 5, 1, 8, 0, tzinfo=UTC),
        config=config,
        sender=fake_sender,
    )

    assert providers == ["slack"]
    assert len(sent_messages) == 1
    assert sent_messages[0][0] == "slack"
    assert "Scan: 21" in sent_messages[0][2]
