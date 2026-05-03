# AGENTS.md

This file is for AI agents that are helping a user install and fully set up `surface-watch` on a real system.

Use this workflow when the user asks you to deploy, configure, operationalize, or productionize the project. Do not jump straight to editing `config.yaml` or creating timers until you have asked the required scope and integration questions.

## Primary Rules

- Ask for authorization scope before any scan. `surface-watch` must only be used for domains, hosts, and IPs the user owns or is explicitly authorized to scan.
- Ask questions before assuming scope, schedule, notification channels, or passive discovery providers.
- Do not put secrets directly into `config.yaml` unless the user explicitly asks for that. Prefer environment variables.
- Warn the user that the default TCP scan covers `1-65535`, and a full baseline on a larger scope can take hours.
- Make it clear that discovery is helpful but incomplete. The user must provide known public hosts and public IPs that passive discovery or DNS lookups may miss.
- Current code supports passive discovery with `DNSDumpster`, `Chaos`, and `OTX`. It does not have a separate reverse-DNS account integration. If the user asks for reverse-DNS coverage, explain that limitation and collect extra explicit hosts or IPs instead.
- The current config supports domains, explicit hosts, explicit IPs, excluded hosts, and excluded IPs. It does not have a first-class CIDR or network-segment field. If the user mentions network segments, ask them to translate those into specific public IPs or hostnames to monitor.

## Required Setup Questions

Ask these questions before finalizing the system setup.

### 1. System and Runtime

Ask:

- Which operating system and version is this being installed on?
- Where should the project live on disk?
- Is `nmap` already installed and in `PATH`?
- Should scheduling use `cron` or `systemd`? If the user explicitly asked for crontab setup, stay with `cron`.
- Where should logs live?
- Where should webhook and API-key environment variables be stored: shell profile, `.env` file loaded by the scheduler, or another secrets mechanism the user already uses?

### 2. Scan Frequency and Scheduler Safety

Ask:

- How often should analysis run?
- Does the user want a conservative baseline cadence first, then a faster cadence later?

Explain:

- The default scan mode is full TCP on `1-65535`.
- A full scan can take hours on broader scopes or slower networks.
- The schedule must be slower than the observed runtime, otherwise runs can overlap and create operational noise.
- If the user is unsure, start conservatively and tighten later after one measured baseline run.

If using `cron`, prefer a command with absolute paths and a dedicated virtual environment. The README already includes an example in [README.md](README.md#running-from-cron).

### 3. Domains to Monitor

Ask:

- Which root domains should be monitored?
- Are there additional delegated domains, brand domains, regional domains, or acquisition domains that belong in scope?
- Are there any domains that are authorized but should still be excluded from routine scanning?

Map answers into:

- `scope.domains`
- `scope.excluded_hosts`
- `scope.excluded_ips`

### 4. Known Coverage Gaps Beyond Auto-Discovery

Ask:

- Which externally reachable hosts are known but might not be discovered from normal DNS expansion?
- Which public IPs should always be scanned even if they are not tied to a current hostname?
- Are there known third-party hosted assets, CDN origins, VPN gateways, mail gateways, or staging systems that should be explicitly included?
- Are there additional public network ranges the team cares about? If yes, ask for the exact public IPs or hostnames that should be monitored, because the current config is not CIDR-driven.

Explain:

- Auto-discovery is incomplete by design.
- Passive sources are additive, not complete.
- A good baseline depends on the user explicitly filling coverage gaps.

Map answers into:

- `scope.explicit_hosts`
- `scope.explicit_ips`

### 5. Passive Discovery Services

Ask:

- Which passive discovery services should be enabled?
- Does the user already have accounts and API keys for any of them?
- Do they want to keep passive discovery disabled for now and start with DNS-only discovery?

Current supported providers:

- `DNSDumpster`
- `Chaos` by ProjectDiscovery
- `OTX` by AlienVault / LevelBlue

Official setup references:

- `DNSDumpster` account and API docs: [dnsdumpster.com/developer](https://dnsdumpster.com/developer/)
- `Chaos` API-key docs: [chaos.projectdiscovery.io/docs/api-key](https://chaos.projectdiscovery.io/docs/api-key)
- `Chaos` account portal: [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io/)
- `OTX` sign-up: [otx.alienvault.com/accounts/signup/](https://otx.alienvault.com/accounts/signup/)
- `OTX` API page: [otx.alienvault.com/api](https://otx.alienvault.com/api)

Environment variables used by the example config:

- `DNSDUMPSTER_API_KEY`
- `PDCP_API_KEY`
- `OTX_API_KEY`

Agent actions:

1. Ask which providers to enable.
2. Ask where the API keys should be stored.
3. Enable only the providers the user chose.
4. Keep `discovery.passive_sources.enabled` aligned with the chosen provider set.
5. Leave rate-limit-conscious defaults in place unless the user has a reason to change them.
6. Test passive discovery with:

```bash
surface-watch discover --config config.yaml
```

If discovery returns less than the user expects, ask again for explicit hosts and IPs instead of pretending passive discovery is comprehensive.

### 6. Webhook Notifications

Ask:

- Which notification destinations should be enabled: Slack, Microsoft Teams, Discord, or multiple?
- Which channel or room should receive alerts?
- Should notifications be enabled only for higher-severity findings at first?

Official setup guides:

- Slack incoming webhooks: [api.slack.com/incoming-webhooks](https://api.slack.com/incoming-webhooks)
- Microsoft Teams webhook guidance: [learn.microsoft.com incoming webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
- Microsoft Teams Workflows-based webhook setup: [support.microsoft.com Teams webhooks](https://support.microsoft.com/en-us/office/send-messages-in-teams-using-incoming-webhooks-323660ec-12ca-40b1-a1d3-a3df47e808c4)
- Discord webhook docs: [docs.discord.com/developers/platform/webhooks](https://docs.discord.com/developers/platform/webhooks)

Environment variables used by the example config:

- `SLACK_WEBHOOK_URL`
- `TEAMS_WEBHOOK_URL`
- `DISCORD_WEBHOOK_URL`

Important note for Teams:

- Microsoft documents that Microsoft 365 Connectors are nearing deprecation. The code only needs a webhook URL, so help the user choose the current Teams path that works in their tenant, then validate with a test notification.

Agent actions:

1. Enable only the selected providers in `notifications.providers`.
2. Keep webhook secrets in environment variables.
3. Ask the user whether the default severity threshold should stay at `medium`.
4. Test delivery with:

```bash
surface-watch test-notification --config config.yaml
```

5. Do not continue until the user confirms they saw the test message or explicitly accepts postponing notification validation.

### 7. First Baselining Scan

Recommend a first manual baseline before automation starts.

Explain:

- The first successful scan becomes the baseline.
- Later runs are compared against the previous successful baseline.
- For the default full TCP range, the first run can take a long time.

Recommended sequence:

```bash
surface-watch init
$EDITOR config.yaml
surface-watch discover --config config.yaml
surface-watch scan --config config.yaml
surface-watch list-scans --config config.yaml
```

If the user already initialized the project, skip `surface-watch init` and work with the existing config.

### 8. First Notification Drill

Recommend a controlled test so the user sees what a real change notification looks like.

Before the drill:

- Back up `config.yaml`.
- Tell the user this is a temporary simulation.
- Warn that the default notification rules do not alert on every removal event.

Temporary config changes for the drill:

- Set `change_detection.notify_on.disappeared_host: true`
- Set `change_detection.notify_on.closed_port: true`
- Lower `notifications.minimum_severity` to `info` if needed, because `closed_port` defaults to `info`

Drill steps:

1. Pick one explicit public IP in `scope.explicit_ips` that is not also discovered through a monitored hostname.
2. Remove that one IP from `scope.explicit_ips`.
3. Pick one stable, known port on one authorized target.
4. Temporarily remove that port from `scanning.ports.tcp` so the next scan treats it as closed.
5. Run one scan and confirm the webhook output looks acceptable.
6. Re-add the removed IP and restore the full intended port set.
7. Restore the original notification thresholds and removal-related notify rules unless the user wants to keep them enabled.
8. Run another scan so the monitored set is back in the intended state.

Expected result:

- The drill scan should show a disappearance and a closed-port style alert if those notify rules were temporarily enabled.
- The restoration scan should usually produce corresponding reappearance or newly open results, depending on how the asset is modeled in the config and what discovery returns.

If the user does not have a clean explicit-IP-only target for this drill, use one explicit host instead and adjust expectations accordingly.

## Agent Execution Order

Use this order unless the user explicitly wants something different:

1. Confirm authorization and environment.
2. Collect domains, explicit hosts, explicit IPs, exclusions, and scheduling expectations.
3. Configure passive discovery providers, if any, and test with `discover`.
4. Configure webhook destinations and test with `test-notification`.
5. Run the first baseline scan.
6. Set up `cron` or `systemd` only after the baseline and notification path are working.
7. Offer the controlled notification drill.

## Helpful Project References

- Installation and quick start: [README.md](README.md#installation)
- Configuration example: [config/example.yaml](config/example.yaml)
- Notification setup: [README.md](README.md#notification-setup-for-slack-teams-and-discord)
- Cron example: [README.md](README.md#running-from-cron)
- Systemd timer example: [README.md](README.md#running-from-systemd-timer)
- Troubleshooting: [README.md](README.md#troubleshooting)
