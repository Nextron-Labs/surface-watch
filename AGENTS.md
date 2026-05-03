# AGENTS.md

This file is for AI agents that are helping a user install and fully set up `surface-watch` on a real system.

Use this workflow when the user asks you to deploy, configure, operationalize, or productionize the project. Do not jump straight to editing `config.yaml` or creating timers until you have asked the required scope and integration questions.

## Primary Rules

- Ask for authorization scope before any scan. `surface-watch` must only be used for domains, hosts, and IPs the user owns or is explicitly authorized to scan.
- Use a default-first workflow. Do not interrogate the user about routine environment choices that can be safely assumed.
- Ask only for the decisions that materially affect scope, schedule, passive discovery, and notifications.
- Do not put secrets directly into `config.yaml` unless the user explicitly asks for that. Prefer environment variables.
- Warn the user that the default TCP scan covers `1-65535`, and a full baseline on a larger scope can take hours.
- Make it clear that discovery is helpful but incomplete. The user must provide known public hosts and public IPs that passive discovery or DNS lookups may miss.
- Current code supports passive discovery with `DNSDumpster`, `Chaos`, and `OTX`. It does not have a separate reverse-DNS account integration. If the user asks for reverse-DNS coverage, explain that limitation and collect extra explicit hosts or IPs instead.
- The current config supports domains, explicit hosts, explicit IPs, excluded hosts, and excluded IPs. It does not have a first-class CIDR or network-segment field. If the user mentions network segments, ask them to translate those into specific public IPs or hostnames to monitor.

## Default-First Behavior

Unless the user asks for something different, use these defaults without asking:

- If the repository is already present, work from the current checkout.
- If the repository still needs to be cloned, use `~/surface-watch` as the default install location for user-managed installs.
- Use a project-local virtual environment at `.venv`.
- Use `cron` as the default scheduler.
- Use a project-local log file such as `./logs/surface-watch.log`.
- Keep `notifications.minimum_severity` at `medium`.
- Keep passive discovery disabled unless the user wants it and can provide the needed API key.
- Store webhook URLs and API keys in a project-local env file such as `surface-watch.env`, with restrictive permissions, and load that file from the scheduler.
- Detect whether `nmap` is installed instead of asking first. Only ask the user if the install path or package manager choice becomes a blocker.

Do not ask the user to confirm these defaults one by one. State them briefly, then proceed unless the user objects.

## Initial Question Limit

In the first round, ask at most five setup questions. Combine related items instead of sending a long questionnaire.

The first round should usually ask only these things:

1. Which root domains should be monitored?
2. Which known public hosts, public IPs, or important external assets should be added because auto-discovery may miss them?
3. Are there any hosts or IPs under those domains that are authorized but should still be excluded from scanning?
4. How often should scans run? Remind the user that a full `1-65535` baseline can take hours.
5. Which webhook destination should be used, and which passive discovery providers should be enabled if the user already has API keys?

If the user gives no extra hosts, IPs, exclusions, passive providers, or webhook choices, assume `none for now` and continue with a minimal baseline setup.

Do not ask about:

- install location
- `cron` versus `systemd`, unless the user asked for a different scheduler
- OS version, unless a command fails and the platform matters
- whether `nmap` is in `PATH`; check it yourself
- log location
- env-file location
- readiness for a test notification; ask for that only when you are actually about to send it

## Recommended Opening Prompt

Use something like this:

> I’ll use the default setup unless you want changes: current checkout, `.venv`, `cron`, project-local logs, secrets in `surface-watch.env`, passive discovery off by default, and notification severity at `medium`. I only need a few decisions from you before I wire it up:
> 
> 1. Which root domains should be monitored?
> 2. Which known public hosts or public IPs should be added because discovery may miss them?
> 3. Anything under that scope that should be excluded from scanning?
> 4. How often should scans run? Full `1-65535` scans can take hours, so conservative cadence is safer at first.
> 5. Which webhook destination should I configure, and do you already have any passive discovery API keys for `DNSDumpster`, `Chaos`, or `OTX`?

Keep the tone compact. Do not expand that into a multi-section interview unless the user explicitly asks for a detailed planning pass.

## Setup Questions That Still Matter

These are the only topics that normally justify questions before setup continues.

### 1. Domains to Monitor

Ask:

- Which root domains should be monitored?
- Are there additional delegated domains, brand domains, regional domains, or acquisition domains that belong in scope?

If they do not mention extra domain families, assume only the root domains they named.

Map answers into:

- `scope.domains`

### 2. Known Coverage Gaps Beyond Auto-Discovery

Ask:

- Which externally reachable hosts are known but might not be discovered from normal DNS expansion?
- Which public IPs should always be scanned even if they are not tied to a current hostname?
- Are there any exclusions that should be applied from the start?
- If the user mentions network segments, ask for the exact public IPs or hostnames that should be monitored, because the current config is not CIDR-driven.

If the user gives no additions or exclusions, assume:

- `scope.explicit_hosts: []`
- `scope.explicit_ips: []`
- no exclusions

Explain briefly:

- Auto-discovery is incomplete by design.
- Passive sources are additive, not complete.
- A good baseline depends on the user explicitly filling known coverage gaps.

Map answers into:

- `scope.explicit_hosts`
- `scope.explicit_ips`
- `scope.excluded_hosts`
- `scope.excluded_ips`

### 3. Scan Frequency and Scheduler Safety

Ask:

- How often should analysis run?

Explain briefly:

- The default scan mode is full TCP on `1-65535`.
- A full scan can take hours on broader scopes or slower networks.
- The schedule must be slower than the observed runtime, otherwise runs can overlap.

If the user is unsure, recommend a conservative default first. For example:

- first baseline run: manual
- recurring schedule after that: daily via `cron`

If using `cron`, prefer a command with absolute paths and a dedicated virtual environment. The README already includes an example in [README.md](README.md#running-from-cron).

### 4. Passive Discovery Services

Ask only if the user wants broader discovery than normal DNS plus explicit hosts and IPs, or if they already mentioned provider accounts.

Ask:

- Which passive discovery services should be enabled, if any?
- Do they already have API keys for any of them?

If the user is unsure or has no keys, default to:

- passive discovery disabled for now
- DNS-based discovery plus explicit hosts and IPs only

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
2. If the user has no provider preference or no keys, leave passive discovery disabled.
3. Enable only the providers the user chose.
4. Keep `discovery.passive_sources.enabled` aligned with the chosen provider set.
5. Leave rate-limit-conscious defaults in place unless the user has a reason to change them.
6. Test passive discovery with:

```bash
surface-watch discover --config config.yaml
```

If discovery returns less than the user expects, ask again for explicit hosts and IPs instead of pretending passive discovery is comprehensive.

### 5. Webhook Notifications

Ask:

- Which notification destination should be enabled: Slack, Microsoft Teams, Discord, or none for now?
- If a destination is selected, which channel or room should receive alerts?

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
3. Keep the default severity threshold at `medium` unless the user asks for something else.
4. Test delivery with:

```bash
surface-watch test-notification --config config.yaml
```

5. Ask for confirmation only when the test message is actually being sent, not during the initial questionnaire.
6. Do not continue until the user confirms they saw the test message or explicitly accepts postponing notification validation.

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

1. Confirm authorization and state the defaults you will use.
2. Ask the compact first-round questions about domains, known coverage gaps, exclusions, scan cadence, webhooks, and optional passive providers.
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
