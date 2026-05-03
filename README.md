<p align="center">
  <img src="docs/surface-watch.png" alt="surface-watch logo">
</p>

# surface-watch

`surface-watch` monitors the authorized external attack surface of an organization over time.

It builds scan scope from known FQDNs and IPs plus automatic discovery for configured root domains, resolves candidate hosts, scans externally reachable ports with `nmap`, stores historical results in SQLite, detects meaningful changes between scans, and sends grouped webhook notifications to Slack, Microsoft Teams, or Discord.

## What the tool does

- Discovers scan targets from configured domains, explicit hosts, and explicit IPs.
- Resolves DNS data for `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `SRV` records.
- Scans externally reachable TCP ports with `nmap`.
- Stores full scan history, not just the latest result.
- Compares the current scan against the previous successful baseline.
- Detects host, IP, port, scan-status, and basic service changes.
- Sends grouped webhook notifications based on configurable change rules and severity.

## What the tool does not do

- It does not provide a web UI in v1. The tool is CLI-first.
- It does not include exploit modules.
- It does not attempt to bypass rate limits, IDS, or firewall protections.
- It does not perform aggressive probing beyond DNS resolution and `nmap`-based scanning.
- It does not run its own custom port scanner.
- It does not enable UDP scanning by default. UDP is disabled by default because it is slow and noisy.

## Legal / Authorization Warning

Use this tool only for domains, hosts, and IPs that you own or are explicitly authorized to scan.

`surface-watch` is intended for authorized external exposure monitoring of owned or approved assets. Do not use it against third-party systems without permission.

## Installation

1. Create a virtual environment.
2. Install the package.
3. Ensure `nmap` is available in `PATH`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Requirements

- Python `3.11+`
- `nmap` installed and available in `PATH`

If an AI agent is helping with first-time deployment or system setup, start with [AGENTS.md](AGENTS.md). It tells the agent which questions to ask about scope, scheduling, passive discovery, webhook setup, baselining, and validation.

Example on macOS with Homebrew:

```bash
brew install nmap
```

Example on Debian/Ubuntu:

```bash
sudo apt-get install nmap
```

## Quick Start

1. Create a config and initialize the database.
2. Edit the config to match your authorized scope.
3. Run discovery first and review the discovered host list.
4. Add exclusions for anything that is not authorized for scanning.
5. Run a baseline scan.
6. Run the next scan later to detect changes.

```bash
surface-watch init
$EDITOR config.yaml
surface-watch discover --config config.yaml
surface-watch scan --config config.yaml
surface-watch list-scans --config config.yaml
surface-watch show-changes --config config.yaml --scan-id 2
```

## Configuration Example

An example file is included at [config/example.yaml](config/example.yaml).

Typical configuration:

```yaml
project:
  name: "Example External Surface Watch"
  database_path: "./surface-watch.sqlite3"
  log_level: "INFO"

scope:
  domains:
    - "example.com"
  explicit_hosts:
    - "vpn.example.com"
  explicit_ips:
    - "203.0.113.10"
  excluded_hosts:
    - "do-not-scan.example.com"
  excluded_ips:
    - "203.0.113.99"

discovery:
  enabled: true
  passive_sources:
    enabled: false
    dnsdumpster:
      enabled: false
      api_key_env: "DNSDUMPSTER_API_KEY"
      min_interval_seconds: 2.0
      max_pages: 1
      restrict_to_domain_suffix: true
    chaos:
      enabled: false
      api_key_env: "PDCP_API_KEY"
    otx:
      enabled: false
      api_key_env: "OTX_API_KEY"

scanning:
  enabled: true
  nmap_path: "nmap"
  scan_mode: "full_tcp"
  ports:
    tcp: "1-65535"
    udp: ""

notifications:
  enabled: true
  minimum_severity: "medium"
  providers:
    slack:
      enabled: true
      webhook_url_env: "SLACK_WEBHOOK_URL"
```

## How Discovery Works

`surface-watch` has two ways to define scan targets:

1. Manual scope definition with explicit FQDNs and IP addresses.
2. Automatic discovery for configured root domains.

Manual scope definition is useful when you already know the important assets. Automatic discovery is essential in most real-world use cases because most teams do not have a complete, current inventory of every externally visible hostname under their domains.

Normal DNS lookups rarely show the full external picture. Many hosts are only visible through passive DNS, historical DNS data, certificate transparency, and other external intelligence sources. Discovery is therefore one of the central parts of `surface-watch`, not a minor add-on.

Current discovery inputs:

- configured domains
- explicit hosts
- explicit IPs
- optional MX, NS, and SRV-derived hosts
- optional passive discovery providers: DNSDumpster, ProjectDiscovery Chaos, and AlienVault / LevelBlue OTX

Passive discovery is especially important because the default goal is not to guess hostnames with noisy brute force. DNS brute forcing is intentionally not the preferred default path because it is noisy, expensive, incomplete, and can lead to rate limiting or blocking. Passive intelligence sources provide broader coverage with less direct probing.

Passive provider behavior:

- Passive providers are optional and can be enabled independently.
- Multiple passive providers can be enabled in the same run.
- Each enabled provider is queried for each configured root domain.
- Passive results are treated as candidate hostnames, not confirmed live assets.
- Candidate hostnames are normalized before merge, including wildcard cleanup such as `*.app.example.com`.
- Out-of-scope hostnames are dropped.
- Results from all providers are merged and deduplicated before scanning.
- A hostname reported by multiple providers is scanned only once per unique resolved target.
- Source attribution is preserved so you can still see which provider or providers reported a hostname.
- Exclusions are applied after discovery completes and before scanning starts.
- Unresolvable passive candidates are not scanned.
- One passive provider failing does not discard results from the other successful providers.

## Passive Discovery Providers

`surface-watch` supports three optional passive discovery providers. All are disabled by default and require an API key.

- `DNSDumpster`: DNS and attack-surface research service for finding domain-related DNS records, infrastructure, and related hosts. Website: [dnsdumpster.com](https://dnsdumpster.com/). Account and API setup: [dnsdumpster.com/developer](https://dnsdumpster.com/developer/). Environment variable: `DNSDUMPSTER_API_KEY`.
- `ProjectDiscovery Chaos`: Internet-scale DNS dataset and API for subdomain discovery from ProjectDiscovery. Website: [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/). Account and API-key setup: [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io/) and [Chaos API key docs](https://chaos.projectdiscovery.io/docs/api-key). Environment variable: `PDCP_API_KEY`.
- `AlienVault / LevelBlue OTX`: Open threat-intelligence community and API that can contribute passive DNS and hostname data useful for broader hostname discovery. Website: [LevelBlue Open Threat Exchange](https://levelblue.com/open-threat-exchange) and [OTX portal](https://otx.alienvault.com/). Account setup: [OTX sign-up](https://otx.alienvault.com/accounts/signup/). Environment variable: `OTX_API_KEY`.

`surface-watch` does not log API key values.

The tool does not assume one hostname maps to one IP, or one IP maps to one hostname. Discovery builds a candidate set first, then scanning operates only on the final unique in-scope target set.

## First Discovery Run and Scope Review

Treat the first automated discovery run as a scope-building and scope-cleanup step.

Passive discovery can find hostnames under your domain that point to systems operated by third parties, SaaS platforms, CDNs, email providers, documentation platforms, status page providers, hosting providers, customer portals, or other external services.

Common examples:

- `documentation.example.com` on a hosted documentation platform
- `status.example.com` on a status page provider
- `shop.example.com` on an e-commerce provider
- `support.example.com` on a ticketing or SaaS platform
- `blog.example.com` on an external CMS
- `assets.example.com` on a CDN
- mail-related hosts operated by an email provider

Those systems may carry your domain name, but they may not be owned, operated, or security-managed by you.

Important review rules:

- Passive discovery results are candidate assets, not automatically confirmed assets.
- Passive records may be stale, wrong, incomplete, or no longer active.
- Some discovered hosts may not be in your operational responsibility.
- A third-party provider may already have its own security monitoring and scanning restrictions.
- The provider's terms of service may prohibit port scanning or automated scanning.
- Review the discovered host list after the first run.
- Add exclusions for any host or IP that should not be scanned.
- Enable regular recurring scans only after the scope has been reviewed and cleaned up.
- You are responsible for ensuring that every scanned system is authorized for scanning.

## How Scanning Works

Scanning is performed by calling external `nmap` via `subprocess`.

For TCP scans, the command is built around:

- `-Pn`
- `--open`
- `-p <configured ports>`
- `-sS` when running as root on Linux/macOS, otherwise `-sT`
- `-sV` when service detection is enabled
- `--version-intensity <value>`
- `-T<template>`
- `--host-timeout <value>`
- `-oX -`

`surface-watch` parses `nmap` XML output into internal structured models before storing or diffing results.

If one host fails, the run continues for the remaining hosts. A run is only marked fully failed when all host scans fail.

## Why Full TCP Scanning Is the Default

The default TCP range is `1-65535`.

This is intentional:

- a limited port preset can miss newly exposed services
- the tool is meant to maintain a reliable external baseline over time
- meaningful exposure changes often happen on non-standard ports

The goal is not to be aggressive. The goal is to maintain a stable, repeatable baseline of externally exposed TCP services and detect meaningful drift.

UDP scanning is disabled by default because it is slow and noisy.

## How Scan History Is Stored

History is stored in SQLite. Each run creates a scan record.

The database stores:

- `scans`: run metadata and final status
- `targets`: discovered targets for that run
- `host_results`: per-host or per-IP scan outcome
- `port_findings`: open port and service data
- `changes`: detected differences for that run

This makes it possible to compare scans later, inspect previous baselines, and review what changed over time.

## How Change Detection Works

The default comparison baseline is the previous successful scan.

Detection is based on normalized internal tuples:

- host identity: `hostname + ip` where available
- port identity: `ip + protocol + port`
- service identity: `ip + protocol + port + service/product/version`

Important behavior:

- failed scans are stored
- partial scans are stored
- comparisons default to the previous successful scan
- empty and missing service fields are treated consistently to reduce false noise
- missing version strings do not automatically produce version-change events

## Supported Change Types

Implemented in v1:

- `new_host`
- `disappeared_host`
- `new_ip_for_host`
- `removed_ip_from_host`
- `host_scan_failed`
- `host_scan_recovered`
- `new_open_port`
- `closed_port`
- `service_changed`
- `product_changed`
- `version_changed`
- `product_version_changed`

Defined as possible future categories:

- `cname_changed`
- `mx_changed`
- `ns_changed`
- `srv_record_changed`
- `host_timeout`
- `host_unreachable`
- `host_reachable_again`
- `port_state_changed`
- `new_protocol_on_host`
- `banner_changed`
- `tls_detected`
- `tls_removed`
- `certificate_subject_changed`
- `certificate_issuer_changed`
- `certificate_expiry_changed`
- `http_title_changed`
- `http_server_header_changed`
- `http_redirect_changed`
- `risky_port_exposed`
- `admin_port_exposed`
- `database_port_exposed`
- `remote_access_port_exposed`

## Notification Setup for Slack, Teams, and Discord

Webhook URLs are not stored directly in config by default. The config references environment variable names instead.

Example:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export TEAMS_WEBHOOK_URL="https://..."
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

Then enable the provider in `config.yaml`.

Notifications are:

- filtered by `change_detection.notify_on`
- filtered by `notifications.minimum_severity`
- grouped into one message per scan
- skipped when no change qualifies

`risk_policy` can raise severity for specific ports such as `3389`, `5900`, `9200`, `27017`, `3306`, and similar exposures. This makes notifications more useful than treating every newly open port equally.

Service and version changes can be noisy and are therefore not notification-worthy by default.

Use the built-in test command:

```bash
surface-watch test-notification --config config.yaml
```

## Running from cron

Example cron entry:

```cron
MAILTO=""
15 * * * * cd /opt/surface-watch && /opt/surface-watch/.venv/bin/surface-watch scan --config /opt/surface-watch/config.yaml >> /var/log/surface-watch.log 2>&1
```

Use a dedicated virtual environment and absolute paths in cron jobs.

## Running from systemd timer

Example service unit:

```ini
[Unit]
Description=surface-watch scan

[Service]
Type=oneshot
WorkingDirectory=/opt/surface-watch
EnvironmentFile=/opt/surface-watch/surface-watch.env
ExecStart=/opt/surface-watch/.venv/bin/surface-watch scan --config /opt/surface-watch/config.yaml
```

Example timer unit:

```ini
[Unit]
Description=Run surface-watch every hour

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

## Troubleshooting

`nmap not found`

- install `nmap`
- confirm `nmap` is in `PATH`
- or set `scanning.nmap_path` explicitly

No notifications sent

- confirm the provider is enabled in config
- confirm the referenced environment variable is set
- run `surface-watch test-notification --config config.yaml`

DNSDumpster passive discovery returns no results

- confirm `discovery.passive_sources.enabled: true`
- confirm `discovery.passive_sources.dnsdumpster.enabled: true`
- confirm the `DNSDUMPSTER_API_KEY` environment variable is set
- remember that free-tier use is rate-limited to one request every two seconds and limited in returned records
- if you need external MX or NS hosts, check whether `restrict_to_domain_suffix` is filtering them on purpose

Chaos passive discovery returns no results

- confirm `discovery.passive_sources.enabled: true`
- confirm `discovery.passive_sources.chaos.enabled: true`
- confirm the `PDCP_API_KEY` environment variable is set

OTX passive discovery returns no results

- confirm `discovery.passive_sources.enabled: true`
- confirm `discovery.passive_sources.otx.enabled: true`
- confirm the `OTX_API_KEY` environment variable is set

Passive discovery found unexpected hosts

- this can happen with historical passive DNS or third-party hosted subdomains
- review the discovered host list before enabling regular scans
- add exclusions for anything not owned or not authorized for scanning

Unexpected service-change noise

- this can happen with `nmap -sV` fingerprints
- keep service-related notifications disabled unless they matter to your workflow

No previous scan to compare against

- the first successful run becomes the baseline
- change detection starts on later runs

Permission differences for `-sS`

- SYN scan is used only when the effective user is root on Linux/macOS
- otherwise `surface-watch` falls back to `-sT`

## Development / Tests

Install dev dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Run checks:

```bash
ruff check .
pytest
```

Useful commands:

```bash
surface-watch discover --config config.yaml
surface-watch scan --config config.yaml
surface-watch diff --config config.yaml --scan-id 2 --previous-scan-id 1
surface-watch list-scans --config config.yaml
surface-watch show-changes --config config.yaml --scan-id 2
```
