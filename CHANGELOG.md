# Changelog

## v0.2.0 - 2026-05-07

Scanner and baseline hardening release.

- Downgrade timeout-shaped `nmap` results to `failed` or `partial` instead of trusting zero-port host scans as clean success.
- Add automatic `-6` handling for IPv6 targets and reject invalid zero-host scan results instead of storing them as successful hosts.
- Compare new scans only against the previous successful scan with a matching config hash so config changes establish a fresh baseline.
- Expand regression coverage for timeout classification, IPv6 command construction, and baseline selection.

## v0.1.0 - 2026-05-03

Initial public release.

- Discover scan targets from configured domains, explicit hosts, explicit IPs, and optional passive providers.
- Resolve candidate hosts, scan externally reachable ports with `nmap`, and store historical results in SQLite.
- Detect meaningful changes between scans and send grouped webhook notifications to Slack, Microsoft Teams, or Discord.
- Include an `AGENTS.md` setup workflow so AI agents can guide first-time deployment with a compact questionnaire.
