# Changelog

## v0.1.0 - 2026-05-03

Initial public release.

- Discover scan targets from configured domains, explicit hosts, explicit IPs, and optional passive providers.
- Resolve candidate hosts, scan externally reachable ports with `nmap`, and store historical results in SQLite.
- Detect meaningful changes between scans and send grouped webhook notifications to Slack, Microsoft Teams, or Discord.
- Include an `AGENTS.md` setup workflow so AI agents can guide first-time deployment with a compact questionnaire.
