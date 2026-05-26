# Cygor Documentation

Cygor is a modular asset-discovery framework that combines scanning, parsing, enrichment, credential testing, and protocol-specific enumeration into a single workflow — with a FastAPI Web UI that turns raw output into a triagable command center.

This directory is the user-facing documentation. Each `.md` file below is a complete topic; GitHub renders them in the file browser, so you can read them directly here on github.com. The same pages are served by the running web UI at `/docs`.

## Getting Started

- **[Installation Guide](Installation-Guide.md)** — pipx, source, Docker, and the external tools each module wraps
- **[First Scan Tutorial](First-Scan-Tutorial.md)** — end-to-end from scope file to Web UI
- **[Setting Up Workspaces](Setting-Up-Workspaces.md)** — separate engagements cleanly
- **[Web UI Quick Start](Web-UI-Quick-Start.md)** — launching, navigating, loading results

## Core Workflow

- **[Scanning Guide](Scanning-Guide.md)** — Masscan / Naabu / Nmap orchestration via `cygor scan`
- **[Parsing Results](Parsing-Results.md)** — `cygor parse` turns Nmap output into per-service hostlists
- **[Enumeration Modules](Enumeration-Modules.md)** — the 11 built-in modules (lockon, webenum, smb/nfs/rpc/ldap/snmp/dns/ftp/smtp explorers, dbprobe)
- **[Credential Testing](Credential-Testing.md)** — `cygor credrecon` across protocols
- **[IOC Enrichment](IOC-Enrichment.md)** — Shodan / VirusTotal / crt.sh
- **[Device Fingerprinting](Device-Fingerprinting.md)** — Huginn-Muninn / Satori / OUI lookups

## Extending Cygor

- **[Plugin Development](Plugin-Development.md)** — write your own modules; they appear under `cygor enum --list` and in the Web UI alongside built-ins
- **[Data Ingestion & Web UI](Data-Ingestion-And-Web-UI.md)** — the `cygor-result.json` schema, how modules emit it, how the Web UI loads it, and how the next-steps engine turns rows into findings
- **[CLI Reference](CLI-Reference.md)** — every subcommand in one place

## Deployment

- **[Docker Deployment Guide](Docker-Deployment-Guide.md)** — Compose, env vars, ports, volumes

## Troubleshooting

- **[Common Issues](Common-Issues.md)** — installation, scanning, web UI, database, Docker, performance

## Contributing

- **[Contributing](Contributing.md)** — how to edit / add pages here

---

Cygor is a security research and educational framework intended only for environments where you have explicit, written authorization. See [LICENSE](../LICENSE) and the [Disclaimer in the README](../README.md#disclaimer-) for the full terms.
