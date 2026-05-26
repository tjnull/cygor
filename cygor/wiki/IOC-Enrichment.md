# IOC Enrichment

Comprehensive guide to Cygor's passive reconnaissance and threat intelligence enrichment capabilities.

## Overview

Cygor Enrich performs async parallel enrichment of Indicators of Compromise (IOCs) -- IPs, domains, and hashes -- against multiple threat intelligence sources. It features configurable timeouts, exponential backoff retry logic, per-source rate limiting, and real-time streaming output.

## Basic Syntax

```bash
cygor enrich <IOC or file> [options]
```

## Enriching IOCs

### Single IOC

```bash
# Enrich a single IP address
cygor enrich 192.168.1.1

# Enrich a domain
cygor enrich example.com

# Enrich a file hash
cygor enrich 44d88612fea8a8f36de82e1278abb02f
```

### Bulk Enrichment from File

Provide a file with one IOC per line.

```bash
# Enrich all IOCs in a file
cygor enrich iocs.txt

# Using the explicit input flag
cygor enrich -i iocs.txt
```

### Selecting Specific Sources

By default, all configured sources are queried. Use `--sources` to limit to specific ones.

```bash
# Use only Shodan and VirusTotal
cygor enrich 192.168.1.1 --sources shodan vt

# Use only AbuseIPDB
cygor enrich iocs.txt --sources abuseipdb

# Use only GreyNoise and Censys
cygor enrich 10.0.0.1 --sources greynoise censys
```

## Supported Intelligence Sources

| Source | Key | Env Variable | API Key Required | IOC Types |
|---|---|---|---|---|
| Shodan | `shodan` | `SHODAN_API_KEY` | Yes | IP, Domain |
| VirusTotal | `vt` / `virustotal` | `VIRUSTOTAL_API_KEY` | Yes | IP, Domain, Hash |
| AbuseIPDB | `abuseipdb` | `ABUSEIPDB_API_KEY` | Yes | IP, Domain |
| LevelBlue OTX (AlienVault) | `otx` | `OTX_API_KEY` | Yes | IP, Domain |
| URLScan.io | `urlscan` | `URLSCAN_API_KEY` | Yes | IP, Domain |
| Censys | `censys` | `CENSYS_API_ID` | Yes (format: `API_ID:SECRET`) | IP, Domain |
| GreyNoise | `greynoise` | `GREYNOISE_API_KEY` | Yes | IP |
| Spur | `spur` | `SPUR_API_KEY` | Yes | IP |
| Dehashed | `dehashed` | `DEHASHED_API_KEY` | Yes (format: `email:api_key`) | Domain |
| MalwareBazaar (abuse.ch) | `bazaar` | `BAZAAR_API_KEY` | Optional | Hash |
| Prospeo.io | `prospeo` | `PROSPEO_API_KEY` | Yes | Domain |
| Wayback Machine | `wayback` | -- | No | Domain |
| Common Crawl | `commoncrawl` | -- | No | Domain |

## API Key Configuration

Cygor stores API keys in `~/.cygor/enrich_config.json` with restrictive file permissions (owner read/write only). Keys can also be set via environment variables.

### Managing Keys with config-manager

```bash
# Set an API key
cygor enrich config-manager set shodan YOUR_API_KEY

# List all configured keys
cygor enrich config-manager list

# Test all configured keys against their APIs
cygor enrich config-manager test

# Show config-manager help
cygor enrich config-manager --help
```

### Quick Start

1. Configure at least one API key:
   ```bash
   cygor enrich config-manager set shodan YOUR_KEY
   ```
2. Verify the key works:
   ```bash
   cygor enrich config-manager test
   ```
3. Run your first enrichment:
   ```bash
   cygor enrich 8.8.8.8
   ```

## Output Formats

Cygor supports four output formats via the `--format` flag.

```bash
# Plain text (default) - human-readable console output
cygor enrich 192.168.1.1 --format text

# JSON - structured output for automation
cygor enrich 192.168.1.1 --format json -o results.json

# CSV - tabular format for spreadsheets
cygor enrich iocs.txt --format csv -o results.csv

# XML - for integration with other tools
cygor enrich iocs.txt --format xml -o results.xml
```

Results are saved to the active workspace under `enrich/<timestamp>/` when a workspace is active. Use `-o` to specify a custom output path.

## Pentester Feature Options

### Subdomain Extraction

Extract subdomains discovered via Wayback Machine and Common Crawl results.

```bash
cygor enrich example.com --extract-subdomains --sources wayback commoncrawl
```

### Credential Spray Lists

Generate credential spray lists from Dehashed results for use with credrecon.

```bash
cygor enrich example.com --spray-lists --sources dehashed
```

## Advanced Options

### Timeout and Retry Configuration

```bash
# Set per-source timeout to 60 seconds (default: 30)
cygor enrich 192.168.1.1 --timeout 60

# Set max retry attempts to 5 (default: 3)
cygor enrich 192.168.1.1 --retries 5
```

Retries use exponential backoff (base delay 2 seconds, max 60 seconds) and automatically retry on HTTP status codes 429, 500, 502, 503, and 504.

### Sequential Mode

If async parallel enrichment causes issues, fall back to sequential processing.

```bash
cygor enrich iocs.txt --sequential
```

### Custom Config File

Point to an alternate config file instead of the default `~/.cygor/enrich_config.json`.

```bash
cygor enrich 192.168.1.1 --config /path/to/custom_config.json
```

## Web UI Enrichment

The Cygor web interface provides an enrichment view for running and reviewing IOC enrichment interactively.

- Navigate to **Tasks > Enrich IOCs** to start a new enrichment job
- Enter IOCs manually or upload a file
- Select which sources to query
- View results in the task dashboard with filtering by task type

Enrichment tasks can also be scheduled for recurring execution via the **Schedule** page by selecting the **Enrich** task type.

## Rate Limits

Cygor respects per-source rate limits based on free tier API quotas:

| Source | Requests/Minute |
|---|---|
| VirusTotal | 4 |
| Censys | 10 |
| Dehashed | 10 |
| Common Crawl | 10 |
| Wayback Machine | 15 |
| GreyNoise | 30 |
| Spur | 30 |
| MalwareBazaar | 30 |
| Prospeo | 30 |
| Shodan | 60 |
| AbuseIPDB | 60 |
| OTX | 60 |
| URLScan.io | 60 |

If a 429 (rate limit) response is received, Cygor automatically pauses for 60 seconds before retrying.

## Next Steps

- [Scanning Guide](Scanning-Guide.md)
- [Device Fingerprinting](Device-Fingerprinting.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)
