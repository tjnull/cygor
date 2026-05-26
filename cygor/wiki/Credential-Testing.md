# Credential Testing (CredRecon)

Comprehensive guide to Cygor's credential reconnaissance module for testing default and weak credentials across network services.

## Overview

CredRecon is Cygor's built-in credential testing engine. It tests default, weak, and known-compromised credentials against discovered services to identify authentication misconfigurations. It supports 27 protocols, ships with a curated YAML credential database, and can sync additional credentials from external sources.

## Basic Syntax

```bash
cygor credrecon -t <target> [options]
cygor credrecon -i <targets-file> [options]
```

## Supported Protocols

CredRecon supports **27 protocols** across the following categories:

| Category | Protocols |
|----------|-----------|
| **Web** | HTTP/HTTPS (Basic Auth, Digest Auth, Form-based) |
| **Remote Access** | SSH (password, key, certificate, bad key detection), RDP, VNC, Telnet, WinRM/WinRM-SSL |
| **File Transfer** | FTP, SMB (password + NTLM pass-the-hash) |
| **SQL Databases** | MySQL, PostgreSQL, MSSQL |
| **NoSQL Databases** | MongoDB, Redis, Elasticsearch, CouchDB, InfluxDB, Cassandra, Neo4j, Memcached |
| **Email** | SMTP/SMTPS, IMAP/IMAPS, POP3/POP3S |
| **Directory** | LDAP/LDAPS (Simple bind + NTLM) |
| **Network Management** | SNMP (tiered community string wordlists), IPMI |
| **IoT / Messaging** | MQTT/MQTTS |

## CLI Usage

### Single Target

```bash
# Auto-detect protocol from port
cygor credrecon -t 192.168.1.10:22

# Specify protocol explicitly
cygor credrecon -t 192.168.1.10:22 --protocol ssh

# Test multiple protocols on one host
cygor credrecon -t 192.168.1.10 --protocols ssh,smb,winrm --port 22
```

### Multiple Targets

```bash
# From a file (one IP:PORT per line)
cygor credrecon -i targets.txt

# From stdin (supports JSONL or IP:PORT lines)
cat targets.txt | cygor credrecon --stdin

# With custom output directory
cygor credrecon -i targets.txt -o /path/to/output
```

### Attack Modes

CredRecon supports several attack strategies:

```bash
# Default: test known default credentials for detected service
cygor credrecon -i targets.txt --attack-mode default

# Password spray: one password across many usernames
cygor credrecon -i targets.txt --attack-mode spray --spray-password "Winter2026!" --usernames-file users.txt

# Credential stuffing: one username with many passwords
cygor credrecon -i targets.txt --attack-mode stuff --stuff-username admin --passwords-file passwords.txt

# Single credential pair
cygor credrecon -t 192.168.1.10:22 --attack-mode single --single-username root --single-password toor

# SSH key authentication
cygor credrecon -t 192.168.1.10:22 --attack-mode key --ssh-key id_rsa

# SSH key with certificate
cygor credrecon -t 192.168.1.10:22 --attack-mode key --ssh-key id_rsa --ssh-cert id_rsa-cert.pub

# Credential file with per-target entries
cygor credrecon -i targets.txt --attack-mode credfile --credfile-path creds.csv
```

### Tuning and Safety

```bash
# Adjust threads and timeout
cygor credrecon -i targets.txt --threads 20 --timeout 10

# Limit attempts per target (stop after first 3 credential pairs)
cygor credrecon -i targets.txt --max-attempts 3

# Add jitter between tests to avoid detection
cygor credrecon -i targets.txt --jitter 1.5

# Limit attempts per username to avoid account lockout
cygor credrecon -i targets.txt --max-attempts-per-user 2

# Disable service probing (rely on port-based detection only)
cygor credrecon -i targets.txt --no-probe
```

### Protocol-Specific Options

```bash
# SMB pass-the-hash
cygor credrecon -t 192.168.1.10:445 --protocol smb --smb-hash aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 --domain CORP

# SNMP community string tiers (default: 25 strings, extended: 75, full: 200+)
cygor credrecon -t 192.168.1.10:161 --protocol snmp --snmp-tier full

# Disable known-compromised SSH key testing
cygor credrecon -i targets.txt --no-badkeys

# LDAP/WinRM with domain
cygor credrecon -t 192.168.1.10:5985 --protocol winrm --domain CORP
```

### Output Format

```bash
# Output results as JSON Lines to stdout
cygor credrecon -i targets.txt --jsonl
```

## Credential Sources

### Built-in YAML Database

CredRecon ships with a curated credential database in `cygor/credrecon/credentials/builtin/`:

| File | Contents |
|------|----------|
| `generic.yaml` | Protocol-level defaults (admin/admin, root/root, etc.) |
| `databases.yaml` | MySQL, PostgreSQL, MSSQL, MongoDB, Redis, and other database defaults |
| `web.yaml` | Web application default credentials (CMS, routers, management consoles) |
| `enterprise.yaml` | Enterprise software defaults (networking, security appliances) |
| `cloud.yaml` | Cloud platform and SaaS default credentials |
| `iot.yaml` | IoT device and embedded system defaults |
| `snmp_communities.yaml` | SNMP community strings organized by tier (default, extended, full) |

Each credential entry includes a **priority score** (1-100) that determines testing order. Higher-priority credentials (common defaults like admin/admin at 95) are tested first.

### Known-Compromised SSH Keys

The `cygor/credrecon/badkeys/` directory contains known-compromised SSH private keys (Vagrant, F5 BIG-IP, Barracuda, ExaGrid, etc.). These are tested automatically against SSH targets unless disabled with `--no-badkeys`.

### External Sources

Sync additional credentials from online databases:

```bash
# Sync before scanning
cygor credrecon -i targets.txt --sync

# Force offline mode (builtin + cached only)
cygor credrecon -i targets.txt --offline
```

External sources include:
- **CIRT.net**: Default password database organized by vendor and product
- **DefaultCreds-cheat-sheet**: Community-maintained default credential repository from GitHub

### Custom Credentials

Provide your own credential files:

```bash
# Custom YAML or JSON credential file
cygor credrecon -i targets.txt --creds-file my-creds.yaml
```

## Web UI Usage

The Web UI provides a graphical interface for credential testing at `/credrecon`.

### Starting a Scan

1. Navigate to **Tasks** in the top menu and select **Credential Test** (or go directly to `/credrecon/new`)
2. Enter targets (IP:PORT format, one per line) or select from discovered hosts
3. Choose protocols and attack mode
4. Configure thread count, timeout, and safety options
5. Click **Start Scan**

### Viewing Results

After launching a scan, you are redirected to `/credrecon/scans/<scan_id>` where you can:

- Monitor scan progress in real time
- View discovered credentials as they are found
- Filter results by protocol, host, or status

CredRecon results also appear in the **Credential Reconnaissance** section of exported reports, with configurable display modes (full credentials, masked, or statistics only).

## Results Storage

### Output Directory

Results are saved to a timestamped subdirectory under the active workspace:

```
<workspace>/credrecon/YYYYMMDD_HHMMSS/
```

Or to a custom path if `-o` is specified.

### Output Files

| File | Format | Description |
|------|--------|-------------|
| `credrecon_results.json` | JSON | Full results with all metadata |
| `credrecon_results.csv` | CSV | Tabular results for spreadsheet import |
| `credrecon_results.xml` | XML | XML-formatted results |

Each result entry includes: target IP, port, protocol, username, password/hash, success status, and timestamp.

## Workflow Examples

### Post-Scan Credential Check

```bash
# Step 1: Scan the network
sudo cygor scan -i eth0 -f scope.txt --discover naabu

# Step 2: Parse results to get service lists
cygor parse results/nmap

# Step 3: Test credentials against discovered services
cygor credrecon -i results/parsed-hostlists/ssh/ssh-hostlist.txt --protocol ssh
cygor credrecon -i results/parsed-hostlists/smb/smb-hostlist.txt --protocol smb
```

### Safe Internal Assessment

```bash
# Conservative settings to avoid lockouts
cygor credrecon -i targets.txt \
    --max-attempts 3 \
    --max-attempts-per-user 2 \
    --jitter 2.0 \
    --threads 5 \
    --timeout 10
```

### Comprehensive Default Credential Audit

```bash
# Sync external sources, test all protocols
cygor credrecon -i targets.txt --sync --threads 20

# SNMP full community string test
cygor credrecon -i snmp-hosts.txt --protocol snmp --snmp-tier full
```

## Troubleshooting

### Missing Protocol Libraries

Some protocols require optional Python packages:

```bash
# SSH support
pip install paramiko

# SMB support (pass-the-hash)
pip install impacket

# Database clients
pip install pymysql psycopg2 pymssql pymongo redis

# RDP support
pip install aardwolf
```

### Connection Timeouts

1. Increase timeout: `--timeout 15`
2. Reduce thread count: `--threads 5`
3. Verify target is reachable: `nmap -sV -p <port> <target>`

### False Positives

Enable service probing (default) to confirm protocol before testing. If you see false positives, verify manually and check that the correct protocol is being detected.

## Next Steps

- [Scanning Guide](Scanning-Guide.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)
- [Common Issues](Common-Issues.md)
