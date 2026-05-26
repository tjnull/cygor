# Enumeration Modules

`cygor enum` runs protocol-specific enumeration modules against scan results. Modules are shipped in `cygor/modules/` and can be listed at runtime.

## Available Modules

```bash
cygor enum --list
```

| Module | Purpose |
|---|---|
| [`lockon`](#lockon-screenshot-capture) | Capture screenshots from HTTP/HTTPS, RDP, VNC, and X11 targets |
| [`webenum`](#web-content-discovery) | Parallel multi-tool web content discovery (ffuf, feroxbuster, gobuster, dirsearch) |
| [`smbexplorer`](#smb-explorer) | Enumerate SMB shares, permissions, and optionally list files |
| [`nfsexplorer`](#nfs-explorer) | Enumerate NFS exports, detect versions, and check for misconfigurations |
| [`rpcexplorer`](#rpc-explorer) | Enumerate MSRPC: server/domain info, users, groups, password policy, RID cycling |
| [`ldapexplorer`](#ldap-explorer) | Enumerate LDAP/AD: rootDSE, anonymous bind/search, authenticated dump |
| [`snmpexplorer`](#snmp-explorer) | Enumerate SNMP v1/v2c: community brute, system info, MIB sweep |
| [`dnsexplorer`](#dns-explorer) | Enumerate DNS: version, open resolver, AXFR zone transfer |
| [`ftpexplorer`](#ftp-explorer) | Enumerate FTP: banner, anonymous login, listing, anonymous write |
| [`smtpexplorer`](#smtp-explorer) | Enumerate SMTP: banner, STARTTLS, AUTH, VRFY user-enum, open relay |
| [`dbprobe`](#database-probe) | Probe Redis/MySQL/PostgreSQL/MongoDB/Elasticsearch/CouchDB for unauth access |

> **Findings integration.** High-signal observations from these modules (open NFS exports, RPC null sessions, weak password policy, exposed web paths, unauthenticated databases, and more) are fed automatically into Cygor's **next-steps engine**, which surfaces prioritized findings with ready-to-run follow-up commands in the Web UI. No extra flags required — just run the module.

## Basic Syntax

```bash
cygor enum <module> [options]
```

Use `cygor enum <module> --help` for the full option reference. The sections below cover the most useful flags, verified against the current module source.

---

## Lockon (Screenshot Capture)

Lockon captures screenshots across a mix of protocols using Playwright (web) and protocol-specific clients (RDP/VNC/X11).

### Protocols

`lockon` takes a protocol subcommand as a positional argument:

| Subcommand | Captures |
|---|---|
| `http` | HTTP web pages |
| `https` | HTTPS web pages |
| `web` | Both HTTP and HTTPS |
| `rdp` | RDP login screens |
| `vnc` | VNC sessions |
| `x11` | X11 displays |
| `all` | Every protocol above |

### Common Options

| Option | Description |
|---|---|
| `-f`, `--file FILE` | File of targets, one per line. Accepts `host`, `host:port`, or full URLs. |
| `-t`, `--targets ...` | Targets directly on the command line. |
| `-o`, `--output DIR` | Output directory (default: `results/cygor-enumeration-modules/lockon/`). |
| `--output-format {json,csv,xml,txt,all}` | Report format. |
| `--workers N` | Parallel workers. |
| `--timeout N` | Capture timeout (seconds). |
| `--viewport WxH` | Browser viewport for web screenshots. |
| `--nav-timeout MS` | Playwright navigation timeout (ms). |
| `--extra-wait MS` | Extra wait after page load (ms). |
| `--status-filter CODES ...` | Only screenshot HTTP status codes listed (`0` = all). |
| `--install-browsers` | Install Playwright browsers, then exit. |
| `--browser {webkit,chromium,firefox}` | Browser engine (default: `chromium`). |
| `--rdp-user`, `--rdp-pass` | Credentials for RDP capture. |
| `--password` | VNC password. |
| `--displays` | X11 displays, e.g. `0`, `0-5`, `0,1,2`. |

### First Run

Lockon installs the required Playwright browser (Chromium by default) automatically on the first web capture. To pre-install it manually:

```bash
python -m playwright install chromium

# If the browser fails to launch, also install its system libraries:
sudo python -m playwright install-deps chromium
```

### Examples

```bash
# Web screenshots against parsed HTTP+HTTPS hostlist
cygor enum lockon web -f results/parsed-hostlists/http-https/http-https-hostlist.txt

# HTTPS only, save 16-wide
cygor enum lockon https -f urls.txt --workers 16 --viewport 1920x1080

# RDP screenshots with credentials
cygor enum lockon rdp -f rdp_hosts.txt --rdp-user administrator --rdp-pass 'Passw0rd!'

# VNC screenshots
cygor enum lockon vnc -f vnc_hosts.txt --password 'hunter2'

# X11 displays 0-5 across a list
cygor enum lockon x11 -f x11_hosts.txt --displays 0-5

# Everything at once
cygor enum lockon all -f targets.txt --workers 16
```

---

## Web Content Discovery

`webenum` runs multiple content-discovery tools **in parallel** against each web target, then deduplicates and correlates the results across tools so each discovered path appears once with the set of tools that found it (`found_by`) and a confidence score. Only the tools you have installed are launched.

### Tools

| Set | Tools | Notes |
|---|---|---|
| `default` | `ffuf`, `feroxbuster`, `gobuster` | Fast; the default. |
| `all` | adds `dirsearch` | More thorough, noticeably slower. |
| custom | comma-separated, e.g. `--tools ffuf,feroxbuster` | Any subset. |

### Wordlists

Built-in presets are drawn from SecLists / dirb / dirbuster (raft-* lists are the bug-bounty sweet spot):

| Preset | Backing list(s) |
|---|---|
| `quick` | quickhits |
| `common` | common.txt (SecLists + dirb) |
| `medium` *(default)* | raft-medium directories + files |
| `large` | raft-large + dirbuster directory-list-2.3-medium |
| `api` | api-endpoints + objects |

Override with your own list via `--wordlist /path/to/list.txt`.

### Common Options

| Option | Description |
|---|---|
| `-t`, `--target` / `-f`, `--file` | Targets (host, `host:port`, or full URL) directly or from a file. |
| `--tools TOOLS` | `default`, `all`, or a comma-separated subset. |
| `--wordlist PATH` | Custom wordlist (overrides `--wordlist-size`). |
| `--wordlist-size {quick,common,medium,large,api}` | Built-in preset (default: `medium`). |
| `--extensions php,txt,html` | Extensions to append (default: none). |
| `--threads N` | Threads per tool (default: 40). |
| `--target-workers N` | Targets scanned in parallel (default: 3). |
| `--status-codes ...` | HTTP codes to match (default: `200,204,301,302,307,308,401,403,405,500`). |
| `--recursion-depth N` | Recursion depth; `>1` enables recursive discovery (default: 1). |
| `--max-time N` | Per-tool wall-clock cap in seconds (`0` = auto by wordlist size). |
| `--scheme {auto,http,https}` | Scheme for bare-host targets (default: `auto`). |
| `--no-titles` | Skip fetching page `<title>`. |
| `--screenshot` | Screenshot discovered pages via lockon and link them on each row. |
| `--max-screenshots N` | Cap screenshots when `--screenshot` is set (default: 75). |

### Accuracy

`webenum` filters wildcard/catch-all noise automatically: baseline-matched responses, repeated error templates, sized redirect catch-alls, and bulk byte-identical 200s (SPA/prefix catch-alls) are dropped so the results stay high-signal.

### Examples

```bash
# Default fast sweep across a parsed web hostlist
cygor enum webenum -f results/parsed-hostlists/http-https/http-https-hostlist.txt

# Thorough run (all tools) with common extensions and screenshots
cygor enum webenum -t https://target.example --tools all \
  --extensions php,txt,bak --screenshot

# Custom wordlist, deeper recursion
cygor enum webenum -t http://10.10.10.5 --wordlist /opt/lists/custom.txt --recursion-depth 2

# API-focused preset
cygor enum webenum -t https://api.target.example --wordlist-size api
```

> Discovered paths that look interesting (exposed secrets/backups/configs, admin interfaces, API specs) are turned into prioritized findings by the next-steps engine.

---

## SMB Explorer

Enumerates accessible SMB shares, reports permissions, and can optionally list files inside each share. Supports NTLM and Kerberos authentication.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--targets IP[,IP...]` | IP address or comma-separated list (not a file path). |
| `-i`, `--input-file PATH` | File with one IP per line. |

> SMB Explorer reads `--input-file` as plain IPs. When feeding it a `*-hostlist.txt` from `cygor parse`, strip ports first: `cut -d: -f1 smb-hostlist.txt | sort -u > smb-ips.txt`.

### Authentication (NTLM / Hash)

| Flag | Description |
|---|---|
| `-u`, `--username` | Username (default: `guest`). |
| `-p`, `--password` | Password. |
| `-d`, `--domain` | Domain name. |
| `-H`, `--hashes LM:NT` | NTLM hash (pass-the-hash). |

### Authentication (Kerberos)

| Flag | Description |
|---|---|
| `-k`, `--kerberos` | Enable Kerberos authentication. |
| `--kerberos-ccache PATH` | Path to a Kerberos ccache file (overrides `KRB5CCNAME`). |
| `--kerberos-keytab PATH` | Path to a keytab file (common for service accounts). |
| `--kerberos-aeskey HEX` | 128/256-bit AES key (pass-the-key). |
| `--kerberos-principal USER@REALM` | Explicit principal. Defaults to `username@DOMAIN`. |

### Output

| Flag | Description |
|---|---|
| `-o`, `--output-dir [PATH]` | Directory to save results. If `-o` is passed with no path, a timestamped folder is created under `results/cygor-enumeration-modules/smbexplorer/`. |
| `--smb-output-format` | `txt`, `csv`, `json`, `xml`, or `all` (default: all four). |
| `--list-files` | List accessible files in each share. |
| `--max-files N` | Max files per share when `--list-files` is set (default: 50). |

### Examples

```bash
# Guest login against a single host
cygor enum smbexplorer -t 10.10.10.5

# Authenticated with password
cygor enum smbexplorer -t 192.168.1.100 -u administrator -p 'Passw0rd!'

# Pass-the-hash
cygor enum smbexplorer -t 192.168.1.50 -u administrator -d CORP \
  -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99

# Kerberos via ccache
cygor enum smbexplorer -t dc01.corp.local -u user01 -d CORP -k \
  --kerberos-ccache /tmp/krb5cc_user01

# Kerberos via keytab (service account)
cygor enum smbexplorer -t dc01.corp.local -u svc_scanner -d CORP -k \
  --kerberos-keytab /opt/keytabs/svc_scanner.keytab

# Bulk run from a parsed hostlist (strip ports first)
cut -d: -f1 results/parsed-hostlists/smb/smb-hostlist.txt | sort -u > /tmp/smb-ips.txt
cygor enum smbexplorer -i /tmp/smb-ips.txt --list-files --max-files 20 -o results/smb
```

> For Kerberos, the target must be resolvable — use the FQDN or add it to `/etc/hosts`.

---

## NFS Explorer

Enumerates NFS exports, detects supported NFS versions, optionally lists files inside exports, and can check for `no_root_squash` misconfigurations.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--targets IP[,IP...]` | IP address or comma-separated list. |
| `-i`, `--input-file PATH` | File with one IP per line. |

As with SMB Explorer, use plain IPs in the input file (not `host:port`).

### Auth / UID Spoofing

NFS uses UID/GID for authorization on AUTH_SYS mounts. NFS Explorer can spoof these:

| Flag | Description |
|---|---|
| `--uid UID` | Fake UID for NFS requests (default: `0`). |
| `--gid GID` | Fake GID (default: `0`). |
| `--aux-gids G1,G2,...` | Comma-separated auxiliary GIDs. |

### Protocol Options

| Flag | Description |
|---|---|
| `--version {2,3,4}` | Force a specific NFS protocol version. |
| `--timeout N` | RPC timeout in seconds (default: 10). |
| `-r`, `--recurse N` | Directory recursion depth (`0` = list export root only, default: `1`). |
| `--info` | Only show supported NFS versions and exports; skip content listing. |
| `--list-files` | Also list files/directories inside each share. |
| `--check-root` | Detect `no_root_squash` misconfigurations. |

### Output

| Flag | Description |
|---|---|
| `-o`, `--output-dir PATH` | Directory to save results (default: `results/cygor-enumeration-modules/nfsexplorer/`). |
| `--nfs-output-format {text,csv,json,xml,all}` | Save format. If omitted, nothing is saved unless `-o` is set. |

### Examples

```bash
# Basic enumeration (shares/exports only)
cygor enum nfsexplorer -t 10.10.10.5

# List files inside each share
cygor enum nfsexplorer -t 192.168.1.100 --list-files

# Spoof a specific UID/GID to test access
cygor enum nfsexplorer -t 192.168.1.150 --uid 1000 --gid 1000

# Force NFSv3 only
cygor enum nfsexplorer -t 192.168.1.75 --version 3

# Check for no_root_squash
cygor enum nfsexplorer -t 192.168.1.200 --check-root

# Save every format
cygor enum nfsexplorer -t 10.10.10.5 --list-files --nfs-output-format all

# Bulk run from a parsed hostlist (strip ports first)
cut -d: -f1 results/parsed-hostlists/nfs/nfs-hostlist.txt | sort -u > /tmp/nfs-ips.txt
cygor enum nfsexplorer -i /tmp/nfs-ips.txt --info
```

---

## RPC Explorer

Enumerates Windows/Samba hosts over MSRPC (via SMB named pipes), using a **null session by default**: server/OS info, domain name and SID, domain users and groups, and the full password policy. Supply credentials for an authenticated session. Wraps Samba's `rpcclient` (and `polenum` for the lockout/age fields). Complements SMB Explorer (which focuses on shares/files) with the SAMR/LSARPC object enumeration that drives AD recon.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `-u`, `--username` | Username for an authenticated session (default: null session). |
| `-p`, `--password` | Password for the authenticated session. |
| `--timeout N` | Per-host timeout in seconds (default: 10). |
| `--rid-cycle` | Force RID cycling (otherwise it runs automatically when SAMR user enumeration is blocked but `lookupsids` isn't). |
| `--rid-ranges` | RID ranges to cycle, e.g. `500-550,1000-1050` (the default). |

### Password policy & findings

The module surfaces the complete domain password policy — minimum length, complexity, lockout threshold, and max password age — as a `Password Policy` column. Weak settings are emitted as findings: **high** (no account lockout → password spraying isn't rate-limited), **medium** (complexity not enforced), and **low** (minimum length < 8).

### RID cycling

When `enumdomusers` is restricted, RID cycling resolves `domain-SID + RID → account name` via `lookupsids`, recovering usernames that SAMR enumeration won't return. It keeps only user accounts (SID type 1) and drops `*unknown*`.

> Modern Windows blocks null sessions (`NT_STATUS_ACCESS_DENIED`); these features apply to older Windows / Samba and degrade cleanly elsewhere.

### Examples

```bash
# Null session against a single host
cygor enum rpcexplorer -t 10.10.10.5

# Authenticated session
cygor enum rpcexplorer -t 192.168.1.100 -u CORP\\user -p 'Passw0rd!'

# Force RID cycling over a custom range
cygor enum rpcexplorer -t 192.168.1.50 --rid-cycle --rid-ranges 500-600,1000-1200

# Bulk run from the parsed SMB hostlist
cygor enum rpcexplorer -i results/parsed-hostlists/smb/smb-hostlist.txt
```

---

## LDAP Explorer

Enumerates LDAP / Active Directory: reads the `rootDSE`, tests anonymous bind and anonymous search, and (with credentials) runs an authenticated domain dump via `ldapdomaindump`. Wraps `ldapsearch` and `ldapdomaindump`.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `-u`, `--username` | Username for an authenticated dump, e.g. `CORP\\user` (enables `ldapdomaindump`). |
| `-p`, `--password` | Password for the authenticated dump. |
| `--timeout N` | Per-query timeout in seconds (default: 8). |

### Examples

```bash
# Anonymous: rootDSE + anonymous bind/search test
cygor enum ldapexplorer -t 10.10.10.5

# Authenticated domain dump
cygor enum ldapexplorer -t dc01.corp.local -u 'CORP\\user' -p 'Passw0rd!'

# Bulk run from a parsed LDAP hostlist
cygor enum ldapexplorer -i results/parsed-hostlists/ldap/ldap-hostlist.txt
```

---

## SNMP Explorer

Enumerates SNMP v1/v2c: tries common community strings (falling back to an `onesixtyone` brute force), reads device system info, and performs a MIB sweep — users, running processes, installed software, listening TCP ports, and interfaces. Wraps net-snmp (`snmpget`/`snmpwalk`) and `onesixtyone`.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--targets IP[,IP...]` | IP/host or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File of targets, one per line. |

### Options

| Flag | Description |
|---|---|
| `-c`, `--communities` | Community strings to try, comma-separated (default: `public,private`). |
| `--timeout N` | Per-probe timeout in seconds (default: 2). |
| `--threads N` | Concurrent hosts (default: 10). |
| `-o`, `--output-dir` | Output directory (default: workspace). |
| `--output-format {json,csv,xml,txt,all}` | Also export this format (default: json). |

### Examples

```bash
# Default communities against a single host
cygor enum snmpexplorer -t 10.10.10.5

# Custom community list
cygor enum snmpexplorer -t 192.168.1.10 -c public,private,community,manager

# Bulk run with more concurrency
cygor enum snmpexplorer -i results/parsed-hostlists/snmp/snmp-hostlist.txt --threads 20
```

---

## DNS Explorer

Enumerates DNS servers: reads the `version.bind` string, detects open recursion (open resolver), and attempts an AXFR zone transfer. With a domain supplied it also runs `dnsrecon`. Wraps `dig` and `dnsrecon`.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `-d`, `--domain` | Domain/zone to attempt AXFR + `dnsrecon` enumeration against. |
| `--timeout N` | Per-query timeout in seconds (default: 5). |

### Examples

```bash
# Version + open-resolver check
cygor enum dnsexplorer -t 10.10.10.5

# Attempt a zone transfer for a domain
cygor enum dnsexplorer -t 10.10.10.5 -d corp.local

# Bulk run
cygor enum dnsexplorer -i results/parsed-hostlists/dns/dns-hostlist.txt
```

---

## FTP Explorer

Enumerates FTP services: grabs the banner, tests anonymous login, lists the root directory, reads `FEAT`, and (optionally) tests anonymous write access. Uses Python's standard FTP client — no external tool required.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `--port N` | FTP port (default: 21). |
| `--timeout N` | Per-probe timeout in seconds (default: 5). |
| `--check-writable` | Test anonymous write access (creates then removes a temp dir). |

### Examples

```bash
# Banner + anonymous login + listing
cygor enum ftpexplorer -t 10.10.10.5

# Also test anonymous write
cygor enum ftpexplorer -t 192.168.1.20 --check-writable

# Bulk run from a parsed FTP hostlist
cygor enum ftpexplorer -i results/parsed-hostlists/ftp/ftp-hostlist.txt
```

---

## SMTP Explorer

Enumerates SMTP services: grabs the banner, checks STARTTLS, lists advertised AUTH mechanisms, attempts VRFY-based user enumeration, and (optionally) tests for an open relay (MAIL/RCPT only — no message is sent). Uses Python's standard SMTP client.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `--port N` | Probe only this port (default: both 25 and 587). |
| `--timeout N` | Per-probe timeout in seconds (default: 5). |
| `--check-relay` | Test for an open relay (MAIL/RCPT only, no message sent). |

### Examples

```bash
# Banner + STARTTLS + AUTH + VRFY
cygor enum smtpexplorer -t 10.10.10.5

# Also test for an open relay
cygor enum smtpexplorer -t 192.168.1.30 --check-relay

# Bulk run
cygor enum smtpexplorer -i results/parsed-hostlists/smtp/smtp-hostlist.txt
```

---

## Database Probe

Probes common databases — Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch, CouchDB — for unauthenticated access and version disclosure. When auto-dispatched per parsed bucket it picks the right service automatically.

### Targeting

| Flag | Description |
|---|---|
| `-t`, `--target IP[,IP...]` | Single target or comma-separated list. |
| `-f`, `-i`, `--input-file PATH` | File with one target per line. |

### Options

| Flag | Description |
|---|---|
| `--service {couchdb,elasticsearch,mongodb,mysql,postgres,redis}` | Probe only this service (default: all). |
| `--port N` | Override the default port for `--service`. |
| `--timeout N` | Per-probe timeout in seconds (default: 4). |

### Examples

```bash
# Probe all supported databases on a host
cygor enum dbprobe -t 10.10.10.5

# Redis only, custom port
cygor enum dbprobe -t 192.168.1.40 --service redis --port 6380

# Bulk run: parse writes one list per DB service (no single "databases" bucket),
# so combine them, then let dbprobe auto-detect each host's database(s)
cat results/parsed-hostlists/{mysql,postgres,redis,mongodb,couchdb,elasticsearch}/*-hostlist.txt \
  2>/dev/null | sort -u > /tmp/db-hosts.txt
cygor enum dbprobe -i /tmp/db-hosts.txt
```

> Unauthenticated databases are flagged as findings by the next-steps engine with follow-up commands.

---

## Writing Custom Modules

Modules inherit from `cygor.modules.base.CygorModule`. The base class and a worked example are in `cygor/modules/base.py` and `cygor/modules/__init__.py`. At a minimum a module defines `name`, `description`, and a `run(self, targets, **kwargs)` method; `cygor enum` picks up any module in the `cygor/modules/` directory.

## Next Steps

- [Parsing Results](Parsing-Results.md) - generate the hostlists these modules consume
- [Credential Testing](Credential-Testing.md) - use `cygor credrecon` for protocol credential checks
- [Plugin Development](Plugin-Development.md) - extend Cygor with your own modules
