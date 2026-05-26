# Parsing Results

`cygor parse` turns Nmap scan output into categorized hostlists grouped by service. It's the bridge between `cygor scan` and the enumeration / credential-testing commands, which consume those hostlists as input.

## Overview

Cygor parse reads:

- `.xml` — Nmap XML output (`-oX`)
- `.nmap` — Nmap human-readable output (`-oN`)
- `.gnmap` — Nmap greppable output (`-oG`)

Point it at a single file or an entire directory. When given a directory it walks the tree and parses every supported file it finds.

For each host/port pair, the port number and service banner are matched against a built-in service map and sorted into categories (see [Service Categories](#service-categories) below).

## Basic Syntax

```bash
cygor parse [options] <input>
```

## Common invocations

```bash
# Parse a directory of Nmap results and print hostlists to stdout
cygor parse results/nmap

# Parse a single XML file and write hostlists under results/parsed-hostlists/
cygor parse results/nmap/scan1.xml -o results

# Recursively parse a tree of .xml/.nmap/.gnmap files
cygor parse /path/to/scans --out-dir results

# Emit JSON instead of plain hostlists (prints to stdout when no -o)
cygor parse results/nmap --format json

# Write every format at once
cygor parse results/nmap -o results --format all
```

## Options

| Option | Description |
|---|---|
| `<input>` | File or directory of `.xml` / `.nmap` / `.gnmap` files. Required. |
| `-o`, `--out-dir` | Output directory. A `parsed-hostlists/` subdirectory is created under this path. If omitted, results print to stdout. |
| `--format {txt,json,csv,xml,all}` | Output format. Default: `txt`. When no `-o` is given, `json`/`csv`/`xml` print to stdout; `txt` always prints one hostlist per service. `all` writes every format (requires `-o`). |
| `-h`, `--help` | Full usage. |

## Output layout

When `-o results` is given, Cygor creates:

```
results/
  parsed-hostlists/
    http/http-hostlist.txt
    https/https-hostlist.txt
    http-https/http-https-hostlist.txt        ← combined HTTP+HTTPS
    smb/smb-hostlist.txt
    nfs/nfs-hostlist.txt
    ssh/ssh-hostlist.txt
    ...
    parsed-hosts.json   # if --format json
    parsed-hosts.csv    # if --format csv
    parsed-hosts.xml    # if --format xml
```

Each `*-hostlist.txt` contains one `host:port` entry per line, suitable for feeding back into other Cygor commands.

> If you need plain hostnames, strip the port: `cut -d: -f1 file.txt | sort -u`.

## Service Categories

Ports and banner strings are grouped into these categories:

| Group | Services |
|---|---|
| Web / Admin | `http`, `https`, `http-https` (combined convenience list) |
| File sharing | `smb`, `nfs`, `ftp`, `tftp` |
| Remote access | `ssh`, `telnet`, `rdp`, `winrm`, `vnc` |
| Databases | `mysql`, `postgres`, `mssql`, `oracle`, `mongodb`, `couchdb`, `redis`, `elasticsearch`, `cassandra`, `db2` |
| Mail | `smtp`, `imap`, `pop3` |
| Directory / auth | `ldap`, `kerberos`, `radius` |
| Infrastructure | `dns`, `snmp`, `ntp`, `ipp` |
| Messaging / cache | `mqtt`, `amqp`, `stomp`, `zeromq`, `memcached` |
| Virtualization | `proxmox`, `hyperv` |

The exact port-to-category mapping lives in [`cygor/parse.py`](../parse.py) (`SERVICES` dict).

## Feeding results into other commands

Parsed hostlists chain directly into Cygor's enumeration and credential-testing commands:

```bash
# After parsing
cygor parse results/nmap -o results

# Credential testing against SSH hosts (accepts host:port directly)
cygor credrecon --protocol ssh -f results/parsed-hostlists/ssh/ssh-hostlist.txt

# Web screenshots via Lockon (accepts host:port directly)
cygor enum lockon web -f results/parsed-hostlists/http-https/http-https-hostlist.txt

# Multi-tool web content discovery + screenshots
cygor enum webenum -f results/parsed-hostlists/http-https/http-https-hostlist.txt --screenshot

# Most newer modules strip the port automatically — feed the hostlist directly
cygor enum rpcexplorer  -i results/parsed-hostlists/smb/smb-hostlist.txt --rid-cycle
cygor enum ldapexplorer -i results/parsed-hostlists/ldap/ldap-hostlist.txt
cygor enum snmpexplorer -i results/parsed-hostlists/snmp/snmp-hostlist.txt
cygor enum dnsexplorer  -i results/parsed-hostlists/dns/dns-hostlist.txt
cygor enum ftpexplorer  -i results/parsed-hostlists/ftp/ftp-hostlist.txt
cygor enum smtpexplorer -i results/parsed-hostlists/smtp/smtp-hostlist.txt

# SMB / NFS explorers expect IP-only input files, so strip ports first:
cut -d: -f1 results/parsed-hostlists/smb/smb-hostlist.txt | sort -u > /tmp/smb-ips.txt
cygor enum smbexplorer -i /tmp/smb-ips.txt

cut -d: -f1 results/parsed-hostlists/nfs/nfs-hostlist.txt | sort -u > /tmp/nfs-ips.txt
cygor enum nfsexplorer -i /tmp/nfs-ips.txt
```

> **No `databases` bucket.** Each database service gets its own list (`mysql/`, `postgres/`, `redis/`, `mongodb/`, `couchdb/`, `elasticsearch/`). To probe all of them at once with `dbprobe`, concatenate them: `cat results/parsed-hostlists/{mysql,postgres,redis,mongodb,couchdb,elasticsearch}/*-hostlist.txt | sort -u > /tmp/db.txt && cygor enum dbprobe -i /tmp/db.txt`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Nothing parsed from XML | Confirm the file was produced by `nmap -oX`. Check that `libnmap` is installed (a Cygor dependency). |
| Expected service missing | The host/port may not have been service-detected by Nmap — run with `-sV` for better banner detection. Uncommon ports may not be in the built-in `SERVICES` map. |
| `--format json` wrote nothing to disk | JSON/CSV/XML only write files when `-o` is given; otherwise they print to stdout. Pass `-o results` (or `--format all` with `-o`). |

## Next Steps

- [Scanning Guide](Scanning-Guide.md) — generate the scan files parsed here
- [Enumeration Modules](Enumeration-Modules.md) — feed hostlists into the 11 built-in modules
- [Credential Testing](Credential-Testing.md) — `cygor credrecon` across protocols
- [Plugin Development](Plugin-Development.md) — write a module that consumes parsed hostlists
