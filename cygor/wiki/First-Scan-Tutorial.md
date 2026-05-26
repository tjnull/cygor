# First Scan Tutorial

End-to-end walkthrough: from a scope file to enumerated services rendered in the Web UI.

## Prerequisites

- Cygor installed — see [Installation Guide](Installation-Guide.md)
- Root/sudo (Nmap raw sockets, Masscan)
- A scope file or list of target IPs

## Step 1: Prepare a scope

```bash
cat > scope.txt << 'EOF'
192.168.1.0/24
10.0.0.1
10.0.0.5
EOF
```

You can also pass targets inline with `-ips 192.168.1.0/24 10.0.0.5`.

## Step 2: Choose a discovery method

| Tool | Best for | Command |
|---|---|---|
| Masscan | Large networks, fastest | `--discover masscan` |
| Naabu | Medium networks, balanced | `--discover naabu` |
| Both | Maximum coverage | `--discover masscan naabu --nmap-source merge` |

## Step 3: Run the scan

### Discovery + Nmap (typical)

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu
```

Steps automatically:
1. Discover live hosts with Naabu.
2. Nmap on the discovered set.
3. Save to `results/`.

### Discovery only (don't Nmap yet)

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --discover-only
# → results/discovery/
```

### Custom ports

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --ports 80,443,8080,8443
```

### Top-1000 ports

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type top-ports
```

### Full 65535-port scan (slow but thorough)

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type fullscan
```

## Step 4: Parse into per-service hostlists

```bash
# Parse the whole results/nmap directory
cygor parse results/nmap

# Parse a single file with a custom output dir
cygor parse results/nmap/scan.xml -o results/parsed-hostlists

# Or recursively
cygor parse /path/to/scans --out-dir results
```

The parser writes one hostlist per service into `results/parsed-hostlists/<service>/<service>-hostlist.txt`:

```
results/parsed-hostlists/
├── http/http-hostlist.txt
├── https/https-hostlist.txt
├── http-https/http-https-hostlist.txt   ← combined
├── ssh/ssh-hostlist.txt
├── smb/smb-hostlist.txt
├── ftp/ftp-hostlist.txt
└── ...
```

See [Parsing Results](Parsing-Results.md) for every supported service.

## Step 5: Run enumeration modules

Feed the hostlists into the modules that fit. A few common ones:

### Web screenshots

```bash
cygor enum lockon web -f results/parsed-hostlists/http-https/http-https-hostlist.txt
```

### Web content discovery (multi-tool, with screenshots)

```bash
cygor enum webenum -f results/parsed-hostlists/http-https/http-https-hostlist.txt --screenshot
```

### SMB / NFS

```bash
cygor enum smbexplorer -i results/parsed-hostlists/smb/smb-hostlist.txt --list-files
cygor enum nfsexplorer -i results/parsed-hostlists/nfs/nfs-hostlist.txt --info
```

### Active Directory recon (MSRPC)

```bash
cygor enum rpcexplorer -i results/parsed-hostlists/smb/smb-hostlist.txt --rid-cycle
```

> Cygor ships 11 enumeration modules total (LDAP, SNMP, DNS, FTP, SMTP, databases, and more). Run `cygor enum --list` and see [Enumeration Modules](Enumeration-Modules.md) for the full reference.

## Step 6: Load into the Web UI

```bash
cygor web start --load-dir results
# → http://127.0.0.1:8000
```

Navigate to:

- **Dashboard** — overview of hosts and services
- **Hosts** — per-host detail
- **Modules** — the rows produced by each enumeration module
- **Docs** (`/docs`) — this wiki, rendered in the UI

## Common workflows

### Quick reconnaissance

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu --scan-type top-ports
cygor parse results/nmap
cygor web start --load-dir results
```

### Comprehensive assessment

```bash
# 1. Discovery with both tools
sudo cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge

# 2. Full-port scan on discovered hosts
sudo cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type fullscan

# 3. Parse + enumerate
cygor parse results/nmap
cygor enum lockon web -f results/parsed-hostlists/http/http-hostlist.txt
cygor enum webenum -f results/parsed-hostlists/http-https/http-https-hostlist.txt --screenshot

# 4. View
cygor web start --load-dir results
```

### Reusing discovery results

```bash
# 1. Discovery once
sudo cygor scan -i eth0 -f scope.txt --discover naabu --discover-only

# 2. Multiple scan profiles against the same discovered set
sudo cygor scan --use-discovery results/discovery/naabu-discovered.txt --scan-type top-ports
sudo cygor scan --use-discovery results/discovery/naabu-discovered.txt --ports 80,443,8080
```

## Tips

- **Start small** — test on a tiny scope before unleashing on a whole subnet.
- **Discovery-only first** for large networks; iterate scan profiles cheaply.
- **`--processes N`** parallelizes Nmap (max 100).
- **`--exclusions exclusions.txt`** to skip hosts/ranges.
- **Workspaces** ([Setting Up Workspaces](Setting-Up-Workspaces.md)) keep engagements isolated cleanly.

## Next Steps

- [Parsing Results](Parsing-Results.md) — every service bucket the parser produces
- [Enumeration Modules](Enumeration-Modules.md) — the 11 built-in modules
- [Plugin Development](Plugin-Development.md) — write your own modules
- [Data Ingestion & Web UI](Data-Ingestion-And-Web-UI.md) — how results land in the Web UI
