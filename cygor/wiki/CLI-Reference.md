# CLI Reference

Every top-level Cygor subcommand on one page. Each command has its own `--help` with the full flag surface — this page is the map. Where a topic has a deeper guide, the link is in the description.

```text
cygor <command> [args]
```

## Top-level commands

| Group | Command | Purpose |
|---|---|---|
| Scanning & Discovery | [`scan`](#cygor-scan) | Discover hosts and run Nmap *(sudo)* |
| Analysis & Processing | [`parse`](#cygor-parse) | Parse Nmap output into categorized hostlists |
| | [`enrich`](#cygor-enrich) | Look up IOCs (Shodan / VT / crt.sh / etc.) |
| Enumeration & Testing | [`enum`](#cygor-enum) | Run enumeration modules against services |
| | [`credrecon`](#cygor-credrecon) | Test default / weak credentials across protocols |
| Management | [`workspace`](#cygor-workspace) | Manage workspaces |
| | [`proxy`](#cygor-proxy) | Configure HTTP/HTTPS/SOCKS proxy |
| | [`plugin`](#cygor-plugin) | Manage community plugins |
| | [`sync`](#cygor-sync) | Refresh data sources (fingerprints / plugins) |
| | [`web`](#cygor-web) | Control the Web UI |
| | [`setup-privileges`](#cygor-setup-privileges) | Grant capabilities so `scan` doesn't need sudo |
| | [`banner`](#cygor-banner) | Print the full ASCII banner |

## Global environment variables

| Variable | Effect |
|---|---|
| `CYGOR_WORKSPACE` | Override the active workspace for this run |
| `CYGOR_RESULTS_DIR` | Override the workspace's results dir |
| `CYGOR_NO_SUDO` | Set to `1` to disable automatic sudo escalation |
| `CYGOR_DEBUG` | `1` enables debug logging |
| `CYGOR_VERBOSE` | `0` / `1` / `2` — verbosity level |
| `CYGOR_PLUGIN_DIR` | Extra plugin directory to scan first (see [Plugin Development](Plugin-Development.md)) |

---

## `cygor scan`

Discover live hosts and run Nmap against them. Wraps Masscan, Naabu, and Nmap; needs `sudo` (or [setup-privileges](#cygor-setup-privileges)).

| Flag | Description |
|---|---|
| `-i INTERFACE` | Network interface to scan from |
| `-f FILE` / `-ips IP [IP ...]` | Scope: file with one target per line, or inline targets |
| `--discover {masscan,naabu,...}` | Discovery tool(s); pass multiple to combine |
| `--nmap-source {merge,masscan,naabu}` | Which discovery output feeds Nmap when combining |
| `--scan-type {top-ports,fullscan,...}` | Nmap profile |
| `--ports PORTS` | Explicit port list (`80,443,8080-8090`) |
| `--processes N` | Parallel Nmap workers (max 100) |
| `--exclusions FILE` | File of IPs/CIDRs to skip |
| `--discover-only` | Don't run Nmap; just save discovery output |
| `--use-discovery FILE` | Reuse a saved discovery output |
| `--fingerprint` | Enable device-fingerprinting during the scan |

Full guide: [Scanning Guide](Scanning-Guide.md). Examples:

```bash
sudo cygor scan -i eth0 -f scope.txt --discover naabu
sudo cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge
sudo cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type fullscan
```

---

## `cygor parse`

Turn Nmap output (`.xml` / `.nmap` / `.gnmap`) into per-service hostlists under `results/parsed-hostlists/`.

| Flag | Description |
|---|---|
| `<input>` | File or directory |
| `-o`, `--out-dir DIR` | Write results here (creates `parsed-hostlists/` under it) |
| `--format {txt,json,csv,xml,all}` | Output format (default `txt`) |

Full guide: [Parsing Results](Parsing-Results.md). Example:

```bash
cygor parse results/nmap -o results
```

---

## `cygor enrich`

Look up IOCs via external sources (Shodan, VirusTotal, crt.sh, etc.) and merge the results into the workspace.

Full guide: [IOC Enrichment](IOC-Enrichment.md).

```bash
cygor enrich --help
```

---

## `cygor enum`

Run an enumeration module against a list of targets. Modules ship in `cygor/modules/`; user-installed plugins also appear here.

| Action | Command |
|---|---|
| List installed modules | `cygor enum --list` |
| Per-module options | `cygor enum <slug> --help` |
| Run a module | `cygor enum <slug> [-t TARGET ... ǀ -f FILE]` |

Built-in modules: `lockon`, `webenum`, `smbexplorer`, `nfsexplorer`, `rpcexplorer`, `ldapexplorer`, `snmpexplorer`, `dnsexplorer`, `ftpexplorer`, `smtpexplorer`, `dbprobe`. Full reference: [Enumeration Modules](Enumeration-Modules.md).

```bash
cygor enum --list
cygor enum webenum -f http-hostlist.txt --screenshot
cygor enum rpcexplorer -i smb-hostlist.txt --rid-cycle
```

---

## `cygor credrecon`

Test default / weak credentials across SSH, FTP, SMB, SNMP, web admin panels, databases, and more.

Full guide: [Credential Testing](Credential-Testing.md).

```bash
cygor credrecon --help
cygor credrecon --protocol ssh -f ssh-hostlist.txt
```

---

## `cygor workspace`

Workspaces keep per-engagement results, scan files, and databases isolated.

| Subcommand | Action |
|---|---|
| `cygor workspace` *(no args)* | Show the active workspace, other registered ones, and the available commands |
| `cygor workspace create <path>` | Create a workspace at `<path>` (activates the first one automatically) |
| `cygor workspace use <name\|path>` | Switch to one — by name, or any directory path (registers it on the fly) |
| `cygor workspace info <name>` | Show subdirectories, size breakdown, timestamps |
| `cygor workspace clean` | Trim old scan output (use `--keep-last N` / `--dry-run`) |
| `cygor workspace remove <name>` | Unregister; files preserved |
| `cygor workspace none` | Deactivate (stop writing to any workspace) |
| `cygor workspace path` | Print the active path on stdout (designed for shell scripts) |

Full guide: [Setting Up Workspaces](Setting-Up-Workspaces.md).

```bash
cygor workspace create ~/cygor-pentest-acme
cygor workspace use acme
cygor workspace            # status dashboard
cd "$(cygor workspace path)"
```

---

## `cygor proxy`

Configure an HTTP/HTTPS/SOCKS proxy for outbound traffic from Cygor and wrapped tools.

```bash
cygor proxy --help
cygor proxy set http://127.0.0.1:8080
cygor proxy status
cygor proxy clear
```

The proxy applies to enrichment lookups and any external tool invoked through `wrap_external()`.

---

## `cygor plugin`

Manage community plugins. Plugins live in `~/.cygor/plugins/` (or `$CYGOR_PLUGIN_DIR`) and integrate with the same `cygor enum` interface as built-in modules.

| Subcommand | Action |
|---|---|
| `cygor plugin list` | Show every installed plugin (slug, version, path, status) |
| `cygor plugin install <source>` | Install from a `.py` file or git URL |
| `cygor plugin validate <path>` | Validate a `.py` file without installing |
| `cygor plugin create <name>` | Scaffold a new plugin |
| `cygor plugin update [slug] [--all]` | Re-validate / `git pull` |
| `cygor plugin remove <slug>` | Remove an installed plugin |

Full guide: [Plugin Development](Plugin-Development.md).

```bash
cygor plugin create "My Scanner"
cygor plugin install https://github.com/example/cygor-myscanner
cygor plugin list
```

---

## `cygor sync`

Refresh data sources Cygor depends on.

| Subcommand | What it updates |
|---|---|
| `cygor sync` *(no args)* | Show status of every sync source |
| `cygor sync fingerprints` | Huginn-Muninn / Satori / OUI / cloud IP ranges |
| `cygor sync plugins` | Update installed community plugins |
| `cygor sync all` | Run every source in sequence |

```bash
cygor sync
cygor sync fingerprints
cygor sync all
```

---

## `cygor web`

Run the Web UI.

| Subcommand | Action |
|---|---|
| `cygor web start` | Start the server |
| `cygor web stop` | Stop a running server |
| `cygor web status` | Show PID + log path |

`cygor web start` flags:

| Flag | Description |
|---|---|
| `-H HOST` | Bind address (default `127.0.0.1`) |
| `-p PORT` | Port (default `8000`) |
| `--load-dir DIR` | Pre-load this results directory |
| `--workspace DIR` | Override the active workspace |
| `--db-url URL` | Explicit DB connection string |
| `--reset-db` | Drop and recreate the schema, then exit |
| `--debug` | Debug logging (equivalent to `-vv`) |
| `-v` / `-vv` | Verbose / debug verbosity |

Full guide: [Web UI Quick Start](Web-UI-Quick-Start.md).

```bash
cygor web start
cygor web start -H 0.0.0.0 -p 8080 --load-dir ~/scan-results
cygor web start --reset-db   # ⚠ destructive
```

---

## `cygor setup-privileges`

Grant Nmap / Masscan / Naabu the raw-socket capabilities they need, so `cygor scan` doesn't have to run as root.

```bash
cygor setup-privileges --help
```

Without this you'll keep needing `sudo cygor scan ...`.

---

## `cygor banner`

Print the full ASCII banner. Pure vanity, useful for screenshots.

```bash
cygor banner
```

---

## Tips

- Every command supports `-h` / `--help` with the canonical, current option list — this page is a quick-reference, but the source of truth is `--help`.
- `--verbose` / `-v` and `-vv` are universal across most subcommands.
- Commands that need root are marked `[sudo]` in `cygor -h`. Use [`setup-privileges`](#cygor-setup-privileges) once and never `sudo` again.
- For programmatic use, `cygor enum <slug>` always emits `cygor-result.json` — see [Data Ingestion & Web UI](Data-Ingestion-And-Web-UI.md) for the schema.
