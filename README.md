# Cygor

<div align="center">

[![cygor_banner](https://github.com/tjnull/cygor/blob/main/images/cygor-banner.jpg)](https://github.com/tjnull/cygor)

</div>

## General Overview
Cygor is a modular asset discovery framework that brings scanning, parsing, and service enumeration together in one workflow. It replaces the patchwork of separate tools with an automated process that handles discovery, enrichment, and targeted enumeration seamlessly — reducing manual overhead and letting you focus on results instead of tool management.

Cygor’s Web UI takes the chaos of raw scan data and organizes it into a single, visual command center. Instead of combing through endless XML, JSON, or flat text, results are automatically parsed, enriched, and displayed in one space that’s built for fast triage and decision-making.

Powered by FastAPI and Bootstrap 5, the dashboard makes it easy to:
- See the big picture at a glance — counters and summaries reveal service distributions, status code trends, and OS fingerprints.
- Dive deep instantly — pivot from high-level metrics into per-host details, ports, and module results with just a click.
- Visualize exposure — One of Cygor's modules called Lockon takes screenshots of active web services and outputs are embedded directly, giving immediate context without leaving the dashboard.
- Stay organized during triage — mark reviewed vs. unreviewed findings, filter and sort results, and zero in on the highest-value targets.

The Web UI isn’t just for presentation — it’s about efficiency and clarity. By bringing all collected data into a single, interactive workspace, it cuts down the time spent parsing files or reconciling outputs and lets testers focus on what matters: understanding the environment and acting on it.

## Why is it Called Cygor?
A lot of tools, techniques, and tradecrafts that I create are inspired from the Spawn Universe. If you have never read a Spawn comic, it's okay as I will share some information as to why I selected the character to be the name of this tool.

The name Cygor draws from Cy-Gor, a tragic anti-hero in the Spawn universe. Once Michael Konieczny — a government operative and close friend of Al Simmons — he tried to expose corruption after Simmons’s murder. However, he was captured and forced into Project Sim, the Simian experiments of Dr. Frederick Willheim, where a gorilla’s body was merged with Konieczny’s mind through invasive cybernetics. The result was the beast known as Cy-Gor — short for Cybernetic Gorilla.

After escaping captivity, Cy-Gor went on violent rampages, even tearing through government data centers in fits of confusion and rage. Though hunted and recaptured multiple times, he eventually fought back against the systems that sought to control him — removing tracking implants and breaking free to forge his own path, torn between machine, beast, and man.

- Reference: https://www.spawnworld.com/encyclopedia/cygor.htm

## Who Should Use Cygor?
- Red Teams & Pentesters – Automate discovery, streamline enumeration, and maintain context across large engagements
- Blue Teams & System Administrators – Uncover unknown assets, validate inventories, and spot misconfigurations that expand attack surface.
- Security Researchers – Rapidly parse and analyze scan data to identify trends, overlooked services, and identify patterned anomalies.
- Students & Instructors – Learn real-world recon and enumeration techniques in a structured, repeatable environment.

# Tools that Cygor uses:
- Nmap – Reliable service and version detection; XML output is parsed into structured host/service data.
- Masscan – High-speed port scanning for rapid discovery across large networks.
- Naabu – Simple, fast TCP port scanner that complements Masscan/Nmap workflows.
- Playwright – Browser automation engine leveraged by Lockon to capture web screenshots.
- Web content discovery – ffuf, feroxbuster, gobuster, and dirsearch are orchestrated in parallel by the `webenum` module (only the installed tools run).
- Service enumeration tooling – rpcclient/polenum (MSRPC), ldapsearch/ldapdomaindump (LDAP), snmpwalk/onesixtyone (SNMP), dig/dnsrecon (DNS), and showmount (NFS) back the explorer modules; each module skips cleanly if its tool is absent.
- Python libraries – (requests, colorama, SQLModel, etc.) for parsing, enrichment, output formatting, and database handling.

# Installing Cygor
There are a few methods that are supported to install Cygor: pip, pipx, uv, and docker.

## Installing With pipx

Some dependencies (e.g. `gssapi` for Kerberos/WinRM) build C extensions, so install the build toolchain and Kerberos headers first:

```bash
# Debian/Ubuntu/Kali:
sudo apt install -y build-essential python3-dev libkrb5-dev
```

```bash
# Stable version:
pipx install cygor

# Install from source:
git clone https://github.com/tjnull/cygor
cd cygor
pipx install .
```

## Deploying Cygor Using Docker

Cygor's Docker setup includes both the application and a PostgreSQL database service. The system automatically falls back to SQLite if PostgreSQL is unavailable.

### Quick Start

**Production (recommended):**
```bash
# Option 1: Use the wrapper script (automatically handles port conflicts)
./docker-compose-up.sh up --build

# Option 2: Direct docker compose (uses default ports)
docker compose up --build
```

**Development (with source code mounted):**
```bash
# Option 1: Use the wrapper script (automatically handles port conflicts)
./docker-compose-up.sh dev up --build

# Option 2: Direct docker compose (uses default ports)
docker compose -f docker-compose-dev.yaml up --build
```

### Docker Compose Services

The Docker Compose setup includes:

- **PostgreSQL Service**: Automatically configured database (falls back to SQLite if unavailable)
- **Cygor Service**: Web UI and application
- **Automatic Port Detection**: Checks for port conflicts and uses alternative ports if needed
- **Persistent Volumes**: 
  - `results/`: Scan outputs, credrecon results, and database files
  - `cygor-config/`: Local config volume (created automatically)

### Port Configuration

By default:
- **Production**: PostgreSQL exposed on host port `5432` (if available)
- **Development**: PostgreSQL exposed on host port `5434` (if available)
- **Internal**: Containers always use port `5432` internally (Docker network)

If ports are in use, you can:

1. **Use the wrapper script** (recommended - auto-detects available ports):
   ```bash
   ./docker-compose-up.sh up --build
   ```

2. **Set port manually**:
   ```bash
   export POSTGRES_HOST_PORT=5435
   docker compose up --build
   ```

3. **Remove port mapping** (if you don't need external PostgreSQL access):
   Comment out the `ports:` section in `docker-compose.yaml`

### Manual Docker Build

To build the Docker image manually:

```bash
docker build -t cygor .
```

Run a single container (without PostgreSQL service):

```bash
docker run --rm -v ./results:/opt/cygor/results \
  -e CYGOR_RESULTS_DIR=/opt/cygor/results \
  cygor web --host 0.0.0.0 --port 8080 --load-dir /opt/cygor/results
```

### Database Behavior

- **With Docker Compose**: Uses PostgreSQL service (automatically configured)
- **If PostgreSQL fails**: Automatically falls back to SQLite
- **Standalone container**: Uses SQLite by default (unless `CYGOR_DB_URL` is set)

### Environment Variables

Key environment variables for Docker:

**Data & Workspace:**
- `CYGOR_RESULTS_DIR`: Results directory (default: `/opt/cygor/results`)
- `CYGOR_WORKSPACE`: Workspace directory (default: `/opt/cygor/results`)
- `CYGOR_RESULTS_PATH`: Host path for results volume (default: `./results`)
- `CYGOR_CONFIG_PATH`: Host path for authentication config volume (default: `./cygor-config`)

**Database:**
- `CYGOR_DB_URL`: Database connection string (auto-set by docker-compose)
- `CYGOR_DB_USER`: PostgreSQL database user (default: `cygor`)
- `CYGOR_DB_PASSWORD`: PostgreSQL database password
- `POSTGRES_HOST_PORT`: PostgreSQL host port mapping (for port conflict resolution)

**Debug & Verbosity:**
- `CYGOR_DEBUG`: Enable debug mode (set to `1` to enable)
- `CYGOR_VERBOSE`: Verbosity level (`0`=normal, `1`=verbose, `2`=debug)

# Documentation
Detailed guides live in [`cygor/wiki/`](cygor/wiki/) — installation, the 11 built-in enumeration modules, plugin development, workspace management, and more. GitHub renders the directory as a navigable docs site (start at [`cygor/wiki/README.md`](cygor/wiki/README.md)). The same pages are also served by the web UI at `/docs` once you run `cygor web start`.

# Running Cygor
Use the top-level Cygor command to access the available tools. Each subcommand has its own help screen (Cygor <command> --help) that documents flags and actions.

```bash
tjnull@kali:~$ cygor
Usage:
  cygor <command> [args]

Commands:
  banner      Cygor tool banner (Warning it is large!)
  scan        Automated scanner to discover hosts and services. (Will require root/sudo privileges for scanning).
  parse       Analyze a NMAP scan file (nmap, gnmap, xml) and extract categorized hostlists by common service.
  enum        Loads enumeration modules that are located in the cygor modules directory. 
  workspace   Manage workspaces (init/set-default/show).
  web         Control/launch the Cygor Web UI (start/stop/status) or run directly.

Environment:
  CYGOR_WORKSPACE     Override default workspace just for this run.
  CYGOR_RESULTS_DIR   Used by web and modules if set. (Auto-set from default workspace.)

```

## Cygor scanner
You will need `sudo` (`root`) privileges to run the scanner in `cygor`:

```bash
    Run host discovery with Masscan only:

    cygor scan -i eth0 -f scope.txt --discover masscan

    Run host discovery with both Masscan and Naabu, then Nmap on merged results:

    cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge

    Discovery only (no Nmap), save results in results/discovery/:

    cygor scan -i eth0 -f scope.txt --discover masscan naabu --discover-only

    Reuse saved discovery results for Nmap top ports scan:

    cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type top-ports

    Run Nmap with custom ports on discovered hosts:

    cygor scan --use-discovery results/discovery/masscan-discovered.txt --ports 80,443,8443

    Run Nmap with 10 parallel processes on full scope (Max is 100):

    \cygor scan -i eth0 -f scope.txt --discover naabu --processes 10 --scan-type fullscan:

    Run Cygor to discover hosts and scan them with Nmap with a provided lists of IP Addresses or CDRs:

    cygor scan -i eth0 --ips 10.10.10.1 10.10.10.5 10.10.20.0/24 --discover naabu --processes 10 --scan-type fullscan

    Exclude specific subnets or hosts from scan:

    cygor scan -i eth0 -f scope.txt --exclusions exclusions.txt --discover masscan

```

## Cygor Parser:
```bash
    Parse a directory of Nmap results and print hostlists:

    cygor parse results/nmap

    Parse a single XML and write hostlists to results/parsed-hostlists:

    cygor parse results/nmap/scan1.xml -o results

    Recursively parse .xml/.nmap/.gnmap files and write outputs:

    cygor parse /path/to/scans --out-dir results
```

## Cygor Enumeration Modules
Cygor ships a growing set of protocol-specific enumeration modules. Each one wraps proven tooling, parses the output into typed rows ("parse-don't-dump"), and lands the results in the inventory (DB + Web UI) where they're searchable and correlatable by host. High-signal observations are also fed automatically into the **next-steps engine**, which surfaces prioritized findings and ready-to-run follow-up commands in the Web UI.

| Module | Service | What it does |
|---|---|---|
| `lockon` | HTTP/S, RDP, VNC, X11 | Captures screenshots across protocols for fast visual triage. |
| `webenum` | HTTP/S | Parallel multi-tool content discovery (ffuf, feroxbuster, gobuster, dirsearch) with cross-tool dedup/correlation and optional screenshots. |
| `smbexplorer` | SMB (445) | Enumerates shares, permissions, and accessible files; NTLM/Kerberos/pass-the-hash. |
| `nfsexplorer` | NFS (2049) | Enumerates exports, versions, and files; UID/GID spoofing and `no_root_squash` checks. |
| `rpcexplorer` | MSRPC (445) | Null/auth session: server info, domain SID, users, groups, full password policy, and RID cycling. |
| `ldapexplorer` | LDAP/AD (389/636) | rootDSE, anonymous bind/search, and authenticated domain dump. |
| `snmpexplorer` | SNMP (161) | v1/v2c community brute, device system info, and a MIB sweep (users/processes/software/ports/interfaces). |
| `dnsexplorer` | DNS (53) | Version, open-resolver detection, and AXFR zone transfer. |
| `ftpexplorer` | FTP (21) | Banner, anonymous login, directory listing, FEAT, anonymous write test. |
| `smtpexplorer` | SMTP (25/587) | Banner, STARTTLS, AUTH mechanisms, VRFY user-enum, open-relay test. |
| `dbprobe` | Databases | Probes Redis/MySQL/PostgreSQL/MongoDB/Elasticsearch/CouchDB for unauth access and version. |

```bash
    List all available modules:

    cygor enum --list

    Run lockon against an http hostlist:

    cygor enum lockon web -f results/parsed-hostlists/http/http-hostlist.txt -o results/enum/lockon

    Run web content discovery (multi-tool, with screenshots):

    cygor enum webenum -f results/parsed-hostlists/http-https/http-https-hostlist.txt --screenshot

    Run nfsexplorer against NFS targets (exports only):

    cygor enum nfsexplorer -i results/parsed-hostlists/nfs/nfs-hostlist.txt --info

    Run smbexplorer and list files:

    cygor enum smbexplorer -i results/parsed-hostlists/smb/smb-hostlist.txt --list-files

    Enumerate MSRPC (null session) with password policy + RID cycling:

    cygor enum rpcexplorer -i results/parsed-hostlists/smb/smb-hostlist.txt --rid-cycle

    Probe databases for unauthenticated access (point at any DB service hostlist):

    cygor enum dbprobe -i results/parsed-hostlists/mysql/mysql-hostlist.txt
```

Run `cygor enum <module> --help` for the full per-module option reference.

## Cygor Plugins
Cygor is extensible — drop a Python file into `~/.cygor/plugins/` and it shows up under `cygor enum --list` (and in the Web UI) like any built-in module. Wrap your own tools, ship internal scanners across your team, or extend Cygor for a specific engagement without forking it.

```bash
    Scaffold a new plugin (writes ~/.cygor/plugins/my_scanner.py):

    cygor plugin create "My Scanner"

    Install a plugin from a local file or a git URL:

    cygor plugin install ./my_scanner.py
    cygor plugin install https://github.com/example/cygor-myscanner

    Validate, list, update, remove:

    cygor plugin validate ./my_scanner.py
    cygor plugin list
    cygor plugin update --all
    cygor plugin remove my_scanner

    Run an installed plugin (same as a built-in module):

    cygor enum my_scanner -t 10.10.10.5
```

Three reference plugins live under [docs/examples/modules/](docs/examples/modules/): a minimal example, an external-tool wrapper, and a full annotated template. See the **[Plugin Development Guide](docs/plugins.md)** for the full plugin format, options/columns/views, dependency handling, version compatibility, and the optional plugin allowlist.

## Cygor Web UI
After collecting data, you can load it into Cygor's Web UI to transform scan results into a clear visualization of hosts, services, and other key findings. Cygor will create a file called cygor.db that will contain the necessary data to model into Cygor's Web UI

### Starting the Web Server

```bash
# Basic usage - start on default host/port (127.0.0.1:8000)
cygor web start

# Start on all interfaces, port 8080
cygor web start -H 0.0.0.0 -p 8080

# Start with custom results directory
cygor web start --load-dir /path/to/results

# Start with verbose output
cygor web start -vv

# Start with all options
cygor web start -H 0.0.0.0 -p 8080 --load-dir ~/scan-results -vv
```

### Command-Line Options

Run `cygor web start --help` for the full list of options.

### Web Server Management

```bash
# Check if the web server is running
cygor web status

# Stop a running web server
cygor web stop
```

### Database Options

Cygor automatically detects and uses PostgreSQL if available, otherwise falls back to SQLite:

- **PostgreSQL** (recommended for production):
  - Automatically detected if `psql` is available
  - Creates database and user if needed
  - Connection string: `postgresql+psycopg_async://user:pass@host/db`
  
- **SQLite** (default fallback):
  - No setup required
  - Database file: `cygor.db` in the results directory
  - Suitable for single-user deployments

# Disclaimer:
Cygor is a security research and educational framework. It is intended to be used only in environments where you have explicit, written authorization — such as penetration testing engagements, red team operations, classroom labs, or personal test ranges.

This software must not be used for unauthorized access, intrusion, or disruption of systems you do not own or control. Doing so may violate laws and regulations in your jurisdiction, and could result in criminal prosecution or civil penalties.

By downloading, running, or modifying Cygor, you agree that:
- You are solely responsible for how you use it.
- You will restrict its use to legal and ethical scenarios.

The authors and contributors of Cygor accept no liability for misuse, damage, or consequences arising from the use of this software.

If you are uncertain whether you are authorized to use Cygor in a given environment, do not run it.
