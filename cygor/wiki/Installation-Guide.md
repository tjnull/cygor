# Installation Guide

This guide covers every way to install Cygor and the external tools its modules wrap.

## Prerequisites

- Python 3.10 or higher (tested through 3.13)
- Root/sudo privileges for scanning operations (Nmap raw sockets, Masscan)
- Network access for downloading dependencies

## Installation Methods

### Method 1: pipx (recommended)

`pipx` installs Cygor into an isolated venv, avoiding dependency conflicts with system Python.

```bash
# From source (until PyPI builds are published)
git clone https://github.com/tjnull/cygor
cd cygor
pipx install .

# Update after pulling latest changes
pipx install --force .
```

Verify:

```bash
cygor --help
```

### Method 2: pip / venv

```bash
python3 -m venv cygor-env
source cygor-env/bin/activate
pip install .                # from a source checkout
```

### Method 3: uv

```bash
uv tool install .            # from a source checkout
```

### Method 4: Docker

See **Docker Deployment Guide** for the full Compose setup.

```bash
docker compose up --build
```

## Post-Installation: External Tools

Cygor wraps proven external tools — install only the ones you need.

### Scanning

| Tool | Purpose | Install |
|---|---|---|
| **Nmap** | Service/version detection (the engine `cygor scan` drives) | `sudo apt install nmap` · `sudo dnf install nmap` · `brew install nmap` |
| **Masscan** | High-speed discovery | `sudo apt install masscan` or build from [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) |
| **Naabu** | Fast TCP discovery | Download from [projectdiscovery/naabu releases](https://github.com/projectdiscovery/naabu/releases); Cygor will also attempt a download on first use |

### Web Content Discovery (`webenum` module)

Only the installed tools run — install any subset.

| Tool | Install |
|---|---|
| **ffuf** | `sudo apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest` |
| **feroxbuster** | [Cargo / release binaries](https://github.com/epi052/feroxbuster) |
| **gobuster** | `sudo apt install gobuster` or `go install github.com/OJ/gobuster/v3@latest` |
| **dirsearch** | `pipx install dirsearch` (only needed for `--tools all`) |

### Screenshot Capture (`lockon` module)

```bash
# Cygor auto-installs Chromium on first web capture; to pre-install:
python -m playwright install chromium

# If the browser fails to launch, also install its system libraries:
sudo python -m playwright install-deps chromium
```

### Enumeration modules (install per-protocol as needed)

| Module | External tool(s) |
|---|---|
| `smbexplorer` | `smbclient`, `smbmap` (impacket bundled) |
| `nfsexplorer` | `nfs-common` (`showmount`) |
| `rpcexplorer` | `rpcclient`, optionally `polenum` |
| `ldapexplorer` | `ldap-utils` (`ldapsearch`), optionally `ldapdomaindump` |
| `snmpexplorer` | `snmp` (`snmpwalk`, `snmpget`), optionally `onesixtyone` |
| `dnsexplorer` | `dnsutils` (`dig`), optionally `dnsrecon` |
| `ftpexplorer` | (Python stdlib — no external tool) |
| `smtpexplorer` | (Python stdlib — no external tool) |
| `dbprobe` | (Python stdlib — no external tool) |

Modules skip cleanly with a clear message if their tool isn't installed.

## Quick Verification

```bash
cygor --help                       # top-level help
cygor scan --help                  # scanner options
cygor enum --list                  # registered modules
cygor plugin list                  # installed plugins
cygor web start --help             # web UI options
```

## Initialize a Workspace (optional)

Workspaces keep per-engagement results, scan files, and databases isolated.

```bash
cygor workspace init ~/cygor-workspace
cygor workspace set-default ~/cygor-workspace
cygor workspace show
```

## Test the Install

```bash
# Tiny scan on localhost (requires sudo)
sudo cygor scan -i lo -ips 127.0.0.1 --discover naabu --scan-type top-ports

# Start the web UI
cygor web start
# → http://127.0.0.1:8000
```

## Troubleshooting

### Permission errors during scans
Nmap/Masscan need raw-socket privileges:

```bash
sudo -v
which nmap masscan
# Optional: grant capabilities so cygor scan no longer needs sudo
cygor setup-privileges
```

### Python version
Cygor requires Python ≥ 3.10:

```bash
python3 --version
```

If your system Python is older, install a newer one (e.g. `pyenv install 3.12`) and reinstall Cygor against it.

### Dependency conflicts
Use `pipx` (isolated venv). If you need a third-party Python package available to Cygor (e.g. an extra dependency for a plugin):

```bash
pipx inject cygor <package>
```

### Lockon screenshots fail
If `lockon web` produces broken screenshots, the Playwright browser likely isn't installed:

```bash
python -m playwright install chromium
sudo python -m playwright install-deps chromium
```

### Database
Cygor auto-detects PostgreSQL; if not available it falls back to SQLite. No setup needed for SQLite. For PostgreSQL details see the **Docker Deployment Guide** (Compose ships one) or the README.

## Next Steps

Once installed, see:

- **[Setting Up Workspaces](Setting-Up-Workspaces.md)** — keep engagements isolated
- **[Enumeration Modules](Enumeration-Modules.md)** — the 11 built-in modules
- **[Plugin Development](Plugin-Development.md)** — write your own modules
