# Web UI Quick Start

Get started with Cygor's web interface in minutes.

## Starting the Web Server

### Basic start

```bash
# 127.0.0.1:8000
cygor web start
```

Open `http://localhost:8000`.

### Custom host/port

```bash
cygor web start -H 0.0.0.0 -p 8080
```

### Pre-load results

```bash
cygor web start --load-dir ~/scan-results
```

### Debug / verbose

```bash
cygor web start --debug
cygor web start -vv
```

## First-time setup

1. Start the server (`cygor web start`).
2. Open `http://localhost:8000`.
3. Either pre-load results with `--load-dir`, or run a scan in another terminal — the workspace is watched and new results appear on refresh.

## Key features

### Dashboard

- Host & port counts
- Service-type distribution
- OS-fingerprint breakdown
- HTTP status-code distribution
- Quick-stat cards for triage

### Hosts view

- All discovered hosts with IPs
- Click any host for: open ports, services, OS detection, raw scan output, module results (screenshots, SMB shares, RPC enumeration, etc.)

### Modules view

The rows produced by each [enumeration module](Enumeration-Modules.md). Only modules with data appear in the sidebar — runs you've executed show up automatically:

- **lockon** — HTTP/S, RDP, VNC, X11 screenshots
- **webenum** — web content discovery with cross-tool dedup
- **smbexplorer / nfsexplorer** — shares & exports
- **rpcexplorer** — MSRPC: users, groups, password policy, RID cycling
- **ldapexplorer** — rootDSE, anonymous bind, authenticated dump
- **snmpexplorer** — community brute + MIB sweep
- **dnsexplorer / ftpexplorer / smtpexplorer / dbprobe**

### Documentation

Browse this wiki right inside the UI at `/docs` (or via **Help → Documentation** in the top-right). Pages are rendered from `cygor/wiki/*.md` and stay in sync with the installed version.

### Search

Use the global search to find hosts (by IP), services, ports, and module results.

## Navigation

### Sidebar

- **Dashboard** — overview
- **Hosts** — host listing and detail
- **Services** — service listing
- **Modules** — enumeration results (only modules with data appear)
- **Settings** — workspace/database/plugins configuration

### Keyboard

| Key | Action |
|---|---|
| `/` | Focus the search bar |
| `Esc` | Close modals / dropdowns |

## Loading scan results

### Via command line

```bash
cygor web start --load-dir ~/scan-results
```

### Automatic detection

The web UI scans the active workspace for:

- `nmap/*.xml`
- `nmap/*.nmap`
- `nmap/*.gnmap`
- `cygor-enumeration-modules/<slug>/cygor-result.json`

New files added during a session appear on refresh.

### PostgreSQL

If a PostgreSQL DB is configured, results persist across sessions. SQLite is the default fallback. See [Setting Up Workspaces](Setting-Up-Workspaces.md) for workspace + DB configuration.

## Server management

```bash
# Check status (PID, log path)
cygor web status

# Stop
cygor web stop

# Follow logs
tail -f results/cygor-web.log

# Or whatever 'cygor web status' reports as the log path
```

## Common workflows

### Quick view of results

```bash
# 1. Run a scan
sudo cygor scan -i eth0 -f scope.txt --discover naabu

# 2. Start the UI with results
cygor web start --load-dir results

# 3. Open http://localhost:8000
```

### Continuous monitoring

```bash
# 1. Start the UI on a workspace
cygor web start --load-dir ~/workspace

# 2. Run scans in another terminal — results appear on refresh
sudo cygor scan -i eth0 -f scope.txt --discover naabu
```

### LAN-accessible viewing

```bash
# Bind all interfaces; share the URL on the LAN
cygor web start -H 0.0.0.0 -p 8080
```

> Cygor has no built-in authentication. Don't expose `0.0.0.0:8080` to untrusted networks — keep it on localhost, behind a VPN, or behind a reverse proxy with auth.

## Troubleshooting

### Port already in use

```bash
# Try another port
cygor web start -p 8081

# Or find what's holding it
sudo lsof -i :8000
```

### Can't reach from another machine

```bash
# Bind 0.0.0.0
cygor web start -H 0.0.0.0 -p 8080

# Check firewall
sudo ufw allow 8080
```

### Results not showing

- Verify the load-dir / workspace path.
- Confirm scan files are under `nmap/` (or `cygor-enumeration-modules/<slug>/`).
- Check formats (`.xml`, `.nmap`, `.gnmap`, `cygor-result.json`).
- Tail the log: `tail -f results/cygor-web.log`.
- Force a fresh DB: `cygor web start --reset-db` *(destructive — drops the schema)*.

### Database errors

```bash
# Reset the schema (deletes all DB data, results files are untouched)
cygor web start --reset-db

# Provide an explicit DB URL
cygor web start --db-url postgresql+psycopg_async://user:pass@localhost/cygor
```

## Next Steps

- [Enumeration Modules](Enumeration-Modules.md) — what the Modules view shows
- [Data Ingestion & Web UI](Data-Ingestion-And-Web-UI.md) — how module output becomes Web UI rows
- [Setting Up Workspaces](Setting-Up-Workspaces.md) — isolate engagements / configure storage
- [Plugin Development](Plugin-Development.md) — write a module that appears in the Modules view
