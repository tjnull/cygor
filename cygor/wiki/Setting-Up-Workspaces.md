# Setting Up Workspaces

Workspaces help organize your scan results, databases, and configuration in a centralized location.

## What is a Workspace?

A workspace is a directory that contains:
- Scan results (`nmap/`, `discovery/`)
- Parsed hostlists (`parsed-hostlists/`)
- Enumeration module outputs (`enum/`)
- Database files (`cygor.db` or PostgreSQL connection)
- Configuration files

## Workspace Commands

The command syntax mirrors msfconsole's `workspace`. Bare `cygor workspace`
lists, `cygor workspace <name>` switches, flags handle the rest. There is
always exactly one active workspace -- `default` is auto-created on first
use under `~/.cygor/workspaces/` (override the root with the
`$CYGOR_WORKSPACES_ROOT` environment variable).

### Add a Workspace

```bash
# Add a workspace (created at the default root and activated immediately)
cygor workspace -a my-engagement

# Or pin it to a custom path (shared drive, large engagement folder, …)
cygor workspace -a my-engagement --path /mnt/engagements/acme
```

This creates the directory structure:
```
my-engagement/
├── nmap/                       # Nmap scan results
├── parsed-hostlists/           # Parsed hostlists by service
├── credrecon/                  # Credential reconnaissance output
├── schedule-scans/             # Scheduled / automated scans
├── cygor-enumeration-modules/  # Per-module output (lockon, smbexplorer, …)
├── logs/                       # Runtime logs
└── cygor.db                    # SQLite database (if used)
```

### Switch the Active Workspace

```bash
# Switch by name (msfconsole-style bare positional)
cygor workspace my-engagement
```

### List, View, and Use in Scripts

```bash
# List workspaces -- the active one is marked with *
cygor workspace

# Detail view of one workspace (size, subdir file counts, timestamps)
cygor workspace --info my-engagement

# Just the active path (designed for shell substitution)
cd "$(cygor workspace --print-path)"
```

### Delete / Rename

```bash
# Delete from the registry (directory on disk is preserved)
cygor workspace -d my-engagement

# Delete *and* wipe the directory on disk (asks for confirmation)
cygor workspace -d my-engagement --purge

# Rename
cygor workspace -r old-name new-name
```

## Using Workspaces

### Automatic Workspace Detection

When a default workspace is set, Cygor automatically uses it:

```bash
# These commands use the default workspace
cygor scan -i eth0 -f scope.txt
cygor parse results/nmap
cygor web start
```

### Override Workspace

Override the default workspace for a single command:

```bash
# Use different workspace for this scan
CYGOR_WORKSPACE=/path/to/other-workspace cygor scan -i eth0 -f scope.txt

# Or use --workspace flag (if supported)
cygor web start --workspace /path/to/other-workspace
```

### Environment Variable

Set workspace via environment variable:

```bash
# Set for current session
export CYGOR_WORKSPACE=~/cygor-workspace

# Or in .bashrc/.zshrc for persistence
echo 'export CYGOR_WORKSPACE=~/cygor-workspace' >> ~/.bashrc
```

## Workspace Best Practices

### 1. Project-Based Workspaces

Create separate workspaces for different projects:

```bash
cygor workspace -a client-alpha
cygor workspace -a client-beta
cygor workspace -a internal-pentest
```

### 2. Shared vs. Personal Workspaces

- **Shared**: Use for team collaboration (ensure proper permissions)
- **Personal**: Use for individual testing and development

### 3. Workspace Organization

```
workspace/
├── scans/
│   ├── initial-discovery/
│   ├── full-port-scan/
│   └── targeted-scans/
├── enum/
│   ├── lockon/
│   ├── smbexplorer/
│   └── nfsexplorer/
└── reports/
```

### 4. Database Location

- **SQLite**: Database stored in workspace root (`cygor.db`)
- **PostgreSQL**: Database can be shared across workspaces via connection string

## Web UI and Workspaces

### Loading Workspace in Web UI

```bash
# Start web UI with workspace
cygor web start --load-dir ~/cygor-workspace

# Or use default workspace
cygor web start
```

### Multiple Workspaces

To switch between workspaces in the web UI:

1. Stop current web server: `cygor web stop`
2. Start with new workspace: `cygor web start --load-dir /path/to/new-workspace`

Or run multiple instances on different ports:

```bash
# Workspace 1 on port 8000
cygor web start --load-dir ~/workspace1 -p 8000

# Workspace 2 on port 8001
cygor web start --load-dir ~/workspace2 -p 8001
```

## Workspace Configuration

### Configuration File Location

Cygor stores workspace configuration in:
- `~/.config/cygor/config.json` (Linux/macOS)
- `%APPDATA%\cygor\config.json` (Windows)

### Manual Configuration

Edit the config file directly:

```json
{
  "active_workspace": "cygor-workspace",
  "workspaces": {
    "cygor-workspace": {
      "path": "/home/user/cygor-workspace",
      "created_at": "2026-01-01T00:00:00Z",
      "last_used":  "2026-01-01T00:00:00Z"
    }
  }
}
```

## Troubleshooting

### Workspace Not Found

```bash
# Check if workspace exists
ls -la ~/cygor-workspace

# Re-create if needed (also re-registers and re-activates)
cygor workspace -a my-engagement --path ~/cygor-workspace
```

### Permission Issues

```bash
# Ensure proper permissions
chmod -R 755 ~/cygor-workspace
chown -R $USER:$USER ~/cygor-workspace
```

### Database Conflicts

If using SQLite, each workspace has its own database. Switching workspaces means switching databases.

For shared databases, use PostgreSQL:

```bash
# Use PostgreSQL for all workspaces
export CYGOR_DB_URL=postgresql+psycopg_async://user:pass@localhost/cygor
```

## Next Steps

- [First Scan Tutorial](First-Scan-Tutorial.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)
- [Docker Deployment Guide](Docker-Deployment-Guide.md)

