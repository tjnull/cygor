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

### Initialize a Workspace

```bash
# Create a new workspace
cygor workspace init ~/cygor-workspace

# Or specify a custom path
cygor workspace init /opt/cygor/project-alpha
```

This creates the directory structure:
```
workspace/
├── nmap/              # Nmap scan results
├── discovery/         # Discovery results
├── parsed-hostlists/   # Parsed hostlists by service
├── enum/              # Enumeration module outputs
└── cygor.db           # SQLite database (if used)
```

### Set Default Workspace

```bash
# Set workspace as default
cygor workspace set-default ~/cygor-workspace

# This workspace will be used automatically for all commands
```

### View Current Workspace

```bash
# Show current workspace
cygor workspace show

# Output example:
# Current workspace: /home/user/cygor-workspace
# Default workspace: /home/user/cygor-workspace
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
cygor workspace init ~/workspaces/client-alpha
cygor workspace init ~/workspaces/client-beta
cygor workspace init ~/workspaces/internal-pentest
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
  "default_workspace": "/home/user/cygor-workspace"
}
```

## Troubleshooting

### Workspace Not Found

```bash
# Check if workspace exists
ls -la ~/cygor-workspace

# Reinitialize if needed
cygor workspace init ~/cygor-workspace
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

