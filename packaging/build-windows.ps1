#Requires -Version 5.1
<#
.SYNOPSIS
    Build a portable Windows zip for Cygor.

.DESCRIPTION
    Builds a standalone cygor.exe using PyInstaller on Windows, bundles nmap,
    and produces a release zip: cygor-VERSION-windows-x64.zip

.PARAMETER Version
    Cygor version string (default: 1.0.0)

.PARAMETER NmapVersion
    Nmap version to bundle (default: 7.95)

.EXAMPLE
    .\packaging\build-windows.ps1
    .\packaging\build-windows.ps1 -Version 2.0.0 -NmapVersion 7.95
#>

param(
    [string]$Version = "1.0.0",
    [string]$NmapVersion = "7.95"
)

$ErrorActionPreference = 'Stop'

# ── Variables ────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$ReleaseDir  = "cygor-windows-x64"
$ZipFile     = "cygor-${Version}-windows-x64.zip"
$NmapZipUrl  = "https://nmap.org/dist/nmap-${NmapVersion}-win32.zip"
$NmapZipFile = "nmap-${NmapVersion}-win32.zip"

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Info  { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn  { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err   { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

# ── Banner ───────────────────────────────────────────────────────────────────
Write-Host "============================================" -ForegroundColor White
Write-Host "  Cygor Windows Build"                        -ForegroundColor White
Write-Host "  Version      : $Version"                    -ForegroundColor White
Write-Host "  Nmap Version : $NmapVersion"                -ForegroundColor White
Write-Host "  Output       : $ZipFile"                    -ForegroundColor White
Write-Host "============================================" -ForegroundColor White
Write-Host ""

# ── Step 1: Verify Python 3.11+ ─────────────────────────────────────────────
Write-Info "Checking Python version..."

try {
    $pythonVersion = & python --version 2>&1
    if ($pythonVersion -match 'Python (\d+)\.(\d+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
            Write-Err "Python 3.11+ required, found: $pythonVersion"
            exit 1
        }
        Write-Ok "Found $pythonVersion"
    } else {
        Write-Err "Could not parse Python version: $pythonVersion"
        exit 1
    }
} catch {
    Write-Err "Python is not installed or not on PATH"
    Write-Err "Install Python 3.11+ from https://www.python.org/downloads/"
    exit 1
}

# ── Step 2: Install Python dependencies ──────────────────────────────────────
Write-Info "Installing Python dependencies..."

Set-Location $ProjectRoot

& python -m pip install --upgrade pip wheel setuptools
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to upgrade pip"; exit 1 }

& python -m pip install pyinstaller
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to install PyInstaller"; exit 1 }

& python -m pip install -e .
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to install cygor"; exit 1 }

Write-Ok "Python dependencies installed"

# ── Step 3: Create entry point ───────────────────────────────────────────────
Write-Info "Creating PyInstaller entry point..."

$entryPoint = @"
#!/usr/bin/env python3
import sys
from cygor.cli import main
if __name__ == "__main__":
    sys.exit(main())
"@

Set-Content -Path "cygor_entry.py" -Value $entryPoint -Encoding UTF8
Write-Ok "Created cygor_entry.py"

# ── Step 4: Run PyInstaller ──────────────────────────────────────────────────
Write-Info "Running PyInstaller..."

# Build the static files argument
$staticArg = @()
if (Test-Path "cygor/webapp/static") {
    $staticArg = @("--add-data", "cygor/webapp/static;cygor/webapp/static")
}

# Collect-submodules (same as build-common.sh)
$collectSubmodules = @(
    # Core application
    "--collect-submodules", "cygor"
    # Web framework
    "--collect-submodules", "fastapi"
    "--collect-submodules", "uvicorn"
    "--collect-submodules", "starlette"
    # Database / ORM
    "--collect-submodules", "sqlalchemy"
    "--collect-submodules", "alembic"
    "--collect-all", "pydantic_core"
    "--collect-all", "pydantic"
    "--collect-submodules", "aioodbc"
    "--collect-submodules", "asyncmy"
    "--collect-submodules", "oracledb"
    # Auth / crypto / certs
    # Templating / reports
    "--collect-submodules", "jinja2"
    # Scheduling
    "--collect-submodules", "apscheduler"
    # CredRecon protocol libraries
    "--collect-submodules", "impacket"
    "--collect-submodules", "paramiko"
    "--collect-submodules", "ldap3"
    "--collect-submodules", "cassandra"
    "--collect-submodules", "neo4j"
    "--collect-submodules", "aardwolf"
    "--collect-submodules", "paho"
    "--collect-submodules", "scapy"
    "--collect-submodules", "pysnmp"
)

# Hidden imports (same as build-common.sh EXCEPT gssapi and winrm - not available on Windows)
$hiddenImports = @(
    # Scanning / parsing
    "--hidden-import", "libnmap.parser"
    "--hidden-import", "smbmap"
    "--hidden-import", "bs4"
    "--hidden-import", "scapy"
    "--hidden-import", "scapy.all"
    # Web framework
    "--hidden-import", "sqlmodel"
    "--hidden-import", "starlette"
    "--hidden-import", "starlette.responses"
    "--hidden-import", "markupsafe"
    "--hidden-import", "aiohttp"
    "--hidden-import", "httpx"
    "--hidden-import", "requests"
    # Database drivers
    "--hidden-import", "psycopg"
    "--hidden-import", "psycopg2"
    "--hidden-import", "aiosqlite"
    "--hidden-import", "aioodbc"
    "--hidden-import", "asyncmy"
    "--hidden-import", "oracledb"
    "--hidden-import", "pymysql"
    "--hidden-import", "pymssql"
    "--hidden-import", "pymongo"
    "--hidden-import", "bson"
    "--hidden-import", "redis"
    "--hidden-import", "pyodbc"
    # Database migrations
    "--hidden-import", "alembic"
    "--hidden-import", "alembic.config"
    "--hidden-import", "alembic.command"
    # Reporting / data
    "--hidden-import", "rich"
    "--hidden-import", "PIL"
    "--hidden-import", "tabulate"
    # Crypto / auth
    "--hidden-import", "cryptography"
    "--hidden-import", "pyOpenSSL"
    # System / utilities (gssapi excluded - not available on Windows)
    "--hidden-import", "paramiko"
    "--hidden-import", "psutil"
    "--hidden-import", "pytz"
    "--hidden-import", "watchfiles"
    "--hidden-import", "lxml"
    "--hidden-import", "platformdirs"
    "--hidden-import", "pydantic_core._pydantic_core"
    "--hidden-import", "colorama"
    "--hidden-import", "yaml"
    "--hidden-import", "packaging"
    "--hidden-import", "packaging.version"
    "--hidden-import", "dateutil"
    "--hidden-import", "dateutil.parser"
    # CredRecon protocol libraries
    "--hidden-import", "impacket"
    "--hidden-import", "impacket.smbconnection"
    "--hidden-import", "pysnmp"
    "--hidden-import", "pysnmp.hlapi"
    "--hidden-import", "pyghmi"
    "--hidden-import", "pyghmi.ipmi"
    "--hidden-import", "pyghmi.ipmi.command"
    "--hidden-import", "paho"
    "--hidden-import", "paho.mqtt"
    "--hidden-import", "paho.mqtt.client"
    "--hidden-import", "vncdotool"
    "--hidden-import", "vncdotool.api"
    "--hidden-import", "cassandra"
    "--hidden-import", "cassandra.cluster"
    "--hidden-import", "cassandra.auth"
    "--hidden-import", "neo4j"
    "--hidden-import", "aardwolf"
    "--hidden-import", "aardwolf.connection"
    "--hidden-import", "rdpy"
    "--hidden-import", "twisted"
    "--hidden-import", "pyNfsClient"
    "--hidden-import", "pyVmomi"
    "--hidden-import", "pyVim"
    "--hidden-import", "pyVim.connect"
)

# Add-data (Windows uses ; separator)
$addData = @(
    "--add-data", "cygor/webapp/templates;cygor/webapp/templates"
    "--add-data", "cygor/credrecon;cygor/credrecon"
    "--add-data", "cygor/webapp/alembic;cygor/webapp/alembic"
    "--add-data", "cygor/banner.txt;cygor"
)

# Metadata and hooks
$metadataFlags = @(
    "--copy-metadata", "pydantic_core"
    "--copy-metadata", "pydantic"
    "--copy-metadata", "sqlalchemy"
    "--copy-metadata", "uvicorn"
    "--copy-metadata", "fastapi"
    "--copy-metadata", "starlette"
    "--additional-hooks-dir", "packaging/hooks"
)

$pyinstallerArgs = @(
    "--onefile", "--clean", "--noconfirm", "--console", "--name", "cygor"
) + $addData + $metadataFlags + $staticArg + $collectSubmodules + $hiddenImports + @("cygor_entry.py")

& pyinstaller @pyinstallerArgs
if ($LASTEXITCODE -ne 0) { Write-Err "PyInstaller build failed"; exit 1 }

Write-Ok "PyInstaller build complete"

# ── Step 5: Download nmap ────────────────────────────────────────────────────
Write-Info "Downloading nmap $NmapVersion..."

if (-not (Test-Path $NmapZipFile)) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $NmapZipUrl -OutFile $NmapZipFile -UseBasicParsing
        Write-Ok "Downloaded $NmapZipFile"
    } catch {
        Write-Err "Failed to download nmap: $_"
        Write-Warn "Download manually from: $NmapZipUrl"
        exit 1
    }
} else {
    Write-Info "Using cached $NmapZipFile"
}

# ── Step 6: Assemble release directory ───────────────────────────────────────
Write-Info "Assembling release directory..."

# Clean previous release dir
if (Test-Path $ReleaseDir) { Remove-Item -Recurse -Force $ReleaseDir }

New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

# Copy cygor.exe
Copy-Item "dist/cygor.exe" "$ReleaseDir/cygor.exe"

# Extract nmap
Write-Info "Extracting nmap..."
Expand-Archive -Path $NmapZipFile -DestinationPath $ReleaseDir -Force

# Rename extracted nmap directory to just "nmap"
$nmapExtracted = Get-ChildItem -Path $ReleaseDir -Directory -Filter "nmap-*" | Select-Object -First 1
if ($nmapExtracted) {
    Rename-Item -Path $nmapExtracted.FullName -NewName "nmap"
    Write-Ok "Nmap extracted to $ReleaseDir/nmap/"
} else {
    Write-Warn "Could not find extracted nmap directory"
}

# Create README.txt
$readmeContent = @"
Cygor - Security Enumeration Framework (Windows)
==================================================

Quick Start:
  1. Install Npcap (required for nmap):
     Run nmap\npcap-*.exe as Administrator

  2. Run Cygor:
     .\cygor.exe --help

  3. Start web interface:
     .\cygor.exe web start

Notes:
  - nmap is bundled in the nmap\ directory
  - Add the nmap\ directory to your PATH for full nmap functionality
  - Some features (masscan, naabu) are not available on Windows

For more information, visit: https://github.com/tjnull/cygor
"@

Set-Content -Path "$ReleaseDir/README.txt" -Value $readmeContent -Encoding UTF8
Write-Ok "Created README.txt"

# ── Step 7: Create zip ──────────────────────────────────────────────────────
Write-Info "Creating $ZipFile..."

if (Test-Path $ZipFile) { Remove-Item -Force $ZipFile }

Compress-Archive -Path $ReleaseDir -DestinationPath $ZipFile -CompressionLevel Optimal
Write-Ok "Created $ZipFile"

# ── Step 8: Cleanup ─────────────────────────────────────────────────────────
Write-Info "Cleaning up build artifacts..."

# Remove PyInstaller artifacts (never delete packaging/)
if (Test-Path "dist")           { Remove-Item -Recurse -Force "dist" }
if (Test-Path "cygor_entry.py") { Remove-Item -Force "cygor_entry.py" }
if (Test-Path "cygor.spec")     { Remove-Item -Force "cygor.spec" }
if (Test-Path $NmapZipFile)     { Remove-Item -Force $NmapZipFile }
if (Test-Path $ReleaseDir)      { Remove-Item -Recurse -Force $ReleaseDir }

Write-Ok "Cleanup complete"

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "  Output: $ZipFile" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Info "Extract and run:"
Write-Host "  Expand-Archive $ZipFile -DestinationPath ."
Write-Host "  cd $ReleaseDir"
Write-Host "  .\cygor.exe --help"
Write-Host ""
