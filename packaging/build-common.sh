# build-common.sh — Shared configuration for Cygor cross-platform build scripts.
#
# This file is SOURCED by the platform-specific build scripts, not executed
# directly. The sourcing script is responsible for 'set -euo pipefail'.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/build-common.sh"
#
# All exported variables and functions use the cygor_ prefix to avoid collisions.
# Exception: ARCH and PLATFORM are intentionally not prefixed because they are
# standard build variables expected by the consuming build scripts.

# ── Variables ────────────────────────────────────────────────────────────────
CYGOR_VERSION="${CYGOR_VERSION:-1.0.0}"
CYGOR_PYTHON="python3.11"
CYGOR_MAINTAINER="tjnull"
CYGOR_DESCRIPTION="Cygor security enumeration tool"
CYGOR_LONG_DESC="Automated scanner and enumeration framework"

# ── PyInstaller flag arrays (single source of truth) ─────────────────────────

PYINSTALLER_COLLECT_SUBMODULES=(
  # Core application
  --collect-submodules cygor
  # Package resources (appdirs is vendored inside pkg_resources)
  --collect-submodules pkg_resources
  # Web framework
  --collect-submodules fastapi
  --collect-submodules uvicorn
  --collect-submodules starlette
  # Database / ORM
  --collect-submodules sqlalchemy
  --collect-submodules alembic
  --collect-all pydantic_core
  --collect-all pydantic
  --collect-submodules aioodbc
  --collect-submodules asyncmy
  --collect-submodules oracledb
  # Auth / crypto / certs
  # Templating / reports
  --collect-submodules jinja2
  # Scheduling
  --collect-submodules apscheduler
  # CredRecon protocol libraries
  --collect-submodules impacket
  --collect-submodules winrm
  --collect-submodules paramiko
  --collect-submodules ldap3
  --collect-submodules cassandra
  --collect-submodules neo4j
  --collect-submodules aardwolf
  --collect-submodules paho
  --collect-submodules scapy
  --collect-submodules pysnmp
)

PYINSTALLER_HIDDEN_IMPORTS=(
  # Scanning / parsing
  --hidden-import libnmap.parser
  --hidden-import smbmap
  --hidden-import bs4
  --hidden-import scapy
  --hidden-import scapy.all
  # Web framework
  --hidden-import sqlmodel
  --hidden-import starlette
  --hidden-import starlette.responses
  --hidden-import markupsafe
  --hidden-import aiohttp
  --hidden-import httpx
  --hidden-import requests
  # Database drivers
  --hidden-import psycopg
  --hidden-import psycopg2
  --hidden-import aiosqlite
  --hidden-import aioodbc
  --hidden-import asyncmy
  --hidden-import oracledb
  --hidden-import pymysql
  --hidden-import pymssql
  --hidden-import pymongo
  --hidden-import bson
  --hidden-import redis
  --hidden-import pyodbc
  # Database migrations
  --hidden-import alembic
  --hidden-import alembic.config
  --hidden-import alembic.command
  # Reporting / data
  --hidden-import rich
  --hidden-import PIL
  --hidden-import tabulate
  # Crypto / auth
  --hidden-import cryptography
  --hidden-import gssapi
  --hidden-import pyOpenSSL
  # System / utilities
  --hidden-import paramiko
  --hidden-import psutil
  --hidden-import pytz
  --hidden-import watchfiles
  --hidden-import lxml
  --hidden-import platformdirs
  --hidden-import appdirs
  --hidden-import pydantic_core._pydantic_core
  --hidden-import colorama
  --hidden-import yaml
  --hidden-import packaging
  --hidden-import packaging.version
  --hidden-import dateutil
  --hidden-import dateutil.parser
  # CredRecon protocol libraries
  --hidden-import impacket
  --hidden-import impacket.smbconnection
  --hidden-import winrm
  --hidden-import pysnmp
  --hidden-import pysnmp.hlapi
  --hidden-import pyghmi
  --hidden-import pyghmi.ipmi
  --hidden-import pyghmi.ipmi.command
  --hidden-import paho
  --hidden-import paho.mqtt
  --hidden-import paho.mqtt.client
  --hidden-import vncdotool
  --hidden-import vncdotool.api
  --hidden-import cassandra
  --hidden-import cassandra.cluster
  --hidden-import cassandra.auth
  --hidden-import neo4j
  --hidden-import aardwolf
  --hidden-import aardwolf.connection
  --hidden-import rdpy
  --hidden-import twisted
  --hidden-import pyNfsClient
  --hidden-import pyVmomi
  --hidden-import pyVim
  --hidden-import pyVim.connect
)

PYINSTALLER_ADD_DATA=(
  --add-data "cygor/webapp/templates:cygor/webapp/templates"
  --add-data "cygor/credrecon:cygor/credrecon"
  --add-data "cygor/webapp/alembic:cygor/webapp/alembic"
  --add-data "cygor/banner.txt:cygor"
)

PYINSTALLER_METADATA=(
  --copy-metadata pydantic_core
  --copy-metadata pydantic
  --copy-metadata sqlalchemy
  --copy-metadata uvicorn
  --copy-metadata fastapi
  --copy-metadata starlette
)

PYINSTALLER_HOOKS=(
  --additional-hooks-dir "packaging/hooks"
)

# ── Functions ────────────────────────────────────────────────────────────────

# Detect or validate architecture. Sets ARCH and PLATFORM globals.
# Args: $1 (optional) — override architecture (amd64|arm64)
cygor_detect_arch() {
  local override="${1:-}"
  if [[ -n "$override" ]]; then
    ARCH="$override"
  else
    case "$(uname -m)" in
      x86_64)  ARCH="amd64" ;;
      aarch64) ARCH="arm64" ;;
      *)
        echo "ERROR: Unsupported architecture: $(uname -m)" >&2
        echo "Use --arch amd64 or --arch arm64" >&2
        return 1
        ;;
    esac
  fi

  case "$ARCH" in
    amd64) PLATFORM="linux/amd64" ;;
    arm64) PLATFORM="linux/arm64" ;;
    *)
      echo "ERROR: Invalid architecture: $ARCH (use amd64 or arm64)" >&2
      return 1
      ;;
  esac
}

# Parse common build arguments (--arch, --version, --help).
# Sets ARCH, PLATFORM, CYGOR_VERSION globals.
# Returns: 0=success, 1=error, 2=help printed (caller should exit 0)
cygor_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --arch)
        [[ $# -ge 2 ]] || { echo "ERROR: --arch requires a value" >&2; return 1; }
        ARCH="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || { echo "ERROR: --version requires a value" >&2; return 1; }
        CYGOR_VERSION="$2"
        shift 2
        ;;
      -h|--help)
        echo "Usage: $0 [--arch amd64|arm64] [--version X.Y.Z]"
        return 2
        ;;
      *)
        echo "ERROR: Unknown option: $1" >&2
        return 1
        ;;
    esac
  done

  cygor_detect_arch "${ARCH:-}"
}

# Verify Docker is installed.
cygor_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed or not in PATH" >&2
    return 1
  fi
}

# Write the cygor_entry.py PyInstaller entry point.
cygor_create_entry_point() {
  cat > cygor_entry.py << 'ENTRY_EOF'
#!/usr/bin/env python3
import sys
from cygor.cli import main
if __name__ == "__main__":
    sys.exit(main())
ENTRY_EOF
}

# Assemble and run PyInstaller with all shared flags.
# Extra flags can be passed as arguments (e.g., --console).
cygor_run_pyinstaller() {
  local extra_flags=("$@")
  local static_arg=()

  if [[ -d "cygor/webapp/static" ]]; then
    static_arg=(--add-data "cygor/webapp/static:cygor/webapp/static")
  fi

  local cmd=(
    pyinstaller --onefile --clean --noconfirm --name cygor
    "${PYINSTALLER_ADD_DATA[@]}"
    "${PYINSTALLER_METADATA[@]}"
    "${PYINSTALLER_HOOKS[@]}"
    "${static_arg[@]}"
    "${PYINSTALLER_COLLECT_SUBMODULES[@]}"
    "${PYINSTALLER_HIDDEN_IMPORTS[@]}"
    "${extra_flags[@]}"
    cygor_entry.py
  )

  echo "[*] Running PyInstaller..."
  "${cmd[@]}"
}

# Echo the apt-get package list for Debian-based Docker builds.
cygor_system_deps_debian() {
  echo "python3.11 python3.11-dev python3-pip build-essential" \
       "libpq-dev libffi-dev zlib1g-dev libssl-dev zip git fakeroot" \
       "libkrb5-dev libxml2-dev libxslt1-dev" \
       "libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2-dev" \
       "libjpeg-dev libpng-dev pkg-config"
}

# Echo the dnf package list for RHEL-based Docker builds.
cygor_system_deps_rpm() {
  echo "python3.11 python3.11-devel python3.11-pip" \
       "gcc gcc-c++ make" \
       "libpq-devel libffi-devel zlib-devel openssl-devel zip git rpm-build" \
       "krb5-devel libxml2-devel libxslt-devel" \
       "pango cairo-devel gdk-pixbuf2-devel" \
       "libjpeg-turbo-devel libpng-devel pkgconf-pkg-config"
}

# Print build banner.
# Args: $1 — format name (e.g., ".deb"), $2 — output filename
cygor_print_banner() {
  local format="${1:?cygor_print_banner requires a format name}"
  local output="${2:?cygor_print_banner requires an output filename}"
  echo "============================================"
  echo "  Cygor ${format} Build"
  echo "  Architecture : ${ARCH} (${PLATFORM})"
  echo "  Version      : ${CYGOR_VERSION}"
  echo "  Output       : ${output}"
  echo "============================================"
  echo
}

# Remove PyInstaller artifacts from the source tree.
# Args: $1 (optional) — base directory (default: .)
# IMPORTANT: Never deletes packaging/ directory.
cygor_cleanup() {
  local base_dir="${1:-.}"
  rm -rf "${base_dir}/dist" "${base_dir}/cygor_entry.py" "${base_dir}/cygor.spec"
}
