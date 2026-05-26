#!/usr/bin/env bash
# install-deps.sh — Install Cygor runtime dependencies
#
# Detects the system's package manager and installs nmap, masscan,
# git, and postgresql-client. Run with sudo if not root.
#
# Usage:
#   sudo ./install-deps.sh
set -euo pipefail

# ── Status helpers ───────────────────────────────────────────────────────────
info()  { echo "[*] $*"; }
ok()    { echo "[+] $*"; }
warn()  { echo "[!] $*"; }

# ── Sudo handling ────────────────────────────────────────────────────────────
SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
  info "Not running as root — will use sudo for package installation"
fi

# ── Detect package manager ───────────────────────────────────────────────────
detect_pkg_mgr() {
  for mgr in apt-get dnf yum pacman zypper apk; do
    if command -v "$mgr" &>/dev/null; then
      echo "$mgr"
      return
    fi
  done
  echo "none"
}

# ── Install dependencies ────────────────────────────────────────────────────
install_deps() {
  local mgr="$1"

  case "$mgr" in
    apt-get)
      info "Installing via apt-get..."
      $SUDO apt-get update -qq
      $SUDO apt-get install -y nmap masscan git postgresql-client
      ;;
    dnf|yum)
      info "Installing via $mgr..."
      $SUDO $mgr install -y nmap git postgresql
      # masscan requires EPEL on RHEL derivatives
      $SUDO $mgr install -y epel-release 2>/dev/null || true
      if ! $SUDO $mgr install -y masscan 2>/dev/null; then
        warn "masscan not available. Install manually or enable EPEL."
        warn "  Source: https://github.com/robertdavidgraham/masscan"
      fi
      ;;
    pacman)
      info "Installing via pacman..."
      $SUDO pacman -Sy --noconfirm nmap masscan git postgresql
      ;;
    zypper)
      info "Installing via zypper..."
      $SUDO zypper --non-interactive install nmap masscan git postgresql-client
      ;;
    apk)
      info "Installing via apk..."
      $SUDO apk add nmap masscan git postgresql15-client
      ;;
    *)
      warn "No supported package manager detected."
      warn "Please install manually: nmap, masscan, git, postgresql-client"
      exit 1
      ;;
  esac
}

# ── Main ─────────────────────────────────────────────────────────────────────
echo "============================================"
echo "  Cygor Dependency Installer"
echo "============================================"
echo

MGR="$(detect_pkg_mgr)"
info "Detected package manager: $MGR"
echo

install_deps "$MGR"

echo
ok "Dependencies installed successfully!"
echo
info "Run ./bin/cygor --help to get started."
echo
