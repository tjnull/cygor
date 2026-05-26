#!/usr/bin/env bash
# build-tarball.sh — Build a portable .tar.gz for Cygor using Docker (debian:bookworm)
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/build-common.sh"

# ── Parse arguments ──────────────────────────────────────────────────────────
cygor_parse_args "$@" || { [[ $? -eq 2 ]] && exit 0; exit 1; }

TARBALL_FILE="cygor-${CYGOR_VERSION}-linux-${ARCH}.tar.gz"

cygor_print_banner ".tar.gz" "$TARBALL_FILE"
cygor_check_docker || exit 1

# ── Generate inner Docker build script ───────────────────────────────────────
TMPSCRIPT="$(mktemp)"
trap 'rm -f "$TMPSCRIPT"' EXIT

# Assemble PyInstaller flags from shared arrays
_pyinstaller_flags=()
for ((i=0; i<${#PYINSTALLER_ADD_DATA[@]}; i+=2)); do
  _pyinstaller_flags+=("${PYINSTALLER_ADD_DATA[i]}" "${PYINSTALLER_ADD_DATA[i+1]}")
done
for ((i=0; i<${#PYINSTALLER_METADATA[@]}; i+=2)); do
  _pyinstaller_flags+=("${PYINSTALLER_METADATA[i]}" "${PYINSTALLER_METADATA[i+1]}")
done
for ((i=0; i<${#PYINSTALLER_HOOKS[@]}; i+=2)); do
  _pyinstaller_flags+=("${PYINSTALLER_HOOKS[i]}" "${PYINSTALLER_HOOKS[i+1]}")
done
for ((i=0; i<${#PYINSTALLER_COLLECT_SUBMODULES[@]}; i+=2)); do
  _pyinstaller_flags+=("${PYINSTALLER_COLLECT_SUBMODULES[i]}" "${PYINSTALLER_COLLECT_SUBMODULES[i+1]}")
done
for ((i=0; i<${#PYINSTALLER_HIDDEN_IMPORTS[@]}; i+=2)); do
  _pyinstaller_flags+=("${PYINSTALLER_HIDDEN_IMPORTS[i]}" "${PYINSTALLER_HIDDEN_IMPORTS[i+1]}")
done

# Write inner script header (no variable expansion)
cat > "$TMPSCRIPT" << 'INNER_HEADER'
#!/usr/bin/env bash
set -ex

# System dependencies
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3.11 python3.11-dev python3-pip build-essential \
  libpq-dev libffi-dev zlib1g-dev libssl-dev zip git \
  libkrb5-dev libxml2-dev libxslt1-dev \
  libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2-dev \
  libjpeg-dev libpng-dev pkg-config

# Python tooling
python3.11 -m pip install --break-system-packages --upgrade pip wheel setuptools
python3.11 -m pip install --break-system-packages pyinstaller
python3.11 -m pip install --break-system-packages -e .

# Entry point
cat > cygor_entry.py << 'ENTRY_EOF'
#!/usr/bin/env python3
import sys
from cygor.cli import main
if __name__ == "__main__":
    sys.exit(main())
ENTRY_EOF

# Static files detection
STATIC_ARGS=""
if [ -d "cygor/webapp/static" ]; then
  STATIC_ARGS="--add-data cygor/webapp/static:cygor/webapp/static"
fi

# PyInstaller
pyinstaller --onefile --clean --noconfirm --name cygor \
  $STATIC_ARGS \
INNER_HEADER

# Append PyInstaller flags from arrays
for flag in "${_pyinstaller_flags[@]}"; do
  printf '  %q \\\n' "$flag" >> "$TMPSCRIPT"
done
echo '  cygor_entry.py' >> "$TMPSCRIPT"
echo '' >> "$TMPSCRIPT"

# Write inner script footer (with variable expansion for version/arch)
cat >> "$TMPSCRIPT" << INNER_FOOTER

chmod +x dist/cygor
strip dist/cygor || true

# Tarball staging
STAGING="cygor-${CYGOR_VERSION}-linux-${ARCH}"
mkdir -p "\${STAGING}/bin"
cp dist/cygor "\${STAGING}/bin/"
cp /src/packaging/install-deps.sh "\${STAGING}/"
chmod +x "\${STAGING}/install-deps.sh"

cat > "\${STAGING}/README.txt" << 'README_EOF'
Cygor - Security Enumeration Framework
=======================================

Quick Start:
  1. Install dependencies:    sudo ./install-deps.sh
  2. Run Cygor:               ./bin/cygor --help
  3. Start web interface:     ./bin/cygor web start

System Dependencies:
  The install-deps.sh script will install nmap, masscan, git,
  and postgresql-client for your Linux distribution.

  Alternatively, install them manually:
    Debian/Ubuntu:  sudo apt install nmap masscan git postgresql-client
    RHEL/Rocky:     sudo dnf install nmap git postgresql
    Arch:           sudo pacman -S nmap masscan git postgresql

For more information, visit: https://github.com/tjnull/cygor
README_EOF

# Create tarball
tar czf /src/${TARBALL_FILE} "\${STAGING}"

echo
echo '============================================'
echo '  Build complete!'
ls -lh /src/${TARBALL_FILE}
echo '============================================'


# Restore host ownership of artifacts created during the build, so the
# host-side cleanup step can remove dist/ / cygor_entry.py / cygor.spec
# without sudo. /src is bind-mounted from the host, so its uid:gid
# matches the host user that started the container.
HOST_OWNER="\$(stat -c %u:%g /src)"
chown -R "\$HOST_OWNER" /src 2>/dev/null || true
INNER_FOOTER
# ── Build inside Docker ──────────────────────────────────────────────────────
cd "$REPO_ROOT"

docker run --rm --platform "$PLATFORM" \
  -v "$PWD":/src -w /src \
  -v "$TMPSCRIPT":/tmp/build-inner.sh:ro \
  debian:bookworm bash /tmp/build-inner.sh

# ── Clean up ─────────────────────────────────────────────────────────────────
cygor_cleanup "$REPO_ROOT"

echo
echo "Tarball built: $REPO_ROOT/$TARBALL_FILE"
echo
echo "Extract and run:"
echo "  tar xzf $TARBALL_FILE"
echo "  cd cygor-${CYGOR_VERSION}-linux-${ARCH}"
echo "  sudo ./install-deps.sh"
echo "  ./bin/cygor --help"
echo
