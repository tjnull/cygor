#!/usr/bin/env bash
# build-deb.sh — Build a .deb package for Cygor using Docker (debian:bookworm)
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/build-common.sh"

# ── Parse arguments ──────────────────────────────────────────────────────────
cygor_parse_args "$@" || { [[ $? -eq 2 ]] && exit 0; exit 1; }

DEB_FILE="cygor_${CYGOR_VERSION}_${ARCH}.deb"

cygor_print_banner ".deb" "$DEB_FILE"
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
  libpq-dev libffi-dev zlib1g-dev libssl-dev zip git fakeroot \
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

# Package structure
mkdir -p package/usr/local/bin package/DEBIAN
cp dist/cygor package/usr/local/bin/

cat > package/DEBIAN/control << CTRL_EOF
Package: cygor
Version: ${CYGOR_VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: ${CYGOR_MAINTAINER}
Depends: nmap
Recommends: masscan
Description: ${CYGOR_DESCRIPTION}
 ${CYGOR_LONG_DESC}
CTRL_EOF

# Post-install script
cat > package/DEBIAN/postinst << 'POSTINST_EOF'
#!/bin/bash
set -e
mkdir -p /var/lib/cygor /var/log/cygor
chmod 0755 /var/lib/cygor /var/log/cygor
echo ""
echo "============================================"
echo "  Cygor installed successfully!"
echo ""
echo "  Quick start:"
echo "    cygor --help"
echo "    cygor scan --help"
echo "    cygor web start"
echo ""
echo "  Data directory: /var/lib/cygor"
echo "  Log directory:  /var/log/cygor"
echo "============================================"
echo ""
POSTINST_EOF
chmod 0755 package/DEBIAN/postinst

# Pre-remove script
cat > package/DEBIAN/prerm << 'PRERM_EOF'
#!/bin/bash
set -e
if [ -f /var/lib/cygor/cygor-web.pid ]; then
    kill "\$(cat /var/lib/cygor/cygor-web.pid)" 2>/dev/null || true
    rm -f /var/lib/cygor/cygor-web.pid
fi
systemctl is-active cygor >/dev/null 2>&1 && systemctl stop cygor || true
PRERM_EOF
chmod 0755 package/DEBIAN/prerm

# Build .deb
fakeroot dpkg-deb --build package /src/${DEB_FILE}

echo
echo '============================================'
echo '  Build complete!'
ls -lh /src/${DEB_FILE}
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
rm -rf "$REPO_ROOT/package"

echo
echo "Package built: $REPO_ROOT/$DEB_FILE"
echo
echo "Install with:"
echo "  sudo dpkg -i $DEB_FILE"
echo
