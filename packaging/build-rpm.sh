#!/usr/bin/env bash
# build-rpm.sh — Build an .rpm package for Cygor using Docker (rockylinux:9)
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/build-common.sh"

# ── Parse arguments ──────────────────────────────────────────────────────────
cygor_parse_args "$@" || { [[ $? -eq 2 ]] && exit 0; exit 1; }

# Map Debian-style arch names to RPM arch names
case "$ARCH" in
  amd64) RPM_ARCH="x86_64" ;;
  arm64) RPM_ARCH="aarch64" ;;
  *)
    echo "ERROR: Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

RPM_FILE="cygor-${CYGOR_VERSION}-1.el9.${RPM_ARCH}.rpm"

cygor_print_banner ".rpm" "$RPM_FILE"
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
dnf install -y \
  python3.11 python3.11-devel python3.11-pip \
  gcc gcc-c++ make \
  libpq-devel libffi-devel zlib-devel openssl-devel zip git rpm-build \
  krb5-devel libxml2-devel libxslt-devel \
  pango cairo-devel gdk-pixbuf2-devel \
  libjpeg-turbo-devel libpng-devel pkgconf-pkg-config

# Python tooling
python3.11 -m pip install --upgrade pip wheel setuptools
python3.11 -m pip install pyinstaller
python3.11 -m pip install -e .

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

# Set up rpmbuild tree
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp dist/cygor ~/rpmbuild/SOURCES/

# Generate spec from template
sed 's/@@VERSION@@/${CYGOR_VERSION}/g' /src/packaging/cygor.spec.in > ~/rpmbuild/SPECS/cygor.spec

# Build RPM
rpmbuild -bb --target ${RPM_ARCH} ~/rpmbuild/SPECS/cygor.spec

# Copy RPM to source mount
cp ~/rpmbuild/RPMS/${RPM_ARCH}/cygor-${CYGOR_VERSION}-1.el9.${RPM_ARCH}.rpm /src/

echo
echo '============================================'
echo '  Build complete!'
ls -lh /src/cygor-${CYGOR_VERSION}-1.el9.${RPM_ARCH}.rpm
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
  rockylinux:9 bash /tmp/build-inner.sh

# ── Clean up ─────────────────────────────────────────────────────────────────
cygor_cleanup "$REPO_ROOT"

echo
echo "Package built: $REPO_ROOT/$RPM_FILE"
echo
echo "Install with:"
echo "  sudo dnf install $RPM_FILE"
echo
