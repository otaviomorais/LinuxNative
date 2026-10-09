#!/bin/sh
# Rootless development tools for Debian 13 x86_64 cloud machines.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOLS=${LN_TOOLS_DIR:-$(dirname "$REPO")/.linuxnative-tools}
case "$TOOLS" in /*) ;; *) echo 'LN_TOOLS_DIR must be absolute' >&2; exit 1;; esac
. /etc/os-release
if [ "$ID" != debian ] || [ "$VERSION_ID" != 13 ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'This bootstrap supports Debian 13 x86_64; see README for native/Termux builds.' >&2
    exit 1
fi
mkdir -p "$TOOLS/apt/etc/parts" "$TOOLS/apt/lists/partial" \
    "$TOOLS/apt/archives/partial" "$TOOLS/apt/log" "$TOOLS/root"
cat > "$TOOLS/apt/etc/config" <<EOF
Dir::Etc::parts "$TOOLS/apt/etc/parts";
Dir::Etc::main "-";
Dir::Etc::sourcelist "$TOOLS/apt/etc/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "$TOOLS/apt/lists";
Dir::State::status "$TOOLS/apt/status";
Dir::State::extended_states "$TOOLS/apt/extended_states";
Dir::Cache::archives "$TOOLS/apt/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "$TOOLS/apt/log";
APT::Sandbox::User "$(id -un)";
APT::Get::List-Cleanup "false";
EOF
cat > "$TOOLS/apt/etc/sources.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main
EOF
if [ ! -f "$TOOLS/installed-v1" ]; then
    cp /var/lib/dpkg/status "$TOOLS/apt/status"
    APT_CONFIG="$TOOLS/apt/etc/config" /usr/bin/apt-get update
    APT_CONFIG="$TOOLS/apt/etc/config" /usr/bin/apt-get \
        --download-only --no-install-recommends -y install \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user
    for package in "$TOOLS/apt/archives/"*.deb; do
        dpkg-deb -x "$package" "$TOOLS/root"
    done
fi
# This file contains only local tool locations, never credentials.
# Use Python's shell quoting so paths containing spaces/apostrophes are safe.
python3 - "$TOOLS" <<'PY'
import pathlib, shlex, sys
root = pathlib.Path(sys.argv[1])
bin_dir = shlex.quote(str(root / 'root/usr/bin'))
lib_dir = shlex.quote(str(root / 'root/usr/lib/x86_64-linux-gnu'))
(root / 'activate.sh').write_text(
    f'export PATH={bin_dir}:"$PATH"\n'
    f'export LD_LIBRARY_PATH={lib_dir}${{LD_LIBRARY_PATH:+:"$LD_LIBRARY_PATH"}}\n'
)
PY
. "$TOOLS/activate.sh"
aarch64-linux-gnu-gcc --version
qemu-aarch64 --version
cd "$REPO"
make -j2
make test
touch "$TOOLS/installed-v1"
printf 'Ready. Activate with: . "%s/activate.sh"\n' "$TOOLS"
