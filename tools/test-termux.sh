#!/bin/sh
# Run inside Termux, from an app-private checkout (not shared storage).
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(uname -m)" != aarch64 ]; then
    echo 'This device test requires Android ARM64.' >&2
    exit 1
fi
for tool in clang make python; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo 'Install the build tools in Termux: pkg install clang make python' >&2
        exit 1
    fi
done
cd "$REPO"
mkdir -p build
{
    date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
    if command -v git >/dev/null 2>&1; then
        printf 'Commit: '; git rev-parse HEAD 2>/dev/null || printf 'unavailable\n'
    fi
    uname -smr
    if command -v getprop >/dev/null 2>&1; then
        printf 'Model: '; getprop ro.product.model
        printf 'Android: '; getprop ro.build.version.release
        printf 'SDK: '; getprop ro.build.version.sdk
    fi
    printf 'Page size: '; python -c 'import os; print(os.sysconf("SC_PAGE_SIZE"))'
    clang --version
} > build/device-info.txt
# Rebuild only generated targets, to avoid reusing a cloud/glibc executable.
rm -f build/lnative build/probe build/file-scan build/file-abi build/mem-abi build/mini-ls build/fs-mut build/pie-abi
if make CC=clang LDFLAGS= > build/device-build.log 2>&1; then
    cat build/device-build.log
else
    cat build/device-build.log
    exit 1
fi
if make CC=clang LDFLAGS= RUNNER= PYTHON=python test > build/device-test.log 2>&1; then
    cat build/device-test.log
else
    cat build/device-test.log
    exit 1
fi
printf 'Device tests passed. Reports: build/device-{info.txt,build.log,test.log}\n'
