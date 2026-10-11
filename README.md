# LinuxNative

An experimental Debian/Linux compatibility runtime for **Android ARM64 without
root or ptrace**. Milestone 0 proves direct syscall rewriting for a deliberately
small class of static ELF programs. The next experiment adds a separately
compiled C file inspector. It does **not** yet run arbitrary Debian
packages, BusyBox, Python, Go, or an entire Debian userland.

The loader replaces each supported guest `svc #0` with a direct branch to an
in-process gateway. The gateway implements a small syscall ABI and returns to
the original next instruction. There is no ptrace supervisor, signal-based
syscall trap, seccomp notification broker, or CPU emulator in the runtime.
QEMU is used only to test ARM64 code on x86_64 development machines.

## Current evidence

- Cross-compiled with GCC 14 and executed with QEMU user mode 10 on Linux x86_64.
- Milestone 0's 23 tests passed on the user's Poco F3 according to their report:
  Android 17 / SDK 37, kernel 4.19, 4 KiB pages, Clang 21.1.8 in Termux.
- The current suite has 42 tests, adding direct-vs-runtime execution of C
  programs, static PIE (`ET_DYN`) relocatable binaries, stripped binaries via linear
  SVC scanning, full Linux auxiliary vector (`auxv`), thread register isolation
  (`tpidr_el0`), file metadata, seeking, directory traversal (`getdents64`), process credentials,
  filesystem mutation, micro-libc dynamic memory allocation (`mmap`, `munmap`, `mprotect`, `brk`),
  system identification (`uname`), and Debian/glibc dynamic linker and utility execution
  (`ld-linux-aarch64.so.1`, `/bin/true`, `/bin/uname`, `/bin/echo`, `/bin/ls`).
  All 42 tests pass natively on Android ARM64 (Poco F3, Android 17 / SDK 37, Clang 21.1.8 in Termux).
- See [validation evidence and limits](docs/validation.md). Other devices and
  16 KiB pages remain unverified. Remote CI results have not been verified here.

## Build and test

On Debian/Ubuntu x86_64, install `gcc-aarch64-linux-gnu`,
`libc6-dev-arm64-cross`, `qemu-user`, `make`, and `python3`, then:

```sh
make
make test
```

On the Debian 13 cloud development machine, a rootless bootstrap downloads
packages using Debian's signed APT metadata and extracts them outside the repo:

```sh
sh tools/bootstrap-cloud.sh
. /workspace/.linuxnative-tools/activate.sh
make test
```

The default tool directory is `.linuxnative-tools` beside this checkout; set
`LN_TOOLS_DIR` to override it. The bootstrap reuses its verified installation.
It follows Debian trixie package updates; it is not a bit-reproducible toolchain lock.

On native Linux ARM64:

```sh
make CC=gcc RUNNER= test
```

### Android / Termux

Keep the checkout inside Termux's private `$HOME`, not `/sdcard`. The runtime
must be built with Termux's compiler so it uses Android's Bionic libraries.
The cloud's static glibc runtime is not the recommended Android executable.

```sh
pkg install git clang make python
git clone --branch main https://github.com/otaviomorais/LinuxNative.git ~/LinuxNative
cd ~/LinuxNative
sh tools/test-termux.sh
```

This runs the same tests directly on the CPU, without QEMU, root, or ptrace.
It records limited device metadata, build output, and test results in
`build/device-info.txt`, `build/device-build.log`, and `build/device-test.log`.
It does not collect serial numbers, accounts, or environment-variable values.
See [device setup instructions](docs/device-testing.md), including what to do
if that checkout directory already exists.

### Manual example on the cloud machine

```sh
mkdir -p build/demo-root/etc
printf 'Hello from the mapped Debian directory!\n' > build/demo-root/etc/linuxnative-probe.txt
qemu-aarch64 build/lnative --verbose --root build/demo-root build/probe
```

On a native ARM64 machine, omit `qemu-aarch64`. The test program first checks
register preservation and error behavior, then reads `/etc/linuxnative-probe.txt`
from the selected root and writes its contents to stdout. The original ELF is
never modified on disk.

### C program example

The same file inspector can run directly or through LinuxNative. In the cloud:

```sh
qemu-aarch64 build/file-scan "$PWD/build/demo-root/etc/linuxnative-probe.txt"
qemu-aarch64 build/lnative --root build/demo-root build/file-scan /etc/linuxnative-probe.txt
```

Both should print the same JSON metadata and content fingerprint. On the phone,
omit `qemu-aarch64` after building with `tools/test-termux.sh`. The C executable
has no dependency on the runtime but uses a custom linker layout and no libc;
this is a step toward existing Debian binaries, not general support for them.

### Standalone micro-libc application (`mini-ls`)

A standalone application compiled with `examples/micro-libc.h` runs directly on Linux ARM64
and through LinuxNative, demonstrating dynamic memory allocation (`mini_malloc`/`mini_free` via `mmap`/`munmap`),
process credentials, and directory listing (`getdents64`):

```sh
build/mini-ls build
build/lnative --root "$PWD" build/mini-ls /build
```

## Current prototype contract

- Trusted, little-endian AArch64 `ET_EXEC` or PIE/DYN (`ET_DYN`) executables, including
  the glibc dynamic linker `ld-linux-aarch64.so.1`.
- When ELF symbol tables and AAPCS64 `$x`/`$d` mapping symbols are present, code ranges are
  scanned precisely to protect data literals. When `.symtab` is stripped, a 32-bit linear
  instruction scan of executable sections is employed.
- Non-overlapping load-segment pages, no writable executable segments, and an
  image span no larger than 32 MiB. Fixed guest addresses must be available.
- Single thread guest execution; host Bionic TLS (`tpidr_el0`) and `x18` are preserved
  and swapped across the gateway boundary to isolate foreign libc (e.g. glibc) TLS state.
- Valid guest pointers and 16-byte-aligned guest stack populated with standard Linux
  auxiliary vector (`auxv`: `AT_PHDR`, `AT_ENTRY`, `AT_BASE`, `AT_PAGESZ`, `AT_RANDOM`, etc.).
- Syscalls: `fcntl`, `ioctl`, `mkdirat`, `unlinkat`, `openat`, `faccessat`, `read`, `write`,
  `readv`, `writev`, `close`, `fstat`, `newfstatat`, `readlinkat`, `lseek`, `getdents64`,
  `uname`, `getpid`, `getppid`, `getuid`, `geteuid`, `getgid`, `getegid`, `gettid`,
  `set_tid_address`, `set_robust_list`, `nanosleep`, `clock_gettime`, `rt_sigaction`,
  `rt_sigprocmask`, `brk`, `mmap`, `munmap`, `mprotect`, `madvise`, `prlimit64`,
  `getrandom`, `exit`, `exit_group`. Others return raw `-ENOSYS`.
- CLI: `lnative [--verbose] --root DIRECTORY STATIC_ELF [ARG...]`.
  Arguments are copied to a 16-byte-aligned guest stack with a bounded budget.
- Unsupported open modes and relative paths return `-EOPNOTSUPP`; `..` components
  return `-EACCES`. No claim of a complete Linux filesystem or process ABI.

**This is not a sandbox.** Guest code shares memory and privileges with the
runtime. It can access inherited descriptors and host memory; symlinks can lead
outside the selected root. Mapping symbols are trusted metadata, not a security
boundary. Never run untrusted programs with this prototype.

The runtime cannot grant privileges denied by Android's kernel, SELinux, or
seccomp. It uses RW-then-RX memory permissions, never RWX; executable mappings
still require validation in the actual Android app context.

## Next milestones

1. Validate the expanded C-program suite on the Poco F3, then other Android
   configurations including devices with 16 KiB pages.
2. Extend the syscall/process ABI toward a small independently built libc-linked
   application, guided by differential tests and explicit support limits.
3. Add a loader and rewriting strategy for ordinary dynamic/stripped binaries.
4. Address threads, signals, exec, and code generated at runtime.
5. Measure correctness and performance against native Linux and PRoot workloads.

No novelty or near-native performance claim has been established. This source
is a new prototype, not a copy of deb-native. See [architecture](docs/architecture.md).
